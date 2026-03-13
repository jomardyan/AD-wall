#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall SMB/WMI Metadata Collector
.DESCRIPTION
    Collects SMB signing status, legacy protocol exposure, NTLM settings, and
    Kerberos encryption configuration via WMI/CIM and registry queries.
    All operations are read-only. Remote registry access uses standard WMI/CIM.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region Helper Functions

function Invoke-RemoteRegistry {
    <#
    .SYNOPSIS
        Reads a registry value from a local or remote system via .NET/WMI.
    #>
    param(
        [string]$ComputerName = 'localhost',
        [ValidateSet('HKLM','HKCU','HKU','HKCR','HKCC')]
        [string]$Hive  = 'HKLM',
        [string]$Key,
        [string]$Value,
        [System.Management.Automation.PSCredential]$Credential
    )

    $hiveMap = @{
        HKLM = 2147483650
        HKCU = 2147483649
        HKU  = 2147483651
        HKCR = 2147483648
        HKCC = 2147483653
    }

    try {
        $cimParams = @{
            Namespace  = 'root\default'
            ClassName  = 'StdRegProv'
            MethodName = 'GetDWORDValue'
            Arguments  = @{
                hDefKey    = $hiveMap[$Hive]
                sSubKeyName = $Key
                sValueName  = $Value
            }
        }

        if ($ComputerName -ne 'localhost' -and $ComputerName -ne $env:COMPUTERNAME) {
            $sessionParams = @{ ComputerName = $ComputerName }
            if ($null -ne $Credential) { $sessionParams.Credential = $Credential }
            $session = New-CimSession @sessionParams -ErrorAction Stop
            $cimParams.CimSession = $session
        }

        $result = Invoke-CimMethod @cimParams -ErrorAction Stop

        if ($null -ne $session) { Remove-CimSession $session -ErrorAction SilentlyContinue }

        if ($result.ReturnValue -eq 0) {
            return $result.uValue
        }

        # Fall back to GetStringValue
        $cimParams.MethodName = 'GetStringValue'
        $result2 = Invoke-CimMethod @cimParams -ErrorAction Stop
        if ($result2.ReturnValue -eq 0) { return $result2.sValue }

        return $null
    }
    catch {
        Write-Verbose "Registry read failed ($ComputerName\$Hive\$Key\$Value): $_"
        return $null
    }
}

function Invoke-CimQuery {
    <#
    .SYNOPSIS
        Runs a CIM/WMI query, optionally against a remote computer.
    #>
    param(
        [string]$ComputerName = 'localhost',
        [string]$Namespace    = 'root\cimv2',
        [string]$Query,
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        $sessionParams = @{}
        if ($ComputerName -ne 'localhost' -and $ComputerName -ne $env:COMPUTERNAME) {
            $sessionParams.ComputerName = $ComputerName
        }
        if ($null -ne $Credential) { $sessionParams.Credential = $Credential }

        if ($sessionParams.Count -gt 0) {
            $session = New-CimSession @sessionParams -ErrorAction Stop
            $results = Get-CimInstance -CimSession $session -Namespace $Namespace -Query $Query -ErrorAction Stop
            Remove-CimSession $session -ErrorAction SilentlyContinue
        }
        else {
            $results = Get-CimInstance -Namespace $Namespace -Query $Query -ErrorAction Stop
        }

        return $results
    }
    catch {
        Write-Verbose "CIM query failed on ${ComputerName}: $_"
        return $null
    }
}

#endregion

#region SMB Signing

function Get-SMBSigningStatus {
    <#
    .SYNOPSIS
        Checks SMB signing configuration on one or more target hosts.
    .DESCRIPTION
        Queries the registry and CIM for SMB server signing policy. Reports whether
        signing is required, enabled, or disabled.
    .PARAMETER ComputerName
        One or more target hostnames or IPs. Defaults to local machine.
    .PARAMETER Credential
        Optional credential for remote queries.
    .EXAMPLE
        Get-SMBSigningStatus -ComputerName dc01.corp.local, dc02.corp.local
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Checking SMB signing on: $computer"
            $result = [PSCustomObject]@{
                ComputerName        = $computer
                SmbSigningRequired  = $null
                SmbSigningEnabled   = $null
                Smbv2Enabled        = $null
                CheckMethod         = 'Registry'
                Error               = $null
            }

            try {
                # HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
                $sigReq = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                    -Key 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                    -Value 'RequireSecuritySignature' -Credential $Credential

                $sigEna = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                    -Key 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                    -Value 'EnableSecuritySignature' -Credential $Credential

                $result.SmbSigningRequired = ($sigReq -eq 1)
                $result.SmbSigningEnabled  = ($sigEna -eq 1)

                # Check SMBv2 (DisableSmb2 = 1 means disabled)
                $smbv2Disabled = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                    -Key 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                    -Value 'SMB2' -Credential $Credential

                $result.SmbV2Enabled = ($null -eq $smbv2Disabled -or $smbv2Disabled -ne 0)
            }
            catch {
                $result.Error = $_.ToString()
                Write-Warning "SMB signing check failed on ${computer}: $_"
            }

            $result
        }
    }
}

#endregion

#region SMBv1

function Get-SMBv1Status {
    <#
    .SYNOPSIS
        Checks whether SMBv1 is enabled on one or more target hosts.
    .DESCRIPTION
        Checks both the server-side (LanmanServer) and client-side (LanmanWorkstation)
        SMBv1 configuration via registry and optionally via CIM SC_Config.
    .PARAMETER ComputerName
        Target hosts to check.
    .PARAMETER Credential
        Optional credential for remote queries.
    .EXAMPLE
        Get-SMBv1Status -ComputerName dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Checking SMBv1 on: $computer"

            $serverSmbv1 = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                -Value 'SMB1' -Credential $Credential

            $clientSmbv1 = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Services\mrxsmb10' `
                -Value 'Start' -Credential $Credential

            [PSCustomObject]@{
                ComputerName           = $computer
                SMBv1ServerEnabled     = ($serverSmbv1 -ne 0)  # 0 = disabled
                SMBv1ClientEnabled     = ($clientSmbv1 -ne 4)  # 4 = disabled (service start type)
                SMBv1ServerRawValue    = $serverSmbv1
                SMBv1ClientStartType   = $clientSmbv1
                RiskLevel              = if ($serverSmbv1 -ne 0) { 'High' } else { 'Low' }
            }
        }
    }
}

#endregion

#region LDAP Signing

function Get-LDAPSigningPolicy {
    <#
    .SYNOPSIS
        Retrieves the LDAP signing policy from one or more domain controllers.
    .DESCRIPTION
        Checks the LDAPServerIntegrity registry value under:
        HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
        0 = None, 1 = Negotiate (optional), 2 = Require signing
    .PARAMETER ComputerName
        Domain controllers to check.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-LDAPSigningPolicy -ComputerName dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Checking LDAP signing policy on: $computer"

            # DC-side LDAP signing
            $ldapIntegrity = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                -Value 'LDAPServerIntegrity' -Credential $Credential

            # Client-side LDAP signing policy (via GPO)
            $clientSigning = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Services\ldap' `
                -Value 'LDAPClientIntegrity' -Credential $Credential

            $serverPolicy = switch ($ldapIntegrity) {
                0       { 'None' }
                1       { 'Negotiate' }
                2       { 'Required' }
                default { 'Unknown' }
            }

            $clientPolicy = switch ($clientSigning) {
                0       { 'None' }
                1       { 'Negotiate' }
                2       { 'Required' }
                default { 'Unknown' }
            }

            # Check LDAP channel binding (Windows Server 2019+)
            $channelBinding = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' `
                -Value 'LdapEnforceChannelBinding' -Credential $Credential

            $cbPolicy = switch ($channelBinding) {
                0       { 'Never' }
                1       { 'When Supported' }
                2       { 'Always' }
                default { 'Unknown' }
            }

            [PSCustomObject]@{
                ComputerName          = $computer
                ServerLDAPSigning     = $serverPolicy
                ClientLDAPSigning     = $clientPolicy
                ChannelBindingPolicy  = $cbPolicy
                ServerSigningRawValue = $ldapIntegrity
                IsSigningRequired     = ($ldapIntegrity -eq 2)
                RiskLevel             = if ($ldapIntegrity -lt 2) { 'High' } else { 'Low' }
            }
        }
    }
}

#endregion

#region NTLM Settings

function Get-NTLMSettings {
    <#
    .SYNOPSIS
        Retrieves NTLM authentication configuration.
    .DESCRIPTION
        Checks LMCompatibilityLevel and related NTLM restriction registry keys.
        Level 0-2 allows NTLMv1 (insecure); Level 3-5 enforces NTLMv2.
    .PARAMETER ComputerName
        Target hosts.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-NTLMSettings -ComputerName dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Checking NTLM settings on: $computer"

            $lmLevel = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Control\Lsa' `
                -Value 'LmCompatibilityLevel' -Credential $Credential

            # NoLMHash = 1 means LM password hashes not stored
            $noLmHash = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Control\Lsa' `
                -Value 'NoLMHash' -Credential $Credential

            # NTLM auditing/restrictions
            $restrictNtlm = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
                -Value 'RestrictSendingNTLMTraffic' -Credential $Credential

            $levelDesc = switch ($lmLevel) {
                0       { 'Send LM and NTLM responses (highly insecure)' }
                1       { 'Send LM and NTLM, use NTLMv2 if negotiated' }
                2       { 'Send NTLM responses only' }
                3       { 'Send NTLMv2 responses only' }
                4       { 'Send NTLMv2 only, refuse LM' }
                5       { 'Send NTLMv2 only, refuse LM and NTLM (most secure)' }
                default { 'Unknown / Default (typically 0)' }
            }

            $isInsecure = ($null -eq $lmLevel) -or ($lmLevel -lt 3)

            [PSCustomObject]@{
                ComputerName             = $computer
                LmCompatibilityLevel     = if ($null -ne $lmLevel) { $lmLevel } else { 0 }
                LmCompatibilityDesc      = $levelDesc
                NTLMv1Enabled            = $isInsecure
                LmHashesStored           = ($noLmHash -ne 1)
                RestrictSendingNTLM      = $restrictNtlm
                RiskLevel                = if ($isInsecure) { 'High' } else { 'Low' }
            }
        }
    }
}

#endregion

#region Kerberos Encryption

function Get-KerberosEncryptionTypes {
    <#
    .SYNOPSIS
        Retrieves Kerberos encryption type configuration.
    .DESCRIPTION
        Checks the supported Kerberos encryption types from the registry and identifies
        whether weak encryption (DES, RC4) is allowed.
    .PARAMETER ComputerName
        Target domain controllers to check.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-KerberosEncryptionTypes -ComputerName dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName = @('localhost'),
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "Checking Kerberos encryption types on: $computer"

            $supportedTypes = Invoke-RemoteRegistry -ComputerName $computer -Hive HKLM `
                -Key 'SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
                -Value 'SupportedEncryptionTypes' -Credential $Credential

            # Kerberos encryption type bitmask
            # 0x1  = DES-CBC-CRC
            # 0x2  = DES-CBC-MD5
            # 0x4  = RC4-HMAC
            # 0x8  = AES128-CTS-HMAC-SHA1-96
            # 0x10 = AES256-CTS-HMAC-SHA1-96

            $types = if ($null -ne $supportedTypes) { $supportedTypes } else { 28 } # Default: RC4+AES

            [PSCustomObject]@{
                ComputerName         = $computer
                RawEncryptionTypes   = $types
                DES_CBC_CRC          = [bool]($types -band 0x1)
                DES_CBC_MD5          = [bool]($types -band 0x2)
                RC4_HMAC             = [bool]($types -band 0x4)
                AES128_HMAC_SHA1     = [bool]($types -band 0x8)
                AES256_HMAC_SHA1     = [bool]($types -band 0x10)
                WeakEncryptionEnabled = [bool](($types -band 0x3) -gt 0)  # DES enabled
                RC4Enabled           = [bool]($types -band 0x4)
                RiskLevel            = if ($types -band 0x3) { 'High' } elseif ($types -band 0x4) { 'Medium' } else { 'Low' }
            }
        }
    }
}

#endregion

Export-ModuleMember -Function Get-SMBSigningStatus, Get-SMBv1Status, Get-LDAPSigningPolicy,
                               Get-NTLMSettings, Get-KerberosEncryptionTypes
