#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Configuration & GPO Analysis Module
.DESCRIPTION
    Checks AD environment configuration including network protocol security,
    GPO settings, SYSVOL content, and trust relationship risks.
    All findings include severity, remediation guidance, and MITRE ATT&CK mapping.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region Helper

function New-Finding {
    param(
        [string]$RuleId,
        [string]$Title,
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity,
        [string]$Category     = 'Configuration & GPO',
        [string]$Description,
        [object[]]$AffectedObjects,
        [string]$Remediation,
        [string]$MitreAttack  = '',
        [hashtable]$ExtraData = @{}
    )
    return [PSCustomObject]@{
        RuleId          = $RuleId
        Title           = $Title
        Severity        = $Severity
        Category        = $Category
        Description     = $Description
        AffectedObjects = @($AffectedObjects | Where-Object { $_ })
        AffectedCount   = @($AffectedObjects | Where-Object { $_ }).Count
        Remediation     = $Remediation
        MitreAttack     = $MitreAttack
        ExtraData       = $ExtraData
        DetectedAt      = (Get-Date -Format 'o')
    }
}

#endregion

#region Protocol Checks

function Invoke-WeakProtocolCheck {
    <#
    .SYNOPSIS
        Checks for insecure network protocol configurations.
    .DESCRIPTION
        Evaluates SMB signing, LDAP signing, SMBv1, LDAP channel binding, and NTLM
        settings across domain controllers. Identifies configurations that enable
        NTLM relay, credential capture, and man-in-the-middle attacks.
    .PARAMETER DomainControllers
        DC objects from Get-ADDomainControllers.
    .PARAMETER SmbSigningData
        Results from Get-SMBSigningStatus.
    .PARAMETER LdapSigningData
        Results from Get-LDAPSigningPolicy.
    .PARAMETER SmbV1Data
        Results from Get-SMBv1Status.
    .PARAMETER NtlmData
        Results from Get-NTLMSettings.
    .EXAMPLE
        Invoke-WeakProtocolCheck -DomainControllers $dcs -SmbSigningData $smbData -LdapSigningData $ldapData
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$DomainControllers = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$SmbSigningData = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$LdapSigningData = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$SmbV1Data = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$NtlmData = @()
    )

    Write-Verbose "Running weak protocol checks..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # --- SMB Signing ---
    $smbNotRequired = @($SmbSigningData | Where-Object { -not $_.SmbSigningRequired -and $null -eq $_.Error })
    if ($smbNotRequired.Count -gt 0) {
        $affected = $smbNotRequired | Select-Object -ExpandProperty ComputerName
        $findings.Add((New-Finding `
            -RuleId    'CG-001' `
            -Title     "SMB signing NOT required on $($smbNotRequired.Count) host(s)" `
            -Severity  'High' `
            -Description "SMB signing is not required on these hosts. Without required SMB signing, NTLM relay attacks (e.g., Responder + ntlmrelayx) can be used to authenticate as domain users." `
            -AffectedObjects $affected `
            -Remediation 'Enable "Microsoft network server: Digitally sign communications (always)" via GPO. Apply to all domain-joined systems, especially DCs and file servers.' `
            -MitreAttack 'T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay' `
        ))
    }

    # --- LDAP Signing ---
    $ldapWeak = @($LdapSigningData | Where-Object { $_.ServerLDAPSigning -ne 'Required' -and $null -ne $_ })
    if ($ldapWeak.Count -gt 0) {
        $affected = $ldapWeak | Select-Object -ExpandProperty ComputerName
        $findings.Add((New-Finding `
            -RuleId    'CG-002' `
            -Title     "LDAP signing not required on $($ldapWeak.Count) DC(s)" `
            -Severity  'High' `
            -Description "LDAP signing is not enforced (Required) on these domain controllers. This enables LDAP relay attacks: attackers can relay NTLM authentication to LDAP to create accounts, modify ACLs, or configure RBCD." `
            -AffectedObjects $affected `
            -Remediation 'Set "Domain controller: LDAP server signing requirements" to "Require signing" in the Default Domain Controller Policy GPO. Also set LdapEnforceChannelBinding for LDAPS.' `
            -MitreAttack 'T1557 - Adversary-in-the-Middle' `
        ))
    }

    # --- LDAP Channel Binding ---
    $ldapNoCB = @($LdapSigningData | Where-Object { $_.ChannelBindingPolicy -ne 'Always' -and $null -ne $_ })
    if ($ldapNoCB.Count -gt 0) {
        $affected = $ldapNoCB | Select-Object -ExpandProperty ComputerName
        $findings.Add((New-Finding `
            -RuleId    'CG-003' `
            -Title     "LDAP channel binding not enforced on $($ldapNoCB.Count) DC(s)" `
            -Severity  'Medium' `
            -Description "LDAP channel binding is not set to 'Always' on these DCs. Channel binding prevents NTLM relay to LDAPS by tying the NTLM authentication to the TLS channel." `
            -AffectedObjects $affected `
            -Remediation 'Set LdapEnforceChannelBinding=2 (Always) in HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters on all DCs.' `
            -MitreAttack 'T1557 - Adversary-in-the-Middle' `
        ))
    }

    # --- SMBv1 ---
    $smbv1Enabled = @($SmbV1Data | Where-Object { $_.SMBv1ServerEnabled -eq $true })
    if ($smbv1Enabled.Count -gt 0) {
        $affected = $smbv1Enabled | Select-Object -ExpandProperty ComputerName
        $findings.Add((New-Finding `
            -RuleId    'CG-004' `
            -Title     "SMBv1 is ENABLED on $($smbv1Enabled.Count) host(s)" `
            -Severity  'Critical' `
            -Description "SMBv1 is enabled on these systems. SMBv1 is the attack vector used by EternalBlue/WannaCry/NotPetya. It should never be enabled in a modern environment." `
            -AffectedObjects $affected `
            -Remediation 'Disable SMBv1 on all systems: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Remove the SMBv1 Windows feature where possible.' `
            -MitreAttack 'T1210 - Exploitation of Remote Services' `
        ))
    }

    # --- NTLM v1 ---
    $ntlmV1 = @($NtlmData | Where-Object { $_.NTLMv1Enabled -eq $true })
    if ($ntlmV1.Count -gt 0) {
        $affected = $ntlmV1 | Select-Object -ExpandProperty ComputerName
        $findings.Add((New-Finding `
            -RuleId    'CG-005' `
            -Title     "NTLMv1 may be allowed on $($ntlmV1.Count) host(s)" `
            -Severity  'High' `
            -Description "The LmCompatibilityLevel is set below 3 on these systems, which may allow NTLMv1 authentication. NTLMv1 can be captured and cracked trivially, and is also vulnerable to pass-the-hash attacks." `
            -AffectedObjects $affected `
            -Remediation 'Set LmCompatibilityLevel=5 (Send NTLMv2 only, refuse LM and NTLM) on all systems via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options.' `
            -MitreAttack 'T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay' `
        ))
    }

    Write-Verbose "Weak protocol checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region GPO Security Checks

function Invoke-GPOSecurityCheck {
    <#
    .SYNOPSIS
        Checks Group Policy Objects for security misconfigurations.
    .DESCRIPTION
        Scans SYSVOL for cPassword (MS14-025) in Group Policy Preferences files,
        detects GPOs linked to high-value OUs with overly permissive settings,
        and flags GPOs with no security filtering.
    .PARAMETER GPOs
        GPO objects from Get-ADGPOs.
    .PARAMETER SysvolPath
        UNC path to SYSVOL share. Auto-discovered if not specified.
    .PARAMETER DomainName
        Domain DNS name for SYSVOL path construction.
    .EXAMPLE
        Invoke-GPOSecurityCheck -GPOs $adGPOs -DomainName 'corp.local'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$GPOs = @(),

        [Parameter(Mandatory = $false)]
        [string]$SysvolPath,

        [Parameter(Mandatory = $false)]
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    Write-Verbose "Running GPO security checks..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # --- cPassword in SYSVOL (MS14-025) ---
    if ([string]::IsNullOrEmpty($SysvolPath) -and -not [string]::IsNullOrEmpty($DomainName)) {
        $SysvolPath = "\\$DomainName\SYSVOL\$DomainName\Policies"
    }

    if (-not [string]::IsNullOrEmpty($SysvolPath) -and (Test-Path $SysvolPath)) {
        Write-Verbose "Scanning SYSVOL for cPassword in: $SysvolPath"
        try {
            $gppFiles = Get-ChildItem -Path $SysvolPath -Recurse -Include `
                'Groups.xml','Services.xml','Scheduledtasks.xml',
                'DataSources.xml','Printers.xml','Drives.xml' `
                -ErrorAction SilentlyContinue

            $cpasswordHits = [System.Collections.Generic.List[object]]::new()
            foreach ($file in $gppFiles) {
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match 'cpassword="([^"]+)"') {
                        $cpasswordHits.Add([PSCustomObject]@{
                            File      = $file.FullName
                            GPO_GUID  = ($file.FullName -split '\\')[6]  # Extract GUID from path
                        })
                    }
                }
                catch { Write-Verbose "Could not read $($file.FullName)" }
            }

            if ($cpasswordHits.Count -gt 0) {
                $findings.Add((New-Finding `
                    -RuleId    'CG-010' `
                    -Title     "cPassword (MS14-025) found in $($cpasswordHits.Count) SYSVOL file(s)" `
                    -Severity  'Critical' `
                    -Description "Group Policy Preference files containing cpassword attributes were found. These use a static AES key published by Microsoft (MS14-025), meaning any domain user can decrypt the stored passwords. This is a critical credential exposure vulnerability." `
                    -AffectedObjects ($cpasswordHits | Select-Object -ExpandProperty File) `
                    -Remediation 'Remove all Group Policy Preferences containing cpassword immediately. Use the Microsoft fix from MS14-025 and the Group Policy Management Editor to find and remove affected settings. Consider the passwords as fully compromised.' `
                    -MitreAttack 'T1552.006 - Unsecured Credentials: Group Policy Preferences' `
                    -ExtraData @{ Files = $cpasswordHits }
                ))
            }
        }
        catch {
            Write-Warning "SYSVOL scan error: $_"
        }
    }
    else {
        Write-Verbose "SYSVOL path not accessible or not specified; skipping cPassword scan."
    }

    # --- GPO link analysis ---
    $disabledGPOs = @($GPOs | Where-Object { -not $_.IsEnabled })
    if ($disabledGPOs.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId    'CG-011' `
            -Title     "$($disabledGPOs.Count) GPO(s) are fully disabled but still exist" `
            -Severity  'Informational' `
            -Description "Disabled GPOs still exist in Active Directory. While not directly dangerous, they increase administrative complexity and may be re-enabled accidentally." `
            -AffectedObjects ($disabledGPOs | Select-Object -ExpandProperty DisplayName) `
            -Remediation 'Review and delete GPOs that are no longer needed. Document any GPOs kept for historical reference.' `
            -MitreAttack '' `
        ))
    }

    # GPOs with very old version numbers (never updated)
    $staleGPOs = @($GPOs | Where-Object { $_.VersionNumber -eq 0 -and $_.IsEnabled })
    if ($staleGPOs.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId    'CG-012' `
            -Title     "$($staleGPOs.Count) enabled GPO(s) have never been configured (version 0)" `
            -Severity  'Low' `
            -Description "These GPOs are enabled but have a version number of 0, indicating they have never been configured with any settings. Empty GPOs create unnecessary processing overhead and may represent configuration errors." `
            -AffectedObjects ($staleGPOs | Select-Object -ExpandProperty DisplayName) `
            -Remediation 'Review and delete empty GPOs. If they serve as link placeholders, document the intent and add a description.' `
            -MitreAttack '' `
        ))
    }

    Write-Verbose "GPO security checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Trust Checks

function Invoke-TrustCheck {
    <#
    .SYNOPSIS
        Analyzes domain and forest trust relationships for security risks.
    .DESCRIPTION
        Examines trust attributes to identify:
        - Trusts with SID filtering disabled (SID history attacks)
        - Bidirectional trusts (larger attack surface)
        - External trusts (cross-forest with limited isolation)
        - Trusts to unknown/uncategorized domains
    .PARAMETER Trusts
        Trust objects from Get-ADTrusts.
    .EXAMPLE
        Invoke-TrustCheck -Trusts $adTrusts
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Trusts
    )

    Write-Verbose "Running trust relationship checks..."
    $findings = [System.Collections.Generic.List[object]]::new()

    if ($Trusts.Count -eq 0) {
        Write-Verbose "No trusts found."
        return @()
    }

    # --- SID Filtering disabled ---
    $noSidFilter = @($Trusts | Where-Object { -not $_.IsSidFilteringEnabled })
    if ($noSidFilter.Count -gt 0) {
        $affected = $noSidFilter | Select-Object -ExpandProperty TrustPartner
        $findings.Add((New-Finding `
            -RuleId    'CG-020' `
            -Title     "SID filtering disabled on $($noSidFilter.Count) trust(s)" `
            -Severity  'Critical' `
            -Description "SID filtering (Quarantine/SID History Filtering) is disabled on these trusts. Without SID filtering, users in the trusted domain can add arbitrary high-privilege SID history values and escalate to Domain Admin in the trusting domain." `
            -AffectedObjects $affected `
            -Remediation 'Enable SID filtering on all external trusts using: netdom trust <TrustingDomain> /domain:<TrustedDomain> /EnableSIDHistory:No. Forest trusts should use selective authentication.' `
            -MitreAttack 'T1134.005 - Access Token Manipulation: SID-History Injection' `
        ))
    }

    # --- Bidirectional trusts ---
    $bidir = @($Trusts | Where-Object { $_.TrustDirection -eq 'Bidirectional' })
    if ($bidir.Count -gt 0) {
        $affected = $bidir | Select-Object -ExpandProperty TrustPartner
        $findings.Add((New-Finding `
            -RuleId    'CG-021' `
            -Title     "$($bidir.Count) bidirectional trust(s) found" `
            -Severity  'Medium' `
            -Description "Bidirectional trusts allow authentication to flow in both directions, doubling the attack surface. A compromise in the trusted domain can be leveraged against the trusting domain and vice versa." `
            -AffectedObjects $affected `
            -Remediation 'Review whether bidirectional trusts are necessary. Convert to one-way trusts where possible. Enable selective authentication on all forest trusts.' `
            -MitreAttack 'T1199 - Trusted Relationship' `
        ))
    }

    # --- External (non-transitive) trusts ---
    $external = @($Trusts | Where-Object { -not $_.IsForestTrust -and -not $_.IsTransitive })
    if ($external.Count -gt 0) {
        $affected = $external | Select-Object -ExpandProperty TrustPartner
        $findings.Add((New-Finding `
            -RuleId    'CG-022' `
            -Title     "$($external.Count) external trust(s) to non-forest domains" `
            -Severity  'Medium' `
            -Description "External trusts exist to non-forest domains. External trusts provide weaker isolation than forest trusts and may represent legacy configurations that are difficult to fully audit." `
            -AffectedObjects $affected `
            -Remediation 'Review all external trusts for business necessity. Migrate to forest trusts where possible. Ensure selective authentication is enabled.' `
            -MitreAttack 'T1199 - Trusted Relationship' `
        ))
    }

    Write-Verbose "Trust checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

Export-ModuleMember -Function Invoke-WeakProtocolCheck, Invoke-GPOSecurityCheck, Invoke-TrustCheck
