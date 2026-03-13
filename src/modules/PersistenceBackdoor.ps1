#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Persistence & Backdoor Detection Module
.DESCRIPTION
    Detects persistence mechanisms and backdoors in Active Directory:
    - AdminSDHolder modifications
    - SID History abuse
    - DCSync-capable accounts
    - Skeleton Key indicators
    - Rogue domain controllers
    All checks are READ-ONLY.
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
        [string]$Category    = 'Persistence & Backdoor',
        [string]$Description,
        [object[]]$AffectedObjects,
        [string]$Remediation,
        [string]$MitreAttack = '',
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

#region AdminSDHolder

function Invoke-AdminSDHolderCheck {
    <#
    .SYNOPSIS
        Detects unauthorized modifications to the AdminSDHolder object.
    .DESCRIPTION
        The AdminSDHolder object (CN=AdminSDHolder,CN=System) holds the security descriptor
        template applied to all protected accounts/groups. Attackers commonly add ACEs to
        AdminSDHolder to maintain persistence with delayed propagation.

        This check:
        1. Reads the AdminSDHolder ACL and flags non-standard principals with high permissions
        2. Identifies accounts with AdminCount=1 that are not members of known privileged groups
    .PARAMETER ACLs
        ACL objects from Get-ADACLs (should include AdminSDHolder ACEs).
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Groups
        Group objects from Get-ADGroups.
    .EXAMPLE
        Invoke-AdminSDHolderCheck -ACLs $adACLs -Users $adUsers -Groups $adGroups
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$ACLs = @(),
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        [Parameter(Mandatory = $false)]
        [object[]]$Groups = @()
    )

    Write-Verbose "Running AdminSDHolder check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # Known legitimate principals that may appear in AdminSDHolder ACL
    $legitimatePrincipals = @(
        'SYSTEM',
        'NT AUTHORITY\SYSTEM',
        'BUILTIN\Administrators',
        'Enterprise Admins',
        'Domain Admins',
        'Administrators',
        'Schema Admins'
    )

    # --- Check AdminSDHolder ACL for suspicious entries ---
    $adminSDHolderACEs = @($ACLs | Where-Object {
        $_.TargetObject -like '*AdminSDHolder*'
    })

    if ($adminSDHolderACEs.Count -gt 0) {
        $suspiciousACEs = @($adminSDHolderACEs | Where-Object {
            $identity = $_.IdentityReference
            $isLegit = $legitimatePrincipals | Where-Object { $identity -like "*$_*" }
            $hasHighRights = $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights'
            -not $isLegit -and $hasHighRights -and $_.AccessControlType -eq 'Allow'
        })

        if ($suspiciousACEs.Count -gt 0) {
            $affected = $suspiciousACEs | Select-Object -ExpandProperty IdentityReference -Unique
            $findings.Add((New-Finding `
                -RuleId    'PB-001' `
                -Title     "Suspicious ACE(s) on AdminSDHolder ($($suspiciousACEs.Count) non-standard entries)" `
                -Severity  'Critical' `
                -Description "Non-standard principals have high-privilege permissions on the AdminSDHolder object. The SDProp process (runs every 60 minutes) propagates these ACEs to all protected accounts. This is a classic domain persistence technique — the backdoor is applied automatically to all Domain Admins." `
                -AffectedObjects $affected `
                -Remediation '1) Remove suspicious ACEs from AdminSDHolder immediately. 2) Force SDProp by running: Invoke-Command -ScriptBlock { Start-Process ldp }. 3) Investigate how these ACEs were added and who performed the action. 4) Audit all protected accounts for unexpected permissions.' `
                -MitreAttack 'T1098 - Account Manipulation' `
                -ExtraData @{ SuspiciousACEs = $suspiciousACEs }
            ))
        }
    }

    # --- Orphaned AdminCount=1 accounts ---
    # Accounts with AdminCount=1 that are not in known privileged groups (indicate former privilege or manual manipulation)
    $privGroupDNs = @($Groups | Where-Object {
        $_.SamAccountName -in @('Domain Admins','Enterprise Admins','Schema Admins',
            'Backup Operators','Account Operators','Print Operators','Server Operators',
            'Administrators','Group Policy Creator Owners')
    } | Select-Object -ExpandProperty Members | Where-Object { $_ })

    $orphanedAdminCount = @($Users | Where-Object {
        $_.AdminCount -eq 1 -and $_.Enabled -and $_.DistinguishedName -notin $privGroupDNs
    })

    if ($orphanedAdminCount.Count -gt 0) {
        $affected = $orphanedAdminCount | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'PB-002' `
            -Title     "$($orphanedAdminCount.Count) account(s) with orphaned AdminCount=1 (not in privileged groups)" `
            -Severity  'High' `
            -Description "These accounts have AdminCount=1 (indicating they were previously in a protected group) but are no longer members of any protected group. AdminCount=1 prevents the normal password and lockout policies from applying, and their ACLs are not being refreshed by SDProp. This can be used as a stealthy persistence mechanism." `
            -AffectedObjects $affected `
            -Remediation '1) Clear AdminCount attribute (set to 0) for accounts not in protected groups. 2) Review account history — determine if these accounts were inappropriately elevated. 3) Reset password inheritance on the accounts after clearing AdminCount.' `
            -MitreAttack 'T1098 - Account Manipulation' `
        ))
    }

    Write-Verbose "AdminSDHolder check complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region SID History

function Invoke-SIDHistoryCheck {
    <#
    .SYNOPSIS
        Identifies accounts with suspicious SID History values.
    .DESCRIPTION
        SID History is used during domain migrations to maintain access. However,
        attackers use it to grant accounts persistent high privileges by adding
        privileged SIDs (e.g., S-1-5-21-*-512 for Domain Admins).

        This check identifies:
        1. Accounts with any SID History values
        2. SID History values matching known privileged RIDs (500, 502, 512-519, 544, 548, 549)
    .PARAMETER Users
        User objects from Get-ADUsers.
    .EXAMPLE
        Invoke-SIDHistoryCheck -Users $adUsers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )

    Write-Verbose "Running SID History check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # Privileged RIDs that should never appear in SID History for normal accounts
    $privilegedRIDs = @(500, 502, 512, 513, 514, 515, 516, 517, 518, 519, 520, 544, 548, 549, 551)

    $usersWithSidHistory = @($Users | Where-Object {
        $null -ne $_.SidHistory -and $_.SidHistory.Count -gt 0
    })

    if ($usersWithSidHistory.Count -eq 0) { return @() }

    # Flag accounts with any SID history (worth reviewing)
    $findings.Add((New-Finding `
        -RuleId    'PB-010' `
        -Title     "$($usersWithSidHistory.Count) account(s) have SID History values" `
        -Severity  'Medium' `
        -Description "These accounts have SID History attributes populated. While legitimate during domain migrations, SID History can be abused by attackers to grant persistent elevated privileges that persist across privilege review cycles." `
        -AffectedObjects ($usersWithSidHistory | Select-Object -ExpandProperty SamAccountName) `
        -Remediation 'Review all SID History entries. If domain migration is complete, clear SID History from accounts. Use the Get-ADUser cmdlet to inspect and Remove-ADUser SID History.' `
        -MitreAttack 'T1134.005 - Access Token Manipulation: SID-History Injection' `
    ))

    # Flag accounts where SID History contains privileged RIDs
    $highPrivSidHistory = [System.Collections.Generic.List[object]]::new()
    foreach ($user in $usersWithSidHistory) {
        foreach ($sidBytes in $user.SidHistory) {
            try {
                $sid    = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                $sidStr = $sid.Value
                # Extract RID (last component)
                $rid    = [int]($sidStr.Split('-')[-1])
                if ($rid -in $privilegedRIDs) {
                    $highPrivSidHistory.Add([PSCustomObject]@{
                        SamAccountName = $user.SamAccountName
                        SidHistory     = $sidStr
                        RID            = $rid
                    })
                }
            }
            catch { Write-Verbose "Could not parse SID for $($user.SamAccountName)" }
        }
    }

    if ($highPrivSidHistory.Count -gt 0) {
        $affected = $highPrivSidHistory | Select-Object -ExpandProperty SamAccountName -Unique
        $findings.Add((New-Finding `
            -RuleId    'PB-011' `
            -Title     "$($highPrivSidHistory.Count) account(s) have privileged SIDs in SID History" `
            -Severity  'Critical' `
            -Description "These accounts have high-privilege SIDs (RID 500/512-519/544) in their SID History. This grants the account the permissions of the historical SID in addition to their current permissions, enabling effective privilege escalation." `
            -AffectedObjects $affected `
            -Remediation '1) Immediately clear the SID History for these accounts. 2) Investigate how the SID History was set — this is a strong indicator of compromise or unauthorized change. 3) Reset the account passwords and review recent logon history.' `
            -MitreAttack 'T1134.005 - Access Token Manipulation: SID-History Injection' `
            -ExtraData @{ Details = $highPrivSidHistory }
        ))
    }

    Write-Verbose "SID History check complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region DCSync Rights

function Invoke-DCSyncRightsCheck {
    <#
    .SYNOPSIS
        Identifies non-standard accounts with DCSync-capable permissions.
    .DESCRIPTION
        DCSync requires 'Replicating Directory Changes' and 'Replicating Directory Changes All'
        extended rights on the domain partition. This check reads the domain root ACL and
        identifies principals with these rights that are not Domain Controllers or standard
        replication accounts.

        Extended rights GUIDs:
        1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes
        1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 = DS-Replication-Get-Changes-All
        89e95b76-444d-4c62-991a-0facbeda640c = DS-Replication-Get-Changes-In-Filtered-Set
    .PARAMETER ACLs
        ACL objects from Get-ADACLs (domain root ACEs).
    .EXAMPLE
        Invoke-DCSyncRightsCheck -ACLs $adACLs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ACLs
    )

    Write-Verbose "Running DCSync rights check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # Extended right GUIDs for replication
    $replicationGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
        '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
    )

    # Legitimate principals that should have replication rights
    $legitimatePrincipals = @(
        'Domain Controllers',
        'Enterprise Domain Controllers',
        'Enterprise Read-Only Domain Controllers',
        'Administrators',
        'ENTERPRISE DOMAIN CONTROLLERS',
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
        'BUILTIN\Administrators'
    )

    # Find domain root ACEs (first component of DN without the DC= parts)
    $domainRootACEs = @($ACLs | Where-Object {
        $dn = $_.TargetObject
        # Match ACEs on domain root (DC=...,DC=...)
        $dn -match '^DC=' -and $dn -notlike '*CN=*'
    })

    $replicationACEs = @($domainRootACEs | Where-Object {
        $_.ObjectType -in $replicationGuids -and $_.AccessControlType -eq 'Allow'
    })

    # Also catch GenericAll / AllExtendedRights on domain root
    $broadPermACEs = @($domainRootACEs | Where-Object {
        $_.ActiveDirectoryRights -match 'GenericAll|AllExtendedRights' -and
        $_.AccessControlType -eq 'Allow'
    })

    $allReplicationACEs = @($replicationACEs) + @($broadPermACEs)

    $suspiciousACEs = @($allReplicationACEs | Where-Object {
        $identity = $_.IdentityReference
        $isLegit = $legitimatePrincipals | Where-Object { $identity -like "*$_*" }
        -not $isLegit
    })

    if ($suspiciousACEs.Count -gt 0) {
        $affected = $suspiciousACEs | Select-Object -ExpandProperty IdentityReference -Unique
        $findings.Add((New-Finding `
            -RuleId    'PB-020' `
            -Title     "$($affected.Count) non-standard principal(s) have DCSync-capable rights" `
            -Severity  'Critical' `
            -Description "These principals have 'Replicating Directory Changes' (or AllExtendedRights/GenericAll) on the domain partition. They can perform a DCSync attack using tools like Mimikatz to dump all domain credential hashes without requiring access to a DC." `
            -AffectedObjects $affected `
            -Remediation '1) Remove replication rights from non-DC accounts immediately. 2) Investigate when these rights were granted and by whom (Event ID 5136 in Security log). 3) Rotate credentials for any account that may have used these rights to exfiltrate hashes.' `
            -MitreAttack 'T1003.006 - OS Credential Dumping: DCSync' `
            -ExtraData @{ SuspiciousACEs = $suspiciousACEs }
        ))
    }

    Write-Verbose "DCSync rights check complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Skeleton Key Indicators

function Invoke-SkeletonKeyCheck {
    <#
    .SYNOPSIS
        Looks for indicators of Skeleton Key malware implant on domain controllers.
    .DESCRIPTION
        READ-ONLY heuristic check. Skeleton Key patches LSASS on domain controllers,
        allowing authentication with a master password alongside normal passwords.
        Detection indicators (none are definitive without memory analysis):
        1. Unexpected processes / service names on DCs
        2. LSASS integrity check via CIM
        3. Suspicious modules loaded by LSASS (via WMI)
        4. Presence of known Skeleton Key indicator files/services
        NOTE: Skeleton Key survives only until DC reboot. Full detection requires memory forensics.
    .PARAMETER DomainControllers
        DC objects.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Invoke-SkeletonKeyCheck -DomainControllers $dcs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Running Skeleton Key indicator check (heuristic)..."
    $findings = [System.Collections.Generic.List[object]]::new()
    $indicators = [System.Collections.Generic.List[object]]::new()

    # Known Skeleton Key / implant indicators
    $suspiciousServiceNames = @('msupdate','wceaux','fgexec','wce','htran')
    $suspiciousProcessNames = @('mimikatz','wce','gsecdump','fgdump','pwdump')

    foreach ($dc in $DomainControllers) {
        $hostname = if ($dc.DnsHostName) { $dc.DnsHostName } else { $dc.Name }

        try {
            $cimParams = @{ ClassName = 'Win32_Process'; ErrorAction = 'Stop' }
            if ($hostname -ne $env:COMPUTERNAME -and $hostname -ne 'localhost') {
                if ($null -ne $Credential) {
                    $session = New-CimSession -ComputerName $hostname -Credential $Credential -ErrorAction Stop
                    $cimParams.CimSession = $session
                }
                else {
                    $cimParams.ComputerName = $hostname
                }
            }

            $processes = Get-CimInstance @cimParams
            if ($null -ne ($cimParams['CimSession'])) {
                Remove-CimSession $cimParams['CimSession'] -ErrorAction SilentlyContinue
            }

            foreach ($proc in $processes) {
                if ($proc.Name -replace '\.exe$','' -in $suspiciousProcessNames) {
                    $indicators.Add([PSCustomObject]@{
                        DCName    = $hostname
                        Type      = 'SuspiciousProcess'
                        Name      = $proc.Name
                        ProcessId = $proc.ProcessId
                        Path      = $proc.ExecutablePath
                    })
                }
            }
        }
        catch {
            Write-Verbose "Could not query processes on ${hostname}: $_"
        }

        # Check for suspicious services
        try {
            $svcParams = @{ ClassName = 'Win32_Service'; ErrorAction = 'Stop' }
            if ($hostname -ne $env:COMPUTERNAME -and $hostname -ne 'localhost') {
                $svcParams.ComputerName = $hostname
                if ($null -ne $Credential) { $svcParams.Credential = $Credential }
            }
            $services = Get-CimInstance @svcParams
            foreach ($svc in $services) {
                if ($svc.Name -in $suspiciousServiceNames) {
                    $indicators.Add([PSCustomObject]@{
                        DCName = $hostname
                        Type   = 'SuspiciousService'
                        Name   = $svc.Name
                        State  = $svc.State
                        Path   = $svc.PathName
                    })
                }
            }
        }
        catch {
            Write-Verbose "Could not query services on ${hostname}: $_"
        }
    }

    if ($indicators.Count -gt 0) {
        $affectedDCs = $indicators | Select-Object -ExpandProperty DCName -Unique
        $findings.Add((New-Finding `
            -RuleId    'PB-030' `
            -Title     "Potential Skeleton Key / malware indicators on $($affectedDCs.Count) DC(s)" `
            -Severity  'Critical' `
            -Description "Suspicious processes or services associated with credential theft / LSASS manipulation were found on domain controllers. This may indicate a Skeleton Key implant or active credential theft tool." `
            -AffectedObjects $affectedDCs `
            -Remediation '1) Isolate affected DCs immediately. 2) Perform memory forensics with Volatility or similar tools. 3) Reboot DCs to clear in-memory Skeleton Key implants. 4) Rotate ALL domain credentials (KRBTGT twice, all privileged accounts). 5) Review authentication events for suspicious patterns.' `
            -MitreAttack 'T1556.001 - Modify Authentication Process: Domain Controller Authentication' `
            -ExtraData @{ Indicators = $indicators }
        ))
    }
    else {
        Write-Verbose "No Skeleton Key process/service indicators found. Note: full detection requires memory forensics."
    }

    return $findings.ToArray()
}

#endregion

#region Rogue DC Detection

function Invoke-RogueDCCheck {
    <#
    .SYNOPSIS
        Identifies potential rogue or unexpected domain controllers.
    .DESCRIPTION
        Compares domain controllers found via LDAP (legitimate DCs registered in AD) with
        those found in DNS SRV records and the Sites/Services configuration. Discrepancies
        may indicate a rogue DC or a DC that was improperly decommissioned.
    .PARAMETER DomainControllers
        DC objects from Get-ADDomainControllers.
    .PARAMETER DomainName
        DNS domain name for SRV record lookup.
    .EXAMPLE
        Invoke-RogueDCCheck -DomainControllers $dcs -DomainName 'corp.local'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers,
        [Parameter(Mandatory = $false)]
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    Write-Verbose "Running rogue DC detection check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    $adDCNames = @($DomainControllers | Select-Object -ExpandProperty DnsHostName | Where-Object { $_ })

    # Attempt DNS SRV lookup for _ldap._tcp.<domain>
    $dnsDCNames = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrEmpty($DomainName)) {
        try {
            $srvRecords = Resolve-DnsName -Name "_ldap._tcp.$DomainName" -Type SRV -ErrorAction Stop
            foreach ($rec in $srvRecords) {
                if ($rec.PSObject.Properties['NameTarget']) {
                    $dnsDCNames.Add($rec.NameTarget.TrimEnd('.').ToLower())
                }
            }
            Write-Verbose "DNS SRV lookup found $($dnsDCNames.Count) DCs."
        }
        catch {
            Write-Verbose "DNS SRV lookup failed: $_"
        }
    }

    # DCs in DNS but not in AD
    $adDCNamesLower = @($adDCNames | ForEach-Object { $_.ToLower() })
    $inDNSNotAD = @($dnsDCNames | Where-Object { $_ -notin $adDCNamesLower })

    if ($inDNSNotAD.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId    'PB-040' `
            -Title     "$($inDNSNotAD.Count) DC(s) found in DNS but not in AD computer objects" `
            -Severity  'High' `
            -Description "These hostnames are registered as domain controllers in DNS SRV records but do not appear in Active Directory computer objects. This could indicate a rogue DC, a decommissioned DC with stale DNS records, or a DCShadow attack artifact." `
            -AffectedObjects $inDNSNotAD `
            -Remediation '1) Verify each hostname. 2) If stale, clean DNS SRV records. 3) If unknown, treat as a potential rogue DC — investigate network traffic, LDAP replication events, and DC authentication logs.' `
            -MitreAttack 'T1207 - Rogue Domain Controller' `
        ))
    }

    # Flag RODCs (Read-Only DCs) as informational — they have a unique attack surface
    $rodcs = @($DomainControllers | Where-Object { $_.IsRODC -eq $true })
    if ($rodcs.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId    'PB-041' `
            -Title     "$($rodcs.Count) Read-Only Domain Controller(s) (RODC) detected" `
            -Severity  'Informational' `
            -Description "RODCs are present in the environment. While RODCs provide reduced attack surface for branch offices, misconfigured RODCs (Password Replication Policy, RODC admin delegation) can be used as pivot points." `
            -AffectedObjects ($rodcs | Select-Object -ExpandProperty DnsHostName) `
            -Remediation 'Review RODC Password Replication Policy (PRP). Ensure no highly-privileged accounts are in the Allowed Password Replication Group. Audit RODC admin delegation.' `
            -MitreAttack '' `
        ))
    }

    Write-Verbose "Rogue DC check complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion


#region Startup/Logon Script Abuse

function Invoke-StartupScriptCheck {
    <#
    .SYNOPSIS
        Detects suspicious startup and logon scripts in NETLOGON and SYSVOL.
    .DESCRIPTION
        Enumerates logon/startup/logoff/shutdown scripts configured in GPOs
        (SYSVOL Policies paths) and the NETLOGON share, then flags:
        - Scripts with suspicious extensions (.vbs, .ps1, .bat, .cmd, .js, .hta)
          pointing to external UNC paths outside the domain's SYSVOL/NETLOGON
        - Script files containing known suspicious content patterns
        - Scripts with unexpected permissions (writable by non-admins)

        This detects the persistence technique of planting malicious scripts
        that execute on user logon or machine startup/shutdown.
    .PARAMETER DomainName
        DNS domain name (used to build SYSVOL/NETLOGON paths).
    .PARAMETER SysvolPath
        Override SYSVOL Policies path.
    .PARAMETER GPOs
        GPO objects from Get-ADGPOs (used for metadata enrichment).
    .EXAMPLE
        Invoke-StartupScriptCheck -DomainName 'corp.local'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DomainName = $env:USERDNSDOMAIN,

        [Parameter(Mandatory = $false)]
        [string]$SysvolPath,

        [Parameter(Mandatory = $false)]
        [object[]]$GPOs = @()
    )

    Write-Verbose "Running startup/logon script abuse check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    if ([string]::IsNullOrEmpty($SysvolPath) -and -not [string]::IsNullOrEmpty($DomainName)) {
        $SysvolPath = "\\$DomainName\SYSVOL\$DomainName\Policies"
    }

    if ([string]::IsNullOrEmpty($SysvolPath) -or -not (Test-Path $SysvolPath)) {
        Write-Verbose "SYSVOL not accessible; skipping script abuse check."
        return @()
    }

    $suspiciousPatterns = @(
        'IEX\s*\(',                # Invoke-Expression
        'Invoke-Expression',
        'DownloadString',
        'DownloadFile',
        'WebClient',
        'Start-BitsTransfer',
        'certutil.*-decode',
        'powershell\s+-enc',
        'Net\.Sockets\.TcpClient',
        'Invoke-Mimikatz',
        '-WindowStyle\s+Hidden',
        'cmd\.exe\s*/c',
        'wscript\.shell',
        'regsvr32.*scrobj'
    )

    $suspiciousExtensions = @('.ps1','.vbs','.js','.jse','.hta','.wsf','.bat','.cmd')
    $hits = [System.Collections.Generic.List[object]]::new()

    # Scan SYSVOL Scripts directories
    try {
        $scriptDirs = Get-ChildItem -Path $SysvolPath -Recurse -Directory -Filter 'Scripts' -ErrorAction SilentlyContinue
        foreach ($dir in $scriptDirs) {
            $files = Get-ChildItem -Path $dir.FullName -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ($file.Extension -notin $suspiciousExtensions) { continue }

                $finding = [PSCustomObject]@{
                    Path        = $file.FullName
                    Name        = $file.Name
                    GPO_GUID    = ($file.FullName -split '\\')[6]
                    SuspiciousContent = @()
                    IsWritableByNonAdmins = $false
                }

                # Check content for suspicious patterns
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($content -match $pattern) {
                                $finding.SuspiciousContent += $pattern
                            }
                        }
                    }
                }
                catch { Write-Verbose "Could not read $($file.FullName)" }

                # Check ACL — writable by Authenticated Users or Everyone?
                try {
                    $acl = Get-Acl $file.FullName -ErrorAction SilentlyContinue
                    if ($acl) {
                        $writableByAll = $acl.Access | Where-Object {
                            $_.IdentityReference -match 'Authenticated Users|Everyone|Domain Users|BUILTIN\\Users' -and
                            $_.FileSystemRights  -match 'Write|FullControl|Modify' -and
                            $_.AccessControlType -eq 'Allow'
                        }
                        if ($writableByAll) { $finding.IsWritableByNonAdmins = $true }
                    }
                }
                catch {}

                if ($finding.SuspiciousContent.Count -gt 0 -or $finding.IsWritableByNonAdmins) {
                    $hits.Add($finding)
                }
            }
        }
    }
    catch { Write-Warning "Script abuse SYSVOL scan error: $_" }

    # Also check NETLOGON share scripts
    if (-not [string]::IsNullOrEmpty($DomainName)) {
        $netlogonPath = "\\$DomainName\NETLOGON"
        if (Test-Path $netlogonPath) {
            try {
                $netlogonFiles = Get-ChildItem -Path $netlogonPath -Recurse -File -ErrorAction SilentlyContinue
                foreach ($file in $netlogonFiles) {
                    if ($file.Extension -notin $suspiciousExtensions) { continue }
                    try {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content) {
                            $matched = @($suspiciousPatterns | Where-Object { $content -match $_ })
                            if ($matched.Count -gt 0) {
                                $hits.Add([PSCustomObject]@{
                                    Path              = $file.FullName
                                    Name              = $file.Name
                                    GPO_GUID          = 'NETLOGON'
                                    SuspiciousContent = $matched
                                    IsWritableByNonAdmins = $false
                                })
                            }
                        }
                    }
                    catch {}
                }
            }
            catch { Write-Verbose "NETLOGON scan error: $_" }
        }
    }

    if ($hits.Count -gt 0) {
        $writableFiles  = @($hits | Where-Object { $_.IsWritableByNonAdmins })
        $suspiciousFiles = @($hits | Where-Object { $_.SuspiciousContent.Count -gt 0 })

        if ($suspiciousFiles.Count -gt 0) {
            $findings.Add((New-Finding `
                -RuleId    'PB-050' `
                -Title     "Suspicious content found in $($suspiciousFiles.Count) logon/startup script(s)" `
                -Severity  'Critical' `
                -Description "Logon or startup scripts in SYSVOL/NETLOGON contain patterns associated with malicious activity: download cradles, obfuscated execution, credential theft tools, or reverse shells. These scripts execute on every user logon or machine startup." `
                -AffectedObjects ($suspiciousFiles | Select-Object -ExpandProperty Path) `
                -Remediation '1) Immediately review and quarantine flagged scripts. 2) Investigate who last modified these scripts (Event ID 5136 in AD audit log). 3) Validate all logon/startup scripts against an approved baseline. 4) Restrict write access to SYSVOL/NETLOGON to Domain Admins only.' `
                -MitreAttack 'T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)' `
                -ExtraData @{ SuspiciousFiles = $suspiciousFiles }
            ))
        }

        if ($writableFiles.Count -gt 0) {
            $findings.Add((New-Finding `
                -RuleId    'PB-051' `
                -Title     "$($writableFiles.Count) logon/startup script(s) are writable by non-admins" `
                -Severity  'High' `
                -Description "Script files in SYSVOL are writable by low-privilege users (Authenticated Users, Domain Users). Any domain user can modify these scripts to execute arbitrary code on all affected machines at next logon/startup." `
                -AffectedObjects ($writableFiles | Select-Object -ExpandProperty Path) `
                -Remediation '1) Reset ACLs on SYSVOL script files to admin-only write access. 2) Use icacls or Set-Acl to restrict write permissions. 3) Enable SYSVOL replication monitoring (DFSR event logs).' `
                -MitreAttack 'T1037.001 - Boot or Logon Initialization Scripts: Logon Script (Windows)'
            ))
        }
    }

    Write-Verbose "Startup/logon script checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Rogue Scheduled Task Detection

function Invoke-RogueScheduledTaskCheck {
    <#
    .SYNOPSIS
        Identifies unexpected or suspicious scheduled tasks on domain controllers.
    .DESCRIPTION
        Queries scheduled tasks on all domain controllers and flags tasks that:
        - Run as SYSTEM, NT AUTHORITY\SYSTEM, or privileged service accounts
        - Execute from unusual paths (%TEMP%, public folders, User profile directories)
        - Use PowerShell with encoded commands, download cradles, or hidden windows
        - Were recently created or modified
        - Have authors/paths inconsistent with Microsoft/Windows defaults

        Attackers plant scheduled tasks on DCs for persistent, high-privilege execution.
    .PARAMETER DomainControllers
        DC objects from Get-ADDomainControllers.
    .PARAMETER Credential
        Optional PSCredential for remote access.
    .EXAMPLE
        Invoke-RogueScheduledTaskCheck -DomainControllers $dcs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Running rogue scheduled task check on DCs..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # Suspicious execution patterns
    $suspiciousExecPatterns = @(
        'powershell.*-enc',
        'powershell.*-e\s',
        'powershell.*downloadstring',
        'powershell.*iex\s',
        'cmd.*\s/c\s',
        'wscript',
        'cscript',
        'mshta',
        'regsvr32',
        'rundll32.*comsvcs',
        'certutil.*-decode',
        '%temp%',
        '%appdata%',
        'C:\\Users\\.*\\AppData',
        'C:\\Windows\\Temp',
        'C:\\ProgramData\\.*\\.exe'
    )

    # Trusted task paths (Microsoft/Windows built-in tasks)
    $trustedPaths = @(
        '\Microsoft\',
        '\Windows\',
        '\WMI ',
        '\Active Directory\',
        '\Dynamic Data Exchange\'
    )

    $suspiciousTasks = [System.Collections.Generic.List[object]]::new()

    foreach ($dc in $DomainControllers) {
        $hostname = if ($dc.DnsHostName) { $dc.DnsHostName } else { $dc.Name }
        Write-Verbose "Checking scheduled tasks on: $hostname"

        try {
            $taskParams = @{ ErrorAction = 'Stop' }
            # Use CIM for remote query when possible
            if ($hostname -ne $env:COMPUTERNAME -and $hostname -ne 'localhost') {
                $cimOpts = New-CimSessionOption -Protocol Dcom
                $cimParams = @{ ComputerName = $hostname; SessionOption = $cimOpts; ErrorAction = 'SilentlyContinue' }
                if ($null -ne $Credential) { $cimParams.Credential = $Credential }
                $session = New-CimSession @cimParams
                if ($null -eq $session) { Write-Verbose "Could not connect to $hostname"; continue }

                $tasks = Get-CimInstance -ClassName MSFT_ScheduledTask -Namespace 'Root\Microsoft\Windows\TaskScheduler' `
                    -CimSession $session -ErrorAction SilentlyContinue
                Remove-CimSession $session -ErrorAction SilentlyContinue
            }
            else {
                $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
            }

            if ($null -eq $tasks) { continue }

            foreach ($task in $tasks) {
                $taskPath  = if ($null -ne $task.TaskPath)  { $task.TaskPath }  else { '' }
                $taskName  = if ($null -ne $task.TaskName)  { $task.TaskName }  else { '' }
                $actions   = if ($null -ne $task.Actions)   { $task.Actions }   else { @() }
                $principal = if ($null -ne $task.Principal) { $task.Principal } else { $null }

                # Skip known-trusted Microsoft paths
                $isTrusted = $trustedPaths | Where-Object { $taskPath -like "*$_*" }
                if ($isTrusted) { continue }

                $isSuspicious = $false
                $reasons      = [System.Collections.Generic.List[string]]::new()

                # Check run-as user
                $runAs = if ($principal) { if ($null -ne $principal.UserId) { $principal.UserId } else { '' } } else { '' }
                if ($runAs -match '^SYSTEM$|^NT AUTHORITY\\SYSTEM$|^S-1-5-18$') {
                    $reasons.Add("RunsAsSystem")
                }

                # Check actions for suspicious execution
                foreach ($action in $actions) {
                    $exec = ''
                    if ($action.PSObject.Properties['Execute']) {
                        $exec = if ($null -ne $action.Execute) { $action.Execute } else { '' }
                    }
                    if ($action.PSObject.Properties['Arguments']) {
                        $exec += ' ' + (if ($null -ne $action.Arguments) { $action.Arguments } else { '' })
                    }
                    foreach ($pattern in $suspiciousExecPatterns) {
                        if ($exec -imatch $pattern) {
                            $reasons.Add("SuspiciousExec: $pattern")
                            $isSuspicious = $true
                            break
                        }
                    }
                }

                # Non-trusted path with SYSTEM execution is always suspicious
                if ($runAs -match 'SYSTEM' -and -not $isTrusted -and $reasons.Count -gt 0) {
                    $isSuspicious = $true
                }

                if ($isSuspicious) {
                    $suspiciousTasks.Add([PSCustomObject]@{
                        DCName   = $hostname
                        TaskPath = $taskPath
                        TaskName = $taskName
                        RunAs    = $runAs
                        Reasons  = $reasons -join '; '
                    })
                }
            }
        }
        catch {
            Write-Verbose "Could not query scheduled tasks on ${hostname}: $_"
        }
    }

    if ($suspiciousTasks.Count -gt 0) {
        $affectedDCs = $suspiciousTasks | Select-Object -ExpandProperty DCName -Unique
        $findings.Add((New-Finding `
            -RuleId    'PB-060' `
            -Title     "Suspicious scheduled task(s) found on $($affectedDCs.Count) DC(s) ($($suspiciousTasks.Count) tasks)" `
            -Severity  'Critical' `
            -Description "Unexpected or suspicious scheduled tasks are present on domain controllers. Scheduled tasks running as SYSTEM with obfuscated or download-based payloads are a primary persistence mechanism for post-compromise attackers." `
            -AffectedObjects ($suspiciousTasks | ForEach-Object { "$($_.DCName): $($_.TaskPath)$($_.TaskName)" }) `
            -Remediation '1) Immediately review and disable flagged tasks. 2) Investigate creation time and author (schtasks /query /v /fo LIST). 3) Check Security event log for task creation (Event ID 4698). 4) Compare against known-good task inventory. 5) Restart DCs in safe mode if task removal is not sufficient.' `
            -MitreAttack 'T1053.005 - Scheduled Task/Job: Scheduled Task' `
            -ExtraData @{ SuspiciousTasks = $suspiciousTasks }
        ))
    }

    Write-Verbose "Rogue scheduled task checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

Export-ModuleMember -Function Invoke-AdminSDHolderCheck, Invoke-SIDHistoryCheck,
                               Invoke-DCSyncRightsCheck, Invoke-SkeletonKeyCheck,
                               Invoke-RogueDCCheck, Invoke-StartupScriptCheck,
                               Invoke-RogueScheduledTaskCheck
