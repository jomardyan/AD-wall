#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Identity & Privilege Analysis Module
.DESCRIPTION
    Performs security checks on Active Directory identity and privilege configuration.
    Checks privileged group membership, password policies, stale accounts, delegation,
    and Kerberoastable accounts. All findings include severity, description, affected
    objects, and remediation guidance.
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
        [string]$Category     = 'Identity & Privilege',
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

#region Privileged Group Checks

function Invoke-PrivilegedGroupCheck {
    <#
    .SYNOPSIS
        Enumerates membership in sensitive privileged groups.
    .DESCRIPTION
        Checks membership of: Domain Admins, Enterprise Admins, Schema Admins,
        Backup Operators, Account Operators, Print Operators, Server Operators,
        Group Policy Creator Owners, and BUILTIN\Administrators.
        Flags excessive membership, service accounts, and non-standard accounts.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Groups
        Group objects from Get-ADGroups.
    .EXAMPLE
        Invoke-PrivilegedGroupCheck -Users $adUsers -Groups $adGroups
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        [Parameter(Mandatory = $true)]
        [object[]]$Groups
    )

    Write-Verbose "Running privileged group checks..."

    $findings  = [System.Collections.Generic.List[object]]::new()
    $privGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Backup Operators',
        'Account Operators',
        'Print Operators',
        'Server Operators',
        'Group Policy Creator Owners',
        'Administrators',
        'DNSAdmins'
    )

    # Build group-to-member lookup
    $groupMap = @{}
    foreach ($grp in $Groups) {
        $gName = $grp.SamAccountName
        if ($gName -in $privGroups) {
            $groupMap[$gName] = $grp
        }
    }

    # Build user SAM -> user object lookup
    $userMap = @{}
    foreach ($u in $Users) { $userMap[$u.DistinguishedName] = $u }

    foreach ($privGroup in $privGroups) {
        if (-not $groupMap.ContainsKey($privGroup)) { continue }

        $grp     = $groupMap[$privGroup]
        $members = @($grp.Members | Where-Object { $_ })
        $resolvedMembers = $members | ForEach-Object {
            if ($userMap.ContainsKey($_)) { $userMap[$_].SamAccountName } else { $_ }
        }

        # Flag if more than expected thresholds
        $threshold = switch ($privGroup) {
            'Domain Admins'     { 5 }
            'Enterprise Admins' { 3 }
            'Schema Admins'     { 2 }
            default             { 10 }
        }

        $severity = switch ($privGroup) {
            'Domain Admins'     { 'High' }
            'Enterprise Admins' { 'Critical' }
            'Schema Admins'     { 'Critical' }
            'Backup Operators'  { 'High' }
            'DNSAdmins'         { 'High' }
            default             { 'Medium' }
        }

        if ($members.Count -gt $threshold) {
            $findings.Add((New-Finding `
                -RuleId    'IP-001' `
                -Title     "Excessive membership in '$privGroup' ($($members.Count) members)" `
                -Severity  $severity `
                -Description "The '$privGroup' group has $($members.Count) members, exceeding the expected threshold of $threshold. Excessive privilege group membership increases the attack surface." `
                -AffectedObjects $resolvedMembers `
                -Remediation "Review and reduce '$privGroup' membership. Implement the principle of least privilege. Use tiered administration and Privileged Access Workstations (PAWs)." `
                -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts' `
            ))
        }

        # Flag service accounts in DA/EA
        if ($privGroup -in @('Domain Admins','Enterprise Admins')) {
            $svcAccounts = $members | Where-Object {
                $u = $userMap[$_]
                $null -ne $u -and (
                    $u.SamAccountName -match '^svc|^sa_|^service|_svc$|_sa$' -or
                    $u.ServicePrincipalNames.Count -gt 0
                )
            }
            if ($svcAccounts.Count -gt 0) {
                $svcNames = $svcAccounts | ForEach-Object {
                    if ($userMap.ContainsKey($_)) { $userMap[$_].SamAccountName } else { $_ }
                }
                $findings.Add((New-Finding `
                    -RuleId    'IP-002' `
                    -Title     "Service account(s) in '$privGroup'" `
                    -Severity  'Critical' `
                    -Description "Service accounts with SPNs or service-naming conventions are members of '$privGroup'. Service accounts in highly privileged groups are prime targets for Kerberoasting and credential theft." `
                    -AffectedObjects $svcNames `
                    -Remediation "Remove service accounts from '$privGroup'. Use Managed Service Accounts (MSAs) or Group MSAs (gMSAs) with minimal permissions." `
                    -MitreAttack 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting' `
                ))
            }
        }
    }

    # Schema Admins: should be empty except during schema modifications
    if ($groupMap.ContainsKey('Schema Admins')) {
        $sa = $groupMap['Schema Admins']
        # Filter out the default krbtgt/Administrator
        $nonDefault = @($sa.Members | Where-Object { $_ -and $_ -notlike '*krbtgt*' -and $_ -notlike '*Administrator*' })
        if ($nonDefault.Count -gt 0) {
            $findings.Add((New-Finding `
                -RuleId    'IP-003' `
                -Title     'Schema Admins group is not empty' `
                -Severity  'Critical' `
                -Description "The Schema Admins group contains $($nonDefault.Count) member(s). This group should be empty except during schema extension operations." `
                -AffectedObjects ($nonDefault | ForEach-Object { if ($userMap.ContainsKey($_)) { $userMap[$_].SamAccountName } else { $_ } }) `
                -Remediation 'Remove all accounts from Schema Admins except during planned schema modifications. Re-add members only for the duration of the change.' `
                -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts' `
            ))
        }
    }

    Write-Verbose "Privileged group checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Password Policy Checks

function Invoke-PasswordPolicyCheck {
    <#
    .SYNOPSIS
        Checks for password policy weaknesses and vulnerable account configurations.
    .DESCRIPTION
        Identifies: PasswordNeverExpires, PasswordNotRequired, AS-REP Roastable accounts
        (DontRequirePreAuth), reversible encryption, and weak domain password policies.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER PasswordPolicies
        Password policy objects from Get-ADPasswordPolicies.
    .EXAMPLE
        Invoke-PasswordPolicyCheck -Users $adUsers -PasswordPolicies $policies
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        [Parameter(Mandatory = $false)]
        [object[]]$PasswordPolicies = @()
    )

    Write-Verbose "Running password policy checks..."

    $findings = [System.Collections.Generic.List[object]]::new()

    # --- Domain password policy ---
    foreach ($policy in $PasswordPolicies) {
        if ($policy.MinPasswordLength -lt 12) {
            $findings.Add((New-Finding `
                -RuleId    'IP-010' `
                -Title     "Weak minimum password length: $($policy.MinPasswordLength) characters" `
                -Severity  'High' `
                -Description "The domain password policy requires a minimum of only $($policy.MinPasswordLength) characters. NIST SP 800-63B recommends at least 12 characters." `
                -AffectedObjects @($policy.DistinguishedName) `
                -Remediation 'Set the minimum password length to at least 12 characters (preferably 14+) in the Default Domain Policy or via Fine-Grained Password Policy.' `
                -MitreAttack 'T1110 - Brute Force' `
            ))
        }

        if (-not $policy.ComplexityEnabled) {
            $findings.Add((New-Finding `
                -RuleId    'IP-011' `
                -Title     'Password complexity requirements disabled' `
                -Severity  'High' `
                -Description 'The domain password policy does not enforce complexity requirements, making passwords more susceptible to brute-force attacks.' `
                -AffectedObjects @($policy.DistinguishedName) `
                -Remediation 'Enable password complexity requirements in the Default Domain Policy.' `
                -MitreAttack 'T1110 - Brute Force' `
            ))
        }

        if ($policy.LockoutThreshold -eq 0) {
            $findings.Add((New-Finding `
                -RuleId    'IP-012' `
                -Title     'Account lockout not configured' `
                -Severity  'High' `
                -Description 'No account lockout threshold is set. This allows unlimited password guessing attempts without lockout.' `
                -AffectedObjects @($policy.DistinguishedName) `
                -Remediation 'Configure an account lockout threshold (recommended: 5-10 attempts) and appropriate lockout duration in the Default Domain Policy.' `
                -MitreAttack 'T1110.001 - Password Guessing' `
            ))
        }

        if ($policy.ReversibleEncryption) {
            $findings.Add((New-Finding `
                -RuleId    'IP-013' `
                -Title     'Password stored with reversible encryption' `
                -Severity  'Critical' `
                -Description 'The domain password policy enables reversible encryption, which is essentially the same as storing passwords in plaintext.' `
                -AffectedObjects @($policy.DistinguishedName) `
                -Remediation 'Disable reversible encryption. This may require users to reset their passwords.' `
                -MitreAttack 'T1003.002 - OS Credential Dumping: Security Account Manager' `
            ))
        }

        if ($policy.MaxPasswordAgeDays -eq 0) {
            $findings.Add((New-Finding `
                -RuleId    'IP-014' `
                -Title     'Passwords never expire (domain policy)' `
                -Severity  'Medium' `
                -Description 'The domain password policy has no maximum password age, meaning passwords never expire by default.' `
                -AffectedObjects @($policy.DistinguishedName) `
                -Remediation 'Set a maximum password age (recommended: 90 days or use a long passphrase policy with no expiry per NIST 800-63B).' `
                -MitreAttack 'T1078 - Valid Accounts' `
            ))
        }
    }

    # --- Per-account checks ---
    $pwdNeverExpires = @($Users | Where-Object { $_.PasswordNeverExpires -and $_.Enabled })
    $pwdNotRequired  = @($Users | Where-Object { $_.PasswordNotRequired -and $_.Enabled })
    $asrepRoastable  = @($Users | Where-Object { $_.DontRequirePreAuth -and $_.Enabled })

    if ($pwdNeverExpires.Count -gt 0) {
        $affected = $pwdNeverExpires | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-015' `
            -Title     "$($pwdNeverExpires.Count) enabled account(s) with PasswordNeverExpires" `
            -Severity  'Medium' `
            -Description "These accounts have PasswordNeverExpires set. Stale credentials increase the window of opportunity for attackers using compromised credentials." `
            -AffectedObjects $affected `
            -Remediation 'Review and remove PasswordNeverExpires from non-service accounts. For service accounts, migrate to gMSAs which auto-rotate passwords.' `
            -MitreAttack 'T1078 - Valid Accounts' `
        ))
    }

    if ($pwdNotRequired.Count -gt 0) {
        $affected = $pwdNotRequired | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-016' `
            -Title     "$($pwdNotRequired.Count) account(s) with PasswordNotRequired flag set" `
            -Severity  'High' `
            -Description "These accounts have PASSWD_NOTREQD (UF_PASSWD_NOTREQD) set, meaning they may have empty or no passwords." `
            -AffectedObjects $affected `
            -Remediation 'Clear the PasswordNotRequired flag and ensure all accounts have strong passwords. Verify each account requires authentication.' `
            -MitreAttack 'T1110.001 - Brute Force: Password Guessing' `
        ))
    }

    if ($asrepRoastable.Count -gt 0) {
        $affected = $asrepRoastable | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-017' `
            -Title     "$($asrepRoastable.Count) account(s) vulnerable to AS-REP Roasting" `
            -Severity  'High' `
            -Description "These accounts have 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) set. An attacker can request AS-REP responses and crack them offline without domain credentials." `
            -AffectedObjects $affected `
            -Remediation 'Enable Kerberos pre-authentication for all accounts unless absolutely required. If needed, ensure accounts have strong passwords (20+ chars).' `
            -MitreAttack 'T1558.004 - AS-REP Roasting' `
        ))
    }

    Write-Verbose "Password policy checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Stale Account Checks

function Invoke-StaleAccountCheck {
    <#
    .SYNOPSIS
        Identifies stale user and computer accounts.
    .DESCRIPTION
        Finds enabled accounts that have not logged in for more than the configured
        threshold (default 90 days). Stale accounts that remain enabled can be
        compromised without detection.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Computers
        Computer objects from Get-ADComputers.
    .PARAMETER ThresholdDays
        Number of days of inactivity before an account is flagged. Default: 90.
    .EXAMPLE
        Invoke-StaleAccountCheck -Users $adUsers -Computers $adComputers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        [Parameter(Mandatory = $false)]
        [object[]]$Computers = @(),
        [int]$ThresholdDays = 90
    )

    Write-Verbose "Running stale account checks (threshold: $ThresholdDays days)..."

    $findings  = [System.Collections.Generic.List[object]]::new()
    $threshold = (Get-Date).AddDays(-$ThresholdDays)

    # Stale user accounts
    $staleUsers = @($Users | Where-Object {
        $_.Enabled -and
        ($null -eq $_.LastLogonTimestamp -or $_.LastLogonTimestamp -lt $threshold)
    })

    if ($staleUsers.Count -gt 0) {
        $affected = $staleUsers | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-020' `
            -Title     "$($staleUsers.Count) stale enabled user account(s) (> $ThresholdDays days inactive)" `
            -Severity  'Medium' `
            -Description "These enabled user accounts have not logged on in over $ThresholdDays days. Stale accounts that remain active are prime targets for attackers as their compromise may go unnoticed." `
            -AffectedObjects $affected `
            -Remediation "Implement an account lifecycle management process. Disable accounts inactive for $ThresholdDays days and delete after a further 90 days. Use Active Directory access-based enumeration." `
            -MitreAttack 'T1078 - Valid Accounts' `
        ))
    }

    # Privileged stale accounts (AdminCount=1) are more critical
    $stalePrivUsers = @($staleUsers | Where-Object { $_.AdminCount -eq 1 })
    if ($stalePrivUsers.Count -gt 0) {
        $affected = $stalePrivUsers | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-021' `
            -Title     "$($stalePrivUsers.Count) stale PRIVILEGED account(s) (AdminCount=1, > $ThresholdDays days)" `
            -Severity  'Critical' `
            -Description "Stale privileged accounts (AdminCount=1) are extremely dangerous as they retain administrative permissions while being unmonitored." `
            -AffectedObjects $affected `
            -Remediation "Immediately disable or delete these stale privileged accounts. Review why these accounts accumulated AdminCount=1 status." `
            -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts' `
        ))
    }

    # Stale computer accounts
    $staleComputers = @($Computers | Where-Object {
        $_.Enabled -and
        ($null -eq $_.LastLogonTimestamp -or $_.LastLogonTimestamp -lt $threshold)
    })

    if ($staleComputers.Count -gt 0) {
        $affected = $staleComputers | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-022' `
            -Title     "$($staleComputers.Count) stale enabled computer account(s) (> $ThresholdDays days)" `
            -Severity  'Low' `
            -Description "These computer accounts have not authenticated in over $ThresholdDays days but remain enabled. Orphaned machine accounts can be leveraged by attackers." `
            -AffectedObjects $affected `
            -Remediation "Disable and eventually delete stale computer accounts. Maintain an asset management process aligned with AD accounts." `
            -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts' `
        ))
    }

    Write-Verbose "Stale account checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Delegation Checks

function Invoke-DelegationCheck {
    <#
    .SYNOPSIS
        Identifies dangerous Kerberos delegation configurations.
    .DESCRIPTION
        Checks for:
        - Unconstrained delegation (TrustedForDelegation) on non-DC accounts
        - Constrained delegation to sensitive services (krbtgt, DCs)
        - Resource-Based Constrained Delegation (RBCD) misconfigurations
    .PARAMETER Users
        User objects.
    .PARAMETER Computers
        Computer objects.
    .PARAMETER DomainControllers
        Domain controller objects.
    .EXAMPLE
        Invoke-DelegationCheck -Users $adUsers -Computers $adComputers -DomainControllers $dcs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        [Parameter(Mandatory = $false)]
        [object[]]$Computers = @(),
        [Parameter(Mandatory = $false)]
        [object[]]$DomainControllers = @()
    )

    Write-Verbose "Running delegation checks..."

    $findings = [System.Collections.Generic.List[object]]::new()
    $dcNames  = @($DomainControllers | Select-Object -ExpandProperty SamAccountName | ForEach-Object { $_ -replace '\$$','' })

    # --- Unconstrained delegation ---
    $unconstrainedUsers = @($Users | Where-Object {
        $_.TrustedForDelegation -and
        $_.Enabled -and
        $_.SamAccountName -notin @('krbtgt')
    })
    $unconstrainedComps = @($Computers | Where-Object {
        $_.TrustedForDelegation -and
        $_.Enabled -and
        ($_.SamAccountName -replace '\$$','') -notin $dcNames
    })

    if ($unconstrainedUsers.Count -gt 0) {
        $affected = $unconstrainedUsers | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-030' `
            -Title     "$($unconstrainedUsers.Count) user account(s) with Unconstrained Delegation" `
            -Severity  'Critical' `
            -Description "These user accounts have TrustedForDelegation set (unconstrained delegation). Any service running as these accounts can impersonate any user in the domain, enabling privilege escalation and lateral movement." `
            -AffectedObjects $affected `
            -Remediation 'Remove unconstrained delegation from these accounts. Migrate to constrained or Resource-Based Constrained Delegation (RBCD). Ensure the account runs minimal services.' `
            -MitreAttack 'T1558 - Steal or Forge Kerberos Tickets' `
        ))
    }

    if ($unconstrainedComps.Count -gt 0) {
        $affected = $unconstrainedComps | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-031' `
            -Title     "$($unconstrainedComps.Count) non-DC computer(s) with Unconstrained Delegation" `
            -Severity  'High' `
            -Description "These non-domain controller computer accounts have unconstrained delegation. An attacker who compromises these machines can use the Printer Bug or other coercion techniques to capture privileged TGTs." `
            -AffectedObjects $affected `
            -Remediation 'Remove unconstrained delegation from non-DC computers. Use Constrained Delegation or RBCD instead.' `
            -MitreAttack 'T1558.001 - Golden Ticket / T1187 - Forced Authentication' `
        ))
    }

    # --- Constrained delegation to sensitive SPNs ---
    $sensitiveSpns = @('krbtgt','ldap','cifs','host')
    $constrained = @($Users + $Computers | Where-Object {
        $_.TrustedToAuthForDelegate -and $_.Enabled -and
        ($_.AllowedToDelegateTo | Where-Object { $spn = $_; $sensitiveSpns | Where-Object { $spn -like "*$_*" } }).Count -gt 0
    })

    if ($constrained.Count -gt 0) {
        $affected = $constrained | ForEach-Object { $_.SamAccountName }
        $findings.Add((New-Finding `
            -RuleId    'IP-032' `
            -Title     "$($constrained.Count) account(s) with constrained delegation to sensitive services" `
            -Severity  'High' `
            -Description "These accounts are configured for Protocol Transition (TrustedToAuthForDelegate) with delegation to sensitive service classes (LDAP, CIFS, HOST, krbtgt). This may allow impersonation of privileged accounts." `
            -AffectedObjects $affected `
            -Remediation "Review constrained delegation targets. Avoid delegating to LDAP or krbtgt SPNs. Use RBCD where possible and add protected users to the 'Protected Users' security group." `
            -MitreAttack 'T1558 - Steal or Forge Kerberos Tickets' `
        ))
    }

    Write-Verbose "Delegation checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Kerberoastable Accounts

function Invoke-KerberoastableCheck {
    <#
    .SYNOPSIS
        Finds user accounts with SPNs set (Kerberoastable).
    .DESCRIPTION
        Identifies user accounts (not computers) with Service Principal Names. These
        accounts can be targeted for offline hash cracking via the Kerberoasting attack.
        Prioritises accounts by privilege level and password age.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .EXAMPLE
        Invoke-KerberoastableCheck -Users $adUsers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )

    Write-Verbose "Running Kerberoastable account checks..."

    $findings = [System.Collections.Generic.List[object]]::new()

    $kerberoastable = @($Users | Where-Object {
        $_.Enabled -and
        $_.ServicePrincipalNames.Count -gt 0
    })

    if ($kerberoastable.Count -eq 0) {
        Write-Verbose "No Kerberoastable accounts found."
        return @()
    }

    $privileged = @($kerberoastable | Where-Object { $_.AdminCount -eq 1 })

    $findings.Add((New-Finding `
        -RuleId    'IP-040' `
        -Title     "$($kerberoastable.Count) user account(s) are Kerberoastable (have SPNs)" `
        -Severity  $(if ($privileged.Count -gt 0) { 'Critical' } else { 'High' }) `
        -Description "These user accounts have Service Principal Names (SPNs) set. Any domain user can request their Kerberos service tickets (TGS-REP) and crack the password hash offline. $($privileged.Count) of these are privileged (AdminCount=1)." `
        -AffectedObjects ($kerberoastable | Select-Object -ExpandProperty SamAccountName) `
        -Remediation "Review and remove unnecessary SPNs from user accounts. Use Group Managed Service Accounts (gMSAs) for services — they auto-rotate their 120-char passwords. For required SPNs, ensure passwords are at least 25 characters." `
        -MitreAttack 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting' `
        -ExtraData @{
            PrivilegedKerberoastable = ($privileged | Select-Object SamAccountName, ServicePrincipalNames, AdminCount)
            AllKerberoastable        = ($kerberoastable | Select-Object SamAccountName, ServicePrincipalNames, PasswordLastSet, AdminCount)
        }
    ))

    if ($privileged.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId    'IP-041' `
            -Title     "$($privileged.Count) PRIVILEGED Kerberoastable account(s) (AdminCount=1)" `
            -Severity  'Critical' `
            -Description "Privileged accounts (AdminCount=1) with SPNs are the highest-risk Kerberoasting targets. Cracking these hashes yields domain admin credentials." `
            -AffectedObjects ($privileged | Select-Object -ExpandProperty SamAccountName) `
            -Remediation "Immediately remove SPNs from privileged accounts, or move those services to gMSAs. This is the single highest-priority remediation." `
            -MitreAttack 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting' `
        ))
    }

    Write-Verbose "Kerberoastable checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion


#region Nested Privileged Group Check

function Invoke-NestedPrivilegedGroupCheck {
    <#
    .SYNOPSIS
        Detects Tier 0 privilege gained through nested group membership chains.
    .DESCRIPTION
        Recursively resolves group membership for all privileged groups to expose
        accounts that inherit Domain Admin or Tier 0 rights via deeply nested groups
        that would not be visible in a flat membership scan.
        Flags non-obvious accounts (those not directly in a privileged group but
        reachable via nesting) to surface privilege sprawl hidden inside group chains.
    .PARAMETER Groups
        Group objects from Get-ADGroups.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .EXAMPLE
        Invoke-NestedPrivilegedGroupCheck -Groups $adGroups -Users $adUsers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Groups,
        [Parameter(Mandatory = $true)]
        [object[]]$Users
    )

    Write-Verbose "Running nested privileged group check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    $tier0Groups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators')

    # Build indexed lookups
    $groupByDN   = @{}
    $groupByName = @{}
    foreach ($g in $Groups) {
        if ($g.DistinguishedName) { $groupByDN[$g.DistinguishedName] = $g }
        if ($g.SamAccountName)   { $groupByName[$g.SamAccountName]  = $g }
    }
    $userByDN = @{}
    foreach ($u in $Users) {
        if ($u.DistinguishedName) { $userByDN[$u.DistinguishedName] = $u }
    }

    # Recursive resolver — returns all user DNs reachable from a group DN
    $resolveCache = @{}
    function Resolve-GroupMembers {
        param([string]$GroupDN, [int]$Depth = 0)
        if ($Depth -gt 10) { return @() }
        if ($resolveCache.ContainsKey($GroupDN)) { return $resolveCache[$GroupDN] }
        $resolveCache[$GroupDN] = @()   # break cycles

        if (-not $groupByDN.ContainsKey($GroupDN)) { return @() }
        $grp = $groupByDN[$GroupDN]
        $directMembers  = @($grp.Members | Where-Object { $_ })
        $allUserDNs     = [System.Collections.Generic.List[string]]::new()

        foreach ($memberDN in $directMembers) {
            if ($userByDN.ContainsKey($memberDN)) {
                $allUserDNs.Add($memberDN)
            }
            elseif ($groupByDN.ContainsKey($memberDN)) {
                foreach ($nestedUserDN in (Resolve-GroupMembers -GroupDN $memberDN -Depth ($Depth+1))) {
                    $allUserDNs.Add($nestedUserDN)
                }
            }
        }
        $result = $allUserDNs.ToArray() | Sort-Object -Unique
        $resolveCache[$GroupDN] = $result
        return $result
    }

    foreach ($privGroupName in $tier0Groups) {
        if (-not $groupByName.ContainsKey($privGroupName)) { continue }

        $grp        = $groupByName[$privGroupName]
        $directDNs  = @($grp.Members | Where-Object { $_ } | Where-Object { $userByDN.ContainsKey($_) })
        $allUserDNs = Resolve-GroupMembers -GroupDN $grp.DistinguishedName

        # Nested members = all - direct
        $nestedDNs  = @($allUserDNs | Where-Object { $_ -notin $directDNs })

        if ($nestedDNs.Count -gt 0) {
            $nestedAccounts = $nestedDNs | ForEach-Object {
                if ($userByDN.ContainsKey($_)) { $userByDN[$_].SamAccountName } else { $_ }
            }
            $findings.Add((New-Finding `
                -RuleId    'IP-050' `
                -Title     "$($nestedDNs.Count) account(s) reach '$privGroupName' via nested group chains" `
                -Severity  'High' `
                -Description "These accounts are NOT direct members of '$privGroupName' but inherit Tier 0 privileges through nested group membership. Nested privilege is often overlooked during access reviews, creating hidden attack paths to Domain Admin." `
                -AffectedObjects $nestedAccounts `
                -Remediation "Review the group nesting chain to '$privGroupName'. Remove unnecessary nested groups and flatten privilege assignment. Use tooling like BloodHound to visualise all paths." `
                -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts'
            ))
        }
    }

    Write-Verbose "Nested privileged group checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Weak Kerberos Encryption Type Check

function Invoke-WeakEncryptionTypeCheck {
    <#
    .SYNOPSIS
        Identifies accounts configured with only weak Kerberos encryption types.
    .DESCRIPTION
        Checks the msDS-SupportedEncryptionTypes attribute on user and computer
        accounts to identify objects that support only DES or RC4 encryption.

        DES (0x1, 0x2) is completely broken.
        RC4 (0x4) is vulnerable to offline cracking (Kerberoasting/AS-REP roasting).
        AES128 (0x8) and AES256 (0x10) should be the minimum.

        Accounts with UseDESKeyOnly flag are especially dangerous.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Computers
        Computer objects from Get-ADComputers.
    .EXAMPLE
        Invoke-WeakEncryptionTypeCheck -Users $adUsers -Computers $adComputers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,
        [Parameter(Mandatory = $false)]
        [object[]]$Computers = @()
    )

    Write-Verbose "Running weak Kerberos encryption type check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # Bit flags from msDS-SupportedEncryptionTypes
    $DES_CRC  = 0x01
    $DES_MD5  = 0x02
    $RC4      = 0x04
    $AES128   = 0x08
    $AES256   = 0x10

    # UseDESKeyOnly = UAC bit 0x200000
    $UAC_DES_ONLY = 0x200000

    # Accounts with UseDESKeyOnly set in UserAccountControl
    $desOnlyUsers = @($Users | Where-Object {
        $_.Enabled -and $_.UserAccountControl -band $UAC_DES_ONLY
    })

    if ($desOnlyUsers.Count -gt 0) {
        $affected = $desOnlyUsers | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-060' `
            -Title     "$($desOnlyUsers.Count) account(s) have 'Use DES encryption only' (UseDESKeyOnly)" `
            -Severity  'Critical' `
            -Description "The UseDESKeyOnly UAC flag forces these accounts to use only DES for Kerberos, which was broken in 2008. This allows trivial offline cracking of any captured Kerberos tickets." `
            -AffectedObjects $affected `
            -Remediation 'Clear the UseDESKeyOnly flag on all accounts: Set-ADUser -Identity <user> -KerberosEncryptionType AES256,AES128. DES should be globally disabled via GPO.' `
            -MitreAttack 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
        ))
    }

    # Accounts supporting ONLY DES/RC4 (no AES) via msDS-SupportedEncryptionTypes
    $noAesUsers = @($Users | Where-Object {
        $_.Enabled -and
        $null -ne $_.SupportedEncryptionTypes -and
        $_.SupportedEncryptionTypes -gt 0 -and
        -not ($_.SupportedEncryptionTypes -band ($AES128 -bor $AES256))
    })

    if ($noAesUsers.Count -gt 0) {
        $affected = $noAesUsers | Select-Object -ExpandProperty SamAccountName
        $severity = if ($noAesUsers | Where-Object { $_.AdminCount -eq 1 }) { 'High' } else { 'Medium' }
        $findings.Add((New-Finding `
            -RuleId    'IP-061' `
            -Title     "$($noAesUsers.Count) user account(s) do not support AES Kerberos encryption" `
            -Severity  $severity `
            -Description "These user accounts have msDS-SupportedEncryptionTypes set to only DES or RC4, with no AES support. Kerberos tickets for these accounts use weak ciphers that are easier to crack offline." `
            -AffectedObjects $affected `
            -Remediation 'Update msDS-SupportedEncryptionTypes to include AES256 (0x10) and AES128 (0x8). Apply GPO "Network security: Configure encryption types allowed for Kerberos" to require AES.' `
            -MitreAttack 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
        ))
    }

    # Computer accounts supporting only DES/RC4
    $noAesComps = @($Computers | Where-Object {
        $_.Enabled -and
        $null -ne $_.SupportedEncryptionTypes -and
        $_.SupportedEncryptionTypes -gt 0 -and
        -not ($_.SupportedEncryptionTypes -band ($AES128 -bor $AES256))
    })

    if ($noAesComps.Count -gt 0) {
        $affected = $noAesComps | Select-Object -ExpandProperty SamAccountName
        $findings.Add((New-Finding `
            -RuleId    'IP-062' `
            -Title     "$($noAesComps.Count) computer account(s) do not support AES Kerberos encryption" `
            -Severity  'Medium' `
            -Description "These computer accounts lack AES Kerberos encryption support. Legacy systems forced to RC4 are vulnerable to offline hash cracking of machine account tickets." `
            -AffectedObjects $affected `
            -Remediation 'Upgrade OS on legacy computers where possible. Set "Network security: Configure encryption types allowed for Kerberos" GPO to AES256/AES128 only.' `
            -MitreAttack 'T1558 - Steal or Forge Kerberos Tickets'
        ))
    }

    Write-Verbose "Weak encryption type checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

Export-ModuleMember -Function Invoke-PrivilegedGroupCheck, Invoke-PasswordPolicyCheck,
                               Invoke-StaleAccountCheck, Invoke-DelegationCheck,
                               Invoke-KerberoastableCheck, Invoke-NestedPrivilegedGroupCheck,
                               Invoke-WeakEncryptionTypeCheck
