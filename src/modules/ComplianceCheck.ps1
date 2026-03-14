#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Compliance Check Module
.DESCRIPTION
    Audits the Active Directory environment against major industry security
    benchmarks and controls frameworks:
    - CIS Microsoft Active Directory Security Benchmark
    - Microsoft Security Baseline for AD
    - NIST SP 800-53 Rev5 (AC, IA, CM, AU control families)
    - DISA STIG for Active Directory

    Each check produces a finding with CIS control ID, severity, MITRE ATT&CK
    mapping, and rollback-safe remediation steps.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

# New-Finding is defined in src/core/FindingHelper.ps1 and dot-sourced before this module.

#region CIS AD Benchmark Checks

function Invoke-CISBenchmarkCheck {
    <#
    .SYNOPSIS
        Checks AD configuration against the CIS Microsoft AD Security Benchmark.
    .DESCRIPTION
        Evaluates password policy, account hygiene, privileged access controls,
        trust configuration, and audit settings against CIS Level 1 and Level 2
        Active Directory controls. Returns findings for deviations.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Groups
        Group objects from Get-ADGroups.
    .PARAMETER PasswordPolicies
        Password policy objects from Get-ADPasswordPolicies.
    .PARAMETER DomainControllers
        DC objects from Get-ADDomainControllers.
    .PARAMETER Trusts
        Trust objects from Get-ADTrusts.
    .PARAMETER NtlmData
        NTLM settings from Get-NTLMSettings.
    .EXAMPLE
        Invoke-CISBenchmarkCheck -Users $users -Groups $groups -PasswordPolicies $pols
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)] [object[]]$Users             = @(),
        [Parameter(Mandatory = $false)] [object[]]$Groups            = @(),
        [Parameter(Mandatory = $false)] [object[]]$PasswordPolicies  = @(),
        [Parameter(Mandatory = $false)] [object[]]$DomainControllers = @(),
        [Parameter(Mandatory = $false)] [object[]]$Trusts            = @(),
        [Parameter(Mandatory = $false)] [object[]]$NtlmData          = @()
    )

    Write-Verbose "Running CIS AD Benchmark checks..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # -------------------------------------------------------------------------
    # CIS 1.1.x — Password Policy (CIS Level 1)
    # -------------------------------------------------------------------------
    $domainPolicy = $PasswordPolicies | Where-Object { $_.PSObject.Properties.Name -contains 'MinPasswordLength' -or $_.Name -eq 'Default Domain Policy' } | Select-Object -First 1
    if ($null -ne $domainPolicy) {
        # CIS 1.1.1 — Minimum password length >= 14
        $minLen = [int]($domainPolicy.MinPasswordLength)
        if ($minLen -lt 14) {
            $findings.Add((New-Finding `
                -RuleId     'COMP-001' `
                -Title      "Domain password policy: minimum length $minLen (CIS requires ≥ 14)" `
                -Severity   'High' `
                -CISControl 'CIS-AD-1.1.1' `
                -NISTControl 'IA-5(1)' `
                -Description "The Default Domain Password Policy requires only $minLen characters. CIS Microsoft AD Security Benchmark 1.1.1 requires a minimum password length of 14 characters or more. Short passwords are highly susceptible to offline cracking attacks." `
                -AffectedObjects @("Domain password policy (MinPasswordLength=$minLen)") `
                -Remediation 'Set minimum password length to 14+ characters: Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14. Consider passphrase policies (25+ chars) for privileged accounts.' `
                -MitreAttack 'T1110 - Brute Force'
            ))
        }

        # CIS 1.1.2 — Complexity enabled
        $complexity = $domainPolicy.PasswordComplexityEnabled
        if ($complexity -ne $true) {
            $findings.Add((New-Finding `
                -RuleId     'COMP-002' `
                -Title      'Domain password policy: complexity not enabled (CIS 1.1.2)' `
                -Severity   'High' `
                -CISControl 'CIS-AD-1.1.2' `
                -NISTControl 'IA-5(1)' `
                -Description 'Password complexity is not enforced in the Default Domain Password Policy. CIS 1.1.2 requires complexity to be enabled. Without complexity requirements, users can set easily guessable passwords.' `
                -AffectedObjects @('Domain password policy') `
                -Remediation 'Enable complexity: Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true.' `
                -MitreAttack 'T1110 - Brute Force'
            ))
        }

        # CIS 1.1.3 — Lockout threshold <= 10 (0 = never)
        $lockout = [int]($domainPolicy.LockoutThreshold)
        if ($lockout -eq 0 -or $lockout -gt 10) {
            $lockoutStr = if ($lockout -eq 0) { 'disabled (0)' } else { $lockout.ToString() }
            $findings.Add((New-Finding `
                -RuleId     'COMP-003' `
                -Title      "Account lockout threshold is $lockoutStr (CIS 1.1.3 requires ≤ 10)" `
                -Severity   'Medium' `
                -CISControl 'CIS-AD-1.1.3' `
                -NISTControl 'AC-7' `
                -Description "CIS 1.1.3 requires an account lockout threshold of 10 or fewer failed attempts. A value of 0 (disabled) allows unlimited brute-force attempts. High values offer insufficient protection." `
                -AffectedObjects @("Domain policy (LockoutThreshold=$lockoutStr)") `
                -Remediation 'Set: Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00' `
                -MitreAttack 'T1110.001 - Brute Force: Password Guessing'
            ))
        }

        # CIS 1.1.4 — Password history >= 24
        $history = [int]($domainPolicy.PasswordHistoryCount)
        if ($history -lt 24) {
            $findings.Add((New-Finding `
                -RuleId     'COMP-004' `
                -Title      "Password history count $history (CIS 1.1.4 requires ≥ 24)" `
                -Severity   'Low' `
                -CISControl 'CIS-AD-1.1.4' `
                -NISTControl 'IA-5(1)' `
                -Description "CIS 1.1.4 recommends retaining password history of 24 or more. Insufficient history allows users to recycle recently-used passwords." `
                -AffectedObjects @("Domain policy (PasswordHistoryCount=$history)") `
                -Remediation 'Set: Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24' `
                -MitreAttack 'T1078 - Valid Accounts'
            ))
        }

        # CIS 1.1.5 — Maximum password age <= 365 days
        $maxAge = $null
        if ($domainPolicy.MaxPasswordAge) {
            $maxAge = [int]([timespan]::Parse($domainPolicy.MaxPasswordAge).TotalDays)
        }
        if ($null -ne $maxAge -and $maxAge -gt 365) {
            $findings.Add((New-Finding `
                -RuleId     'COMP-005' `
                -Title      "Maximum password age is $maxAge days (CIS 1.1.5 requires ≤ 365)" `
                -Severity   'Low' `
                -CISControl 'CIS-AD-1.1.5' `
                -NISTControl 'IA-5' `
                -Description "CIS 1.1.5 recommends a maximum password age of 365 days or less. Excessively long password ages increase the window of exposure for compromised credentials." `
                -AffectedObjects @("Domain policy (MaxPasswordAge=$maxAge days)") `
                -Remediation 'Set: Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00' `
                -MitreAttack 'T1078 - Valid Accounts'
            ))
        }
    }

    # -------------------------------------------------------------------------
    # CIS 1.2.x — Privileged Account Controls (CIS Level 1)
    # -------------------------------------------------------------------------

    # CIS 1.2.1 — Domain Admins group should have ≤ 5 members
    $daGroup = $Groups | Where-Object { $_.SamAccountName -eq 'Domain Admins' } | Select-Object -First 1
    if ($null -ne $daGroup) {
        $daCount = $daGroup.Members.Count
        if ($daCount -gt 5) {
            $findings.Add((New-Finding `
                -RuleId     'COMP-010' `
                -Title      "Domain Admins has $daCount members (CIS 1.2.1: keep ≤ 5)" `
                -Severity   'High' `
                -CISControl 'CIS-AD-1.2.1' `
                -NISTControl 'AC-6' `
                -Description "CIS 1.2.1 recommends keeping the Domain Admins group to 5 or fewer members. Over-populated Domain Admins groups expand the Tier 0 attack surface. Each additional member is a potential path to full domain compromise." `
                -AffectedObjects @("Domain Admins ($daCount members)") `
                -Remediation 'Review Domain Admins membership. Remove accounts that do not require persistent DA rights. Use time-bound, JIT privileged access instead. Run: Get-ADGroupMember "Domain Admins" | Select SamAccountName, objectClass' `
                -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts'
            ))
        }
    }

    # CIS 1.2.2 — Schema Admins should be empty except during schema operations
    $saGroup = $Groups | Where-Object { $_.SamAccountName -eq 'Schema Admins' } | Select-Object -First 1
    if ($null -ne $saGroup -and $saGroup.Members.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-011' `
            -Title      "Schema Admins group has $($saGroup.Members.Count) member(s) (should be empty)" `
            -Severity   'Medium' `
            -CISControl 'CIS-AD-1.2.2' `
            -NISTControl 'AC-6(9)' `
            -Description "CIS 1.2.2 requires the Schema Admins group to be empty except during explicit schema modification operations. Leaving accounts in Schema Admins persistently creates an unnecessary high-privilege attack target." `
            -AffectedObjects @("Schema Admins ($($saGroup.Members.Count) member(s))") `
            -Remediation 'Remove all accounts from Schema Admins: Get-ADGroupMember "Schema Admins" | ForEach-Object { Remove-ADGroupMember -Identity "Schema Admins" -Members $_ -Confirm:$false }. Re-add only when a schema change is actively needed, then remove immediately after.' `
            -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts'
        ))
    }

    # CIS 1.2.3 — Guest account disabled
    $guestUser = $Users | Where-Object { $_.SamAccountName -eq 'Guest' } | Select-Object -First 1
    if ($null -ne $guestUser -and $guestUser.Enabled) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-012' `
            -Title      'Guest account is enabled (CIS 1.2.3 requires it disabled)' `
            -Severity   'Medium' `
            -CISControl 'CIS-AD-1.2.3' `
            -NISTControl 'AC-2(3)' `
            -Description "CIS 1.2.3 requires the built-in Guest account to be disabled. An enabled Guest account can be exploited for anonymous access or used in pass-the-hash attacks." `
            -AffectedObjects @('Guest') `
            -Remediation 'Disable: Disable-ADAccount -Identity Guest' `
            -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts'
        ))
    }

    # CIS 1.2.4 — Accounts with PasswordNeverExpires in privileged groups
    $enabledPrivUsers = @($Users | Where-Object { $_.Enabled -and $_.PasswordNeverExpires -and $_.AdminCount -eq 1 })
    if ($enabledPrivUsers.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-013' `
            -Title      "$($enabledPrivUsers.Count) privileged account(s) have PasswordNeverExpires (CIS 1.2.4)" `
            -Severity   'High' `
            -CISControl 'CIS-AD-1.2.4' `
            -NISTControl 'IA-5' `
            -Description "CIS 1.2.4 prohibits PasswordNeverExpires on privileged accounts. Permanent passwords create permanent exposure if the password is ever compromised — there is no forced rotation." `
            -AffectedObjects ($enabledPrivUsers | Select-Object -ExpandProperty SamAccountName) `
            -Remediation 'Clear PasswordNeverExpires on privileged accounts and enforce regular rotation. Set-ADUser -Identity <name> -PasswordNeverExpires $false. Use gMSA/MSA for service accounts that need non-expiring credentials.' `
            -MitreAttack 'T1078 - Valid Accounts'
        ))
    }

    # -------------------------------------------------------------------------
    # CIS 1.3.x — NTLM and Legacy Authentication (CIS Level 1)
    # -------------------------------------------------------------------------

    # CIS 1.3.1 — NTLMv1 disabled (LmCompatibilityLevel >= 3 = NTLMv2 only on clients, 5 = NTLMv2 only everywhere)
    $ntlmHostsV1 = @($NtlmData | Where-Object { $_.LmCompatibilityLevel -lt 3 -or $_.NtlmV1Enabled -eq $true })
    if ($ntlmHostsV1.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-020' `
            -Title      "$($ntlmHostsV1.Count) DC(s) allow NTLMv1 authentication (CIS 1.3.1)" `
            -Severity   'High' `
            -CISControl 'CIS-AD-1.3.1' `
            -NISTControl 'IA-3' `
            -Description "CIS 1.3.1 requires LmCompatibilityLevel of at least 3 on DCs, with 5 preferred (NTLMv2 responses only). NTLMv1 hashes can be cracked trivially in minutes with modern hardware." `
            -AffectedObjects ($ntlmHostsV1 | Select-Object -ExpandProperty ComputerName) `
            -Remediation 'Set GPO: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LAN Manager authentication level = "Send NTLMv2 response only. Refuse LM & NTLM" (value 5).' `
            -MitreAttack 'T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay'
        ))
    }

    # -------------------------------------------------------------------------
    # CIS 1.4.x — Trust Security
    # -------------------------------------------------------------------------

    # CIS 1.4.1 — External and forest trusts without SID filtering
    $unsafeTrusts = @($Trusts | Where-Object {
        ($_.TrustType -match 'External|Forest') -and
        ($null -eq $_.SIDFilteringEnabled -or $_.SIDFilteringEnabled -eq $false)
    })
    if ($unsafeTrusts.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-030' `
            -Title      "$($unsafeTrusts.Count) trust(s) without SID filtering (CIS 1.4.1)" `
            -Severity   'High' `
            -CISControl 'CIS-AD-1.4.1' `
            -NISTControl 'AC-4' `
            -Description "CIS 1.4.1 requires SID filtering on all external and forest trusts. Without SID filtering, attackers who have compromised a trusted domain can inject privileged SIDs into cross-domain authentication tokens (SIDHistory abuse), effectively gaining Tier 0 access." `
            -AffectedObjects ($unsafeTrusts | Select-Object -ExpandProperty TargetName) `
            -Remediation 'Enable SID filtering: netdom trust <domain> /domain:<trusted-domain> /quarantine:Yes. For forest trusts: Set-ADObject to enable SID filtering attributes.' `
            -MitreAttack 'T1134.005 - Access Token Manipulation: SID-History Injection'
        ))
    }

    Write-Verbose "CIS benchmark checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region LAPS (Local Administrator Password Solution) Check

function Invoke-LAPSCheck {
    <#
    .SYNOPSIS
        Checks LAPS (Local Administrator Password Solution) deployment and coverage.
    .DESCRIPTION
        LAPS automatically manages local administrator account passwords on domain-joined
        computers, storing them in AD and rotating them on a schedule. Without LAPS,
        organizations typically reuse the same local admin password across all machines,
        enabling lateral movement via pass-the-hash once one machine is compromised.

        This check determines:
        1. Whether the LAPS schema extension is installed (ms-Mcs-AdmPwd attribute)
        2. Whether LAPS is deployed on workstations and servers
        3. Percentage coverage of computer accounts with populated LAPS passwords

        CIS Control: CIS-AD-4.1 (Local Administrator Password Management)
    .PARAMETER Computers
        Computer objects from Get-ADComputers.
    .EXAMPLE
        Invoke-LAPSCheck -Computers $adComputers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Computers
    )

    Write-Verbose "Running LAPS deployment check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    $enabledComputers = @($Computers | Where-Object { $_.Enabled })

    if ($enabledComputers.Count -eq 0) {
        Write-Verbose "No enabled computer accounts found for LAPS check."
        return @()
    }

    # Check LAPS attribute presence on computer objects
    # ms-Mcs-AdmPwd (legacy LAPS) or msLAPS-Password (Windows LAPS)
    $lapsLegacy  = @($enabledComputers | Where-Object { $_.PSObject.Properties.Name -contains 'ms-Mcs-AdmPwd'   -and $null -ne $_.'ms-Mcs-AdmPwd' -and $_.'ms-Mcs-AdmPwd' -ne '' })
    $lapsWindows = @($enabledComputers | Where-Object { $_.PSObject.Properties.Name -contains 'msLAPS-Password' -and $null -ne $_.'msLAPS-Password' -and $_.'msLAPS-Password' -ne '' })

    # Check if either LAPS schema attribute exists (even if empty, means schema is extended)
    $schemaHasLegacyLAPS  = ($enabledComputers | Where-Object { $_.PSObject.Properties.Name -contains 'ms-Mcs-AdmPwd' }  | Measure-Object).Count -gt 0
    $schemaHasWindowsLAPS = ($enabledComputers | Where-Object { $_.PSObject.Properties.Name -contains 'msLAPS-Password' } | Measure-Object).Count -gt 0

    $lapsInstalled  = $schemaHasLegacyLAPS -or $schemaHasWindowsLAPS
    $lapsPopulated  = $lapsLegacy.Count + $lapsWindows.Count
    $coveragePct    = if ($enabledComputers.Count -gt 0) { [math]::Round($lapsPopulated / $enabledComputers.Count * 100, 1) } else { 0 }

    # Computers missing LAPS (excluding DCs — DCs don't need LAPS since they have no local SAM)
    $nonDCComputers = @($enabledComputers | Where-Object { -not ($_.UserAccountControl -band 0x2000) })
    $missingLAPS    = @($nonDCComputers | Where-Object {
        (-not $schemaHasLegacyLAPS  -or [string]::IsNullOrEmpty($_.'ms-Mcs-AdmPwd')) -and
        (-not $schemaHasWindowsLAPS -or [string]::IsNullOrEmpty($_.'msLAPS-Password'))
    })

    if (-not $lapsInstalled) {
        # LAPS schema not even installed
        $findings.Add((New-Finding `
            -RuleId     'COMP-040' `
            -Title      'LAPS is not deployed — local admin passwords are not managed' `
            -Severity   'High' `
            -CISControl 'CIS-AD-4.1' `
            -NISTControl 'AC-2, IA-5' `
            -Description "LAPS (Local Administrator Password Solution) is not deployed in this environment. Without LAPS, the local Administrator account likely uses the same password across all domain-joined computers. Compromising one machine enables lateral movement to all machines via pass-the-hash." `
            -AffectedObjects @("$($enabledComputers.Count) domain-joined computers without LAPS") `
            -Remediation 'Install LAPS: (1) Deploy the LAPS MSI to all computers. (2) Extend the AD schema: Update-AdmPwdADSchema. (3) Set permissions: Set-AdmPwdComputerSelfPermission -OrgUnit <OU>. (4) Configure GPO: Computer Configuration\Administrative Templates\LAPS. For Windows Server 2019+ and Windows 11, use Windows LAPS (built-in): Enable-WindowsOptionalFeature -FeatureName LAPS.' `
            -MitreAttack 'T1550.002 - Use Alternate Authentication Material: Pass the Hash'
        ))
    }
    elseif ($coveragePct -lt 80 -and $missingLAPS.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-041' `
            -Title      "LAPS coverage is only $coveragePct% ($($missingLAPS.Count) of $($nonDCComputers.Count) non-DC computers missing)" `
            -Severity   'Medium' `
            -CISControl 'CIS-AD-4.1' `
            -NISTControl 'AC-2, IA-5' `
            -Description "LAPS is installed but coverage is below 80%. $($missingLAPS.Count) non-DC computer accounts do not have LAPS passwords stored in AD, meaning those machines still likely use a shared local admin password. Each uncovered machine is a lateral movement risk." `
            -AffectedObjects ($missingLAPS | Select-Object -ExpandProperty SamAccountName | Select-Object -First 50) `
            -Remediation 'Ensure LAPS GPO applies to all OU paths containing workstations/servers. Check gpresult on affected machines. Verify LAPS client is installed. Run: Get-ADComputer -Filter {ms-Mcs-AdmPwd -notlike "*"} to identify gaps.' `
            -MitreAttack 'T1550.002 - Use Alternate Authentication Material: Pass the Hash' `
            -ExtraData @{ CoveragePct = $coveragePct; MissingCount = $missingLAPS.Count; TotalNonDC = $nonDCComputers.Count }
        ))
    }
    elseif ($coveragePct -lt 100 -and $missingLAPS.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-042' `
            -Title      "LAPS coverage at $coveragePct% — $($missingLAPS.Count) computer(s) still unmanaged" `
            -Severity   'Low' `
            -CISControl 'CIS-AD-4.1' `
            -NISTControl 'AC-2, IA-5' `
            -Description "LAPS coverage is above 80% but not complete. $($missingLAPS.Count) non-DC computers still lack LAPS-managed local admin passwords, creating residual lateral-movement risk." `
            -AffectedObjects ($missingLAPS | Select-Object -ExpandProperty SamAccountName | Select-Object -First 30) `
            -Remediation 'Investigate why these computers are not receiving the LAPS GPO. Check OU scoping and WMI filters on the LAPS GPO.' `
            -MitreAttack 'T1550.002 - Use Alternate Authentication Material: Pass the Hash'
        ))
    }

    Write-Verbose "LAPS check complete. Findings: $($findings.Count). Coverage: $coveragePct%"
    return $findings.ToArray()
}

#endregion

#region Protected Users Group Check

function Invoke-ProtectedUsersCheck {
    <#
    .SYNOPSIS
        Checks whether privileged users are members of the Protected Users group.
    .DESCRIPTION
        The Protected Users security group (Windows Server 2012 R2+) provides
        additional hardening for its members:
        - No NTLM authentication (Kerberos only)
        - No DES or RC4 in Kerberos (AES only)
        - No credential caching on hosts
        - TGT lifetime capped at 4 hours (requires re-authentication)
        - No Kerberos unconstrained delegation

        All privileged accounts (AdminCount=1, DA, EA, Schema Admins, etc.) should
        be in Protected Users to reduce credential theft impact.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Groups
        Group objects from Get-ADGroups.
    .EXAMPLE
        Invoke-ProtectedUsersCheck -Users $adUsers -Groups $adGroups
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,

        [Parameter(Mandatory = $true)]
        [object[]]$Groups
    )

    Write-Verbose "Running Protected Users group check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # Find the Protected Users group
    $protectedUsersGroup = $Groups | Where-Object { $_.SamAccountName -eq 'Protected Users' } | Select-Object -First 1

    if ($null -eq $protectedUsersGroup) {
        # Group doesn't exist — domain functional level may be too old (pre-2012 R2)
        $findings.Add((New-Finding `
            -RuleId     'COMP-050' `
            -Title      "'Protected Users' security group not found — domain may be at legacy functional level" `
            -Severity   'Medium' `
            -CISControl 'CIS-AD-1.2.5' `
            -NISTControl 'AC-6, IA-5' `
            -Description "The 'Protected Users' security group (introduced in Windows Server 2012 R2) was not found. This may indicate the domain is running at a functional level below Windows Server 2012 R2, or the group has been deleted. Without this group, privileged accounts lack an important layer of credential-theft protection." `
            -AffectedObjects @('Protected Users group not found') `
            -Remediation 'Raise the domain functional level to Windows Server 2012 R2 or higher. Re-create the Protected Users group if accidentally deleted: New-ADGroup -Name "Protected Users" -GroupScope Global -GroupCategory Security -Path "CN=Users,DC=corp,DC=local". Add all privileged accounts to the group.' `
            -MitreAttack 'T1003 - OS Credential Dumping'
        ))
        return $findings.ToArray()
    }

    # Get members of Protected Users (by DN)
    $protectedMemberDNs = @($protectedUsersGroup.Members | Where-Object { $_ })

    # Privileged users = AdminCount=1 or members of Tier 0 groups
    $tier0GroupNames = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators')
    $tier0GroupObjs  = @($Groups | Where-Object { $_.SamAccountName -in $tier0GroupNames })
    $tier0MemberDNs  = @($tier0GroupObjs | ForEach-Object { $_.Members } | Where-Object { $_ } | Sort-Object -Unique)

    $privilegedUsers = @($Users | Where-Object {
        $_.Enabled -and (
            $_.AdminCount -eq 1 -or
            $_.DistinguishedName -in $tier0MemberDNs
        )
    })

    if ($privilegedUsers.Count -eq 0) {
        Write-Verbose "No privileged users found for Protected Users check."
        return @()
    }

    # Privileged users NOT in Protected Users
    $notProtected = @($privilegedUsers | Where-Object { $_.DistinguishedName -notin $protectedMemberDNs })

    if ($notProtected.Count -gt 0) {
        $severity = if ($notProtected.Count -gt 5 -or ($notProtected | Where-Object { $_.AdminCount -eq 1 })) { 'High' } else { 'Medium' }
        $findings.Add((New-Finding `
            -RuleId     'COMP-051' `
            -Title      "$($notProtected.Count) of $($privilegedUsers.Count) privileged account(s) are NOT in Protected Users" `
            -Severity   $severity `
            -CISControl 'CIS-AD-1.2.5' `
            -NISTControl 'AC-6, IA-5' `
            -Description "These privileged accounts (AdminCount=1 or members of Tier 0 groups) are not in the 'Protected Users' security group. Accounts outside this group are susceptible to NTLM credential capture, Kerberos RC4 downgrade attacks, and credential caching on workstations." `
            -AffectedObjects ($notProtected | Select-Object -ExpandProperty SamAccountName) `
            -Remediation 'Add all privileged accounts to Protected Users: Add-ADGroupMember -Identity "Protected Users" -Members @(<username1>, <username2>). Ensure service accounts using NTLM or delegation are excluded — they will break if added. Test in a lab first.' `
            -MitreAttack 'T1003 - OS Credential Dumping; T1558.003 - Kerberoasting'
        ))
    }

    Write-Verbose "Protected Users check complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Managed Service Account (gMSA/MSA) Check

function Invoke-MSACheck {
    <#
    .SYNOPSIS
        Audits use of (Group) Managed Service Accounts vs. plain service accounts.
    .DESCRIPTION
        Group Managed Service Accounts (gMSAs) and Managed Service Accounts (MSAs)
        auto-rotate their 120-character passwords every 30 days without any manual
        intervention, making them immune to Kerberoasting and password spray attacks.

        This check identifies:
        1. Existing gMSA and MSA accounts in the domain.
        2. User accounts with SPNs (classic service accounts) that should be migrated.
        3. Whether the KDS root key is provisioned (required for gMSA operation).

        CIS Control: CIS-AD-2.1 (Service Account Management)
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Computers
        Computer objects (used to detect gMSAs by objectClass).
    .EXAMPLE
        Invoke-MSACheck -Users $adUsers
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,

        [Parameter(Mandatory = $false)]
        [object[]]$Computers = @()
    )

    Write-Verbose "Running MSA/gMSA check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # User accounts with SPNs = classic service accounts (should be migrated to gMSA)
    $classicSvcAccts = @($Users | Where-Object {
        $_.Enabled -and
        $_.ServicePrincipalNames.Count -gt 0 -and
        # Exclude computer accounts (they end in $)
        $_.SamAccountName -notmatch '\$$'
    })

    # gMSA accounts (objectClass = msDS-GroupManagedServiceAccount or SamAccountName ends in $)
    # They may appear in Users or Computers collection depending on collector
    $gmsaAccts = @($Users | Where-Object {
        $_.SamAccountName -match '\$$' -and
        ($_.ObjectClass -match 'msDS-GroupManagedServiceAccount' -or $_.ServicePrincipalNames.Count -gt 0)
    })

    if ($classicSvcAccts.Count -gt 0) {
        $highRiskSvc = @($classicSvcAccts | Where-Object { $_.AdminCount -eq 1 })

        $findings.Add((New-Finding `
            -RuleId     'COMP-060' `
            -Title      "$($classicSvcAccts.Count) classic service account(s) with SPNs could be replaced with gMSAs" `
            -Severity   $(if ($highRiskSvc.Count -gt 0) { 'High' } else { 'Medium' }) `
            -CISControl 'CIS-AD-2.1' `
            -NISTControl 'IA-5(1)' `
            -Description "Found $($classicSvcAccts.Count) user accounts with Service Principal Names (SPNs) that are classic service accounts. These accounts are Kerberoastable and typically have static passwords that rarely rotate. gMSAs auto-rotate 120-character passwords every 30 days, making Kerberoasting attacks infeasible. $($gmsaAccts.Count) gMSA/MSA accounts are currently in use." `
            -AffectedObjects ($classicSvcAccts | Select-Object -ExpandProperty SamAccountName) `
            -Remediation 'Migrate service accounts to gMSAs: (1) Ensure KDS root key exists: Get-KdsRootKey. Create if needed: Add-KdsRootKey -EffectiveImmediately. (2) Create gMSA: New-ADServiceAccount -Name <name> -DNSHostName <fqdn> -PrincipalsAllowedToRetrieveManagedPassword <computer$>. (3) Install on host: Install-ADServiceAccount <name>. (4) Update service to use gMSA (format: DOMAIN\<name>$). (5) Disable old service account once migrated.' `
            -MitreAttack 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting' `
            -ExtraData @{ gMSACount = $gmsaAccts.Count; ClassicCount = $classicSvcAccts.Count; PrivilegedCount = $highRiskSvc.Count }
        ))
    }

    if ($gmsaAccts.Count -eq 0 -and $classicSvcAccts.Count -eq 0) {
        Write-Verbose "No service accounts (gMSA or classic) found."
    }
    elseif ($gmsaAccts.Count -eq 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-061' `
            -Title      'No gMSA/MSA accounts found — KDS root key may not be provisioned' `
            -Severity   'Informational' `
            -CISControl 'CIS-AD-2.1' `
            -NISTControl 'IA-5(1)' `
            -Description 'No Group Managed Service Accounts (gMSAs) or Managed Service Accounts (MSAs) were found in this domain. gMSAs are the Microsoft-recommended replacement for classic service accounts. Ensure the KDS root key is provisioned to enable gMSA creation.' `
            -AffectedObjects @('No gMSA/MSA accounts detected') `
            -Remediation 'Provision the KDS root key: Add-KdsRootKey -EffectiveImmediately (lab) or Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10) (production). Then begin migrating service accounts to gMSAs.' `
            -MitreAttack 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
        ))
    }

    Write-Verbose "MSA/gMSA check complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Tiered Administration Model Check

function Invoke-TieredAdminModelCheck {
    <#
    .SYNOPSIS
        Evaluates whether a Tiered Administration Model is in place.
    .DESCRIPTION
        The Microsoft Tiered Administration Model (PAM/PAW model) prevents lateral
        movement by isolating privileged accounts across tiers:
        - Tier 0: DC and domain-level admin accounts (DA, EA)
        - Tier 1: Server admin accounts
        - Tier 2: Workstation and helpdesk accounts

        Key indicators of a broken tier model:
        - DA accounts used for interactive workstation logon (seen in event logs)
        - Admin accounts with email addresses (used for routine work)
        - DA accounts matching naming patterns of end-user accounts (no separate admin account)
        - Same account in both DA and server admin groups

        This check evaluates account naming and group membership patterns.
    .PARAMETER Users
        User objects from Get-ADUsers.
    .PARAMETER Groups
        Group objects from Get-ADGroups.
    .EXAMPLE
        Invoke-TieredAdminModelCheck -Users $adUsers -Groups $adGroups
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Users,

        [Parameter(Mandatory = $true)]
        [object[]]$Groups
    )

    Write-Verbose "Running Tiered Admin Model check..."
    $findings = [System.Collections.Generic.List[object]]::new()

    $daGroup = $Groups | Where-Object { $_.SamAccountName -eq 'Domain Admins' } | Select-Object -First 1
    if ($null -eq $daGroup) { return @() }

    $daMembers = @($daGroup.Members | Where-Object { $_ })
    $daUsers   = @($Users | Where-Object { $_.DistinguishedName -in $daMembers -and $_.Enabled })

    # Indicator 1: DA accounts with email addresses (used for daily work = mixed-use account)
    $daWithEmail = @($daUsers | Where-Object { -not [string]::IsNullOrEmpty($_.EmailAddress) })
    if ($daWithEmail.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-070' `
            -Title      "$($daWithEmail.Count) Domain Admin account(s) have email addresses (mixed-use accounts)" `
            -Severity   'High' `
            -CISControl 'CIS-AD-1.2.6' `
            -NISTControl 'AC-5, AC-6' `
            -Description "These Domain Admin accounts have email addresses configured, indicating they may be used for daily work as well as privileged administration. Mixed-use privileged accounts violate the Tiered Administration Model: a DA account used for email browsing or document editing is exposed to phishing and malware running in the user context." `
            -AffectedObjects ($daWithEmail | Select-Object -ExpandProperty SamAccountName) `
            -Remediation 'Create separate admin accounts without email/mailbox for DA duties. Regular user account: jsmith@corp.com. Admin account: adm-jsmith (no mailbox). Admin accounts should only log on to Privileged Access Workstations (PAWs).' `
            -MitreAttack 'T1566 - Phishing; T1078.002 - Valid Accounts: Domain Accounts'
        ))
    }

    # Indicator 2: DA accounts that appear to be regular user accounts (no 'adm','admin','svc' prefix/suffix and no separate admin naming pattern)
    $suspectDAs = @($daUsers | Where-Object {
        $_.SamAccountName -notmatch '^(adm|admin|a-|t0-|tier0|priv|da-|svc)' -and
        $_.SamAccountName -notmatch '(adm|admin|-a|-da|-priv)$' -and
        -not [string]::IsNullOrEmpty($_.EmailAddress)
    })

    if ($suspectDAs.Count -gt 0) {
        $findings.Add((New-Finding `
            -RuleId     'COMP-071' `
            -Title      "$($suspectDAs.Count) Domain Admin(s) have non-admin account naming (possible mixed-use)" `
            -Severity   'Medium' `
            -CISControl 'CIS-AD-1.2.6' `
            -NISTControl 'AC-5, AC-6' `
            -Description "These DA accounts do not follow an admin naming convention (e.g., adm-, a-, t0-) and have email addresses, suggesting they may be regular user accounts also granted DA rights rather than dedicated admin accounts. Dedicated admin accounts reduce the blast radius of compromises." `
            -AffectedObjects ($suspectDAs | Select-Object -ExpandProperty SamAccountName) `
            -Remediation 'Follow naming convention for admin accounts: adm-<username> or a-<username>. Create dedicated admin accounts in a privileged OU with no email/mailbox. Remove DA rights from regular user accounts.' `
            -MitreAttack 'T1078.002 - Valid Accounts: Domain Accounts'
        ))
    }

    Write-Verbose "Tiered Admin Model check complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region Consolidated Compliance Runner

function Invoke-AllComplianceChecks {
    <#
    .SYNOPSIS
        Runs all compliance checks and returns aggregated findings.
    .PARAMETER CollectedData
        Full collected-data hashtable from the AD collectors.
    .EXAMPLE
        $complianceFindings = Invoke-AllComplianceChecks -CollectedData $collectedData
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CollectedData
    )

    $users       = @(if ($CollectedData.ContainsKey('Users'))            { $CollectedData.Users }            else { @() })
    $groups      = @(if ($CollectedData.ContainsKey('Groups'))           { $CollectedData.Groups }           else { @() })
    $computers   = @(if ($CollectedData.ContainsKey('Computers'))        { $CollectedData.Computers }        else { @() })
    $policies    = @(if ($CollectedData.ContainsKey('PasswordPolicies')) { $CollectedData.PasswordPolicies } else { @() })
    $dcs         = @(if ($CollectedData.ContainsKey('DomainControllers')){ $CollectedData.DomainControllers } else { @() })
    $trusts      = @(if ($CollectedData.ContainsKey('Trusts'))           { $CollectedData.Trusts }           else { @() })
    $ntlmData    = @(if ($CollectedData.ContainsKey('NtlmSettings'))     { $CollectedData.NtlmSettings }     else { @() })

    $all = [System.Collections.Generic.List[object]]::new()

    foreach ($f in (Invoke-CISBenchmarkCheck -Users $users -Groups $groups -PasswordPolicies $policies -DomainControllers $dcs -Trusts $trusts -NtlmData $ntlmData)) {
        $all.Add($f)
    }
    foreach ($f in (Invoke-LAPSCheck -Computers $computers)) {
        $all.Add($f)
    }
    foreach ($f in (Invoke-ProtectedUsersCheck -Users $users -Groups $groups)) {
        $all.Add($f)
    }
    foreach ($f in (Invoke-MSACheck -Users $users -Computers $computers)) {
        $all.Add($f)
    }
    foreach ($f in (Invoke-TieredAdminModelCheck -Users $users -Groups $groups)) {
        $all.Add($f)
    }

    return $all.ToArray()
}

#endregion

Export-ModuleMember -Function Invoke-CISBenchmarkCheck, Invoke-LAPSCheck,
                               Invoke-ProtectedUsersCheck, Invoke-MSACheck,
                               Invoke-TieredAdminModelCheck, Invoke-AllComplianceChecks
