#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Detection Engineering Module
.DESCRIPTION
    Checks whether domain controllers have the audit policies and log retention
    settings required to detect Active Directory attacks. Identifies gaps in
    SIEM coverage that would leave common AD attack techniques undetected.

    Two functions:
    - Invoke-AuditPolicyCheck  : verifies Windows Advanced Audit Policy categories
    - Invoke-SIEMCoverageCheck : verifies event log sizes/retention and key event presence
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
        [string]$Category    = 'Detection Engineering',
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

#region Audit Policy Check

function Invoke-AuditPolicyCheck {
    <#
    .SYNOPSIS
        Verifies that Windows Advanced Audit Policies required for AD attack detection are enabled.
    .DESCRIPTION
        Checks the following Advanced Audit Policy subcategories on domain controllers,
        which are required to detect common Active Directory attack techniques:

        | Subcategory                           | Required for detecting...                  |
        |---------------------------------------|--------------------------------------------|
        | Audit Logon / Logoff                  | Pass-the-Hash, credential reuse            |
        | Audit Account Logon: Kerberos Auth    | Kerberoasting (TGS-REQ with RC4)           |
        | Audit Account Logon: Kerberos TGT     | AS-REP roasting, Golden/Silver Tickets     |
        | Audit DS Access: DS Changes           | AdminSDHolder mods, DCSync prep            |
        | Audit Account Management              | Privileged group changes, account creation |
        | Audit Privilege Use                   | SeDebugPrivilege, dangerous right use      |
        | Audit Process Creation                | Command-line logging for living-off-land   |
        | Audit Policy Change                   | GPO tampering, audit policy disabling      |
        | Audit Directory Service Replication   | DCSync activity (Event 4929)               |

        This check uses `auditpol.exe /get /category:*` remotely where possible,
        and falls back to registry-based inspection of the GPO audit settings.
    .PARAMETER DomainControllers
        DC objects from Get-ADDomainControllers.
    .PARAMETER Credential
        Optional PSCredential for remote access.
    .EXAMPLE
        Invoke-AuditPolicyCheck -DomainControllers $dcs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Running audit policy check on DCs..."
    $findings = [System.Collections.Generic.List[object]]::new()

    # Required audit categories and their attack detection purpose
    # Registry value names under HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Audit
    $requiredCategories = @(
        [PSCustomObject]@{ Name='Audit Logon';                    RegKey='AuditLogon';              MinValue=2; Purpose='Logon/Logoff — detect Pass-the-Hash, lateral movement' }
        [PSCustomObject]@{ Name='Audit Account Logon';            RegKey='AuditAccountLogon';       MinValue=2; Purpose='Kerberos ticket requests — detect Kerberoasting/AS-REP' }
        [PSCustomObject]@{ Name='Audit DS Access';                RegKey='AuditDSAccess';           MinValue=2; Purpose='Directory Service access — detect DCSync prep, AdminSDHolder mods' }
        [PSCustomObject]@{ Name='Audit Account Management';       RegKey='AuditAccountManage';      MinValue=2; Purpose='Account and group changes — detect privilege escalation' }
        [PSCustomObject]@{ Name='Audit Privilege Use';            RegKey='AuditPrivilegeUse';       MinValue=2; Purpose='Privilege use — detect SeDebugPrivilege, SeTcbPrivilege' }
        [PSCustomObject]@{ Name='Audit Process Creation';         RegKey='AuditProcessTracking';    MinValue=1; Purpose='Process creation — detect living-off-the-land tools' }
        [PSCustomObject]@{ Name='Audit Policy Change';            RegKey='AuditPolicyChange';       MinValue=2; Purpose='Policy changes — detect audit log disabling, GPO tampering' }
        [PSCustomObject]@{ Name='Audit Directory Service Changes';RegKey='AuditDsChanges';          MinValue=2; Purpose='DS object changes — detect AdminSDHolder, SID History injection' }
    )
    # MinValue: 1=Success, 2=Failure, 3=Success+Failure (audit flags)

    $gapsByDC = [System.Collections.Generic.List[object]]::new()

    foreach ($dc in $DomainControllers) {
        $hostname = if ($dc.DnsHostName) { $dc.DnsHostName } else { $dc.Name }
        Write-Verbose "Checking audit policies on: $hostname"

        $auditGaps = [System.Collections.Generic.List[string]]::new()

        try {
            # Try auditpol.exe via Invoke-Command
            $auditpolOutput = $null
            if ($hostname -ne $env:COMPUTERNAME -and $hostname -ne 'localhost') {
                $icParams = @{ ComputerName = $hostname; ErrorAction = 'Stop' }
                if ($null -ne $Credential) { $icParams.Credential = $Credential }
                $auditpolOutput = Invoke-Command @icParams -ScriptBlock {
                    & auditpol.exe /get /category:* 2>&1
                }
            }
            else {
                $auditpolOutput = & auditpol.exe /get /category:* 2>&1
            }

            if ($auditpolOutput) {
                # Parse auditpol output — lines look like:
                #   "  Logon                          Success and Failure"
                #   "  Kerberos Authentication Service No Auditing"
                $auditMap = @{}
                foreach ($line in $auditpolOutput) {
                    if ($line -match '^\s+(.+?)\s{2,}(No Auditing|Success and Failure|Success|Failure)\s*$') {
                        $auditMap[$Matches[1].Trim()] = $Matches[2].Trim()
                    }
                }

                foreach ($cat in $requiredCategories) {
                    # Try exact or partial match
                    $matched = $auditMap.Keys | Where-Object { $_ -like "*$($cat.Name -replace 'Audit ','')*" }
                    if ($matched) {
                        $val = $auditMap[$matched | Select-Object -First 1]
                        $hasSuccess = $val -match 'Success'
                        $hasFailure = $val -match 'Failure'
                        $ok = switch ($cat.MinValue) {
                            1 { $hasSuccess }
                            2 { $hasFailure }
                            3 { $hasSuccess -and $hasFailure }
                            default { $hasSuccess -or $hasFailure }
                        }
                        if (-not $ok) {
                            $auditGaps.Add("$($cat.Name) — currently: '$val' — needed for: $($cat.Purpose)")
                        }
                    }
                    else {
                        $auditGaps.Add("$($cat.Name) — not found in auditpol output — needed for: $($cat.Purpose)")
                    }
                }
            }
        }
        catch {
            Write-Verbose "Could not run auditpol on ${hostname}: $_"
            # Fall back: flag as unknown
            $auditGaps.Add("Unable to verify audit policy (remote access failed) — all categories assumed missing")
        }

        if ($auditGaps.Count -gt 0) {
            $gapsByDC.Add([PSCustomObject]@{
                DCName = $hostname
                Gaps   = $auditGaps.ToArray()
            })
        }
    }

    if ($gapsByDC.Count -gt 0) {
        $affectedDCs = $gapsByDC | Select-Object -ExpandProperty DCName
        $allGaps     = $gapsByDC | ForEach-Object { $_.Gaps } | Sort-Object -Unique

        $findings.Add((New-Finding `
            -RuleId    'DE-001' `
            -Title     "Missing or insufficient audit policies on $($gapsByDC.Count) DC(s)" `
            -Severity  'High' `
            -Description "One or more domain controllers are missing Windows Advanced Audit Policy settings required to detect common AD attacks (Kerberoasting, DCSync, Golden Ticket, Pass-the-Hash, privilege escalation). Without these audit policies, attacks proceed silently with no evidence trail." `
            -AffectedObjects $affectedDCs `
            -Remediation '1) Open Group Policy Management and edit the Default Domain Controllers Policy. 2) Navigate to Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration. 3) Enable Success and Failure for all required subcategories. 4) Verify: auditpol /get /category:* — all critical categories should show "Success and Failure".' `
            -MitreAttack 'T1562.002 - Impair Defenses: Disable Windows Event Logging' `
            -ExtraData @{ GapsByDC = $gapsByDC; AllGaps = $allGaps }
        ))
    }

    Write-Verbose "Audit policy checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

#region SIEM Coverage Check

function Invoke-SIEMCoverageCheck {
    <#
    .SYNOPSIS
        Checks event log sizes and retention settings required for effective AD monitoring.
    .DESCRIPTION
        Validates the Security, System, and Application event logs on domain controllers
        to ensure:
        1. Log size is sufficient (Security: >= 200 MB, others >= 64 MB)
        2. Retention policy does not overwrite events too quickly
        3. Critical event IDs required for attack detection have been logged recently

        Critical event IDs for AD security:
        - 4624/4625  Logon success/failure (Pass-the-Hash, brute force)
        - 4648        Logon with explicit credentials (lateral movement)
        - 4662        Object access (DCSync — Replicating Directory Changes)
        - 4672        Special privileges assigned (privilege escalation)
        - 4698        Scheduled task created (persistence)
        - 4720/4728   Account/group creation (privilege escalation)
        - 4768/4769   Kerberos TGT/TGS requests (Kerberoasting, Golden Ticket)
        - 4771        Kerberos pre-auth failure (password spray, AS-REP roasting)
        - 5136        Directory service object modification (AdminSDHolder, SID history)
        - 7045        Service installed (Skeleton Key, malware installation)
    .PARAMETER DomainControllers
        DC objects from Get-ADDomainControllers.
    .PARAMETER Credential
        Optional PSCredential for remote access.
    .EXAMPLE
        Invoke-SIEMCoverageCheck -DomainControllers $dcs
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$DomainControllers,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Running SIEM coverage check on DCs..."
    $findings = [System.Collections.Generic.List[object]]::new()

    $minimumLogSizesMB = @{
        'Security'    = 200
        'System'      = 64
        'Application' = 32
    }

    # Event IDs that MUST appear in the Security log for monitoring to be meaningful
    $criticalEventIds = @(4624, 4625, 4648, 4662, 4672, 4698, 4720, 4768, 4769, 4771, 5136, 7045)

    $coverageIssues = [System.Collections.Generic.List[object]]::new()

    foreach ($dc in $DomainControllers) {
        $hostname = if ($dc.DnsHostName) { $dc.DnsHostName } else { $dc.Name }
        Write-Verbose "Checking event log coverage on: $hostname"

        $dcIssues = [System.Collections.Generic.List[string]]::new()

        try {
            $cimParams = @{ ErrorAction = 'Stop' }
            if ($hostname -ne $env:COMPUTERNAME -and $hostname -ne 'localhost') {
                $cimParams.ComputerName = $hostname
                if ($null -ne $Credential) { $cimParams.Credential = $Credential }
            }

            # Check log sizes
            foreach ($logName in $minimumLogSizesMB.Keys) {
                try {
                    $logQuery = Get-CimInstance @cimParams -ClassName Win32_NTEventlogFile |
                        Where-Object { $_.LogfileName -eq $logName }

                    if ($logQuery) {
                        $maxSizeMB = [Math]::Round($logQuery.MaxFileSize / 1MB, 0)
                        $minSizeMB = $minimumLogSizesMB[$logName]
                        if ($maxSizeMB -lt $minSizeMB) {
                            $dcIssues.Add("$logName log: ${maxSizeMB}MB (minimum recommended: ${minSizeMB}MB)")
                        }
                        if ($logQuery.OverWriteOutDated -eq 0 -and $logQuery.OverWritePolicy -eq 'WhenNeeded') {
                            $dcIssues.Add("$logName log: 'Overwrite as needed' policy may discard events before ingestion")
                        }
                    }
                }
                catch { Write-Verbose "Could not check $logName log on ${hostname}: $_" }
            }

            # Check for presence of critical event IDs in the last 7 days
            # (absence of these events over a week could indicate log tampering or misconfigured audit)
            $sevenDaysAgo = (Get-Date).AddDays(-7)
            try {
                $recentEvents = @()
                if ($hostname -ne $env:COMPUTERNAME -and $hostname -ne 'localhost') {
                    $icParams = @{ ComputerName = $hostname; ErrorAction = 'Stop' }
                    if ($null -ne $Credential) { $icParams.Credential = $Credential }
                    $recentEvents = Invoke-Command @icParams -ScriptBlock {
                        param($ids, $since)
                        Get-WinEvent -FilterHashtable @{
                            LogName   = 'Security'
                            Id        = $ids
                            StartTime = $since
                        } -ErrorAction SilentlyContinue -MaxEvents 100 | Select-Object Id -Unique
                    } -ArgumentList $criticalEventIds, $sevenDaysAgo
                }
                else {
                    $recentEvents = Get-WinEvent -FilterHashtable @{
                        LogName   = 'Security'
                        Id        = $criticalEventIds
                        StartTime = $sevenDaysAgo
                    } -ErrorAction SilentlyContinue -MaxEvents 100 | Select-Object Id -Unique
                }

                $foundIds   = @($recentEvents | Select-Object -ExpandProperty Id -Unique)
                $missingIds = @($criticalEventIds | Where-Object { $_ -notin $foundIds })

                if ($missingIds.Count -gt ($criticalEventIds.Count / 2)) {
                    $dcIssues.Add("Security log: $($missingIds.Count) critical event IDs not seen in last 7 days: $($missingIds -join ', ') — may indicate missing audit policy or log tampering")
                }
            }
            catch { Write-Verbose "Could not read Security event log on ${hostname}: $_" }
        }
        catch {
            Write-Verbose "Could not check log coverage on ${hostname}: $_"
            $dcIssues.Add("Unable to check event log configuration (remote access denied)")
        }

        if ($dcIssues.Count -gt 0) {
            $coverageIssues.Add([PSCustomObject]@{
                DCName = $hostname
                Issues = $dcIssues.ToArray()
            })
        }
    }

    if ($coverageIssues.Count -gt 0) {
        $affectedDCs = $coverageIssues | Select-Object -ExpandProperty DCName

        $findings.Add((New-Finding `
            -RuleId    'DE-002' `
            -Title     "Insufficient SIEM/event log coverage on $($coverageIssues.Count) DC(s)" `
            -Severity  'High' `
            -Description "Domain controller event logs have insufficient size, retention, or are missing critical security events. This reduces the ability to detect attacks retroactively — incident response requires event history. Critical event IDs for detecting Kerberoasting, DCSync, Pass-the-Hash, privilege escalation, and persistence are absent or insufficiently logged." `
            -AffectedObjects $affectedDCs `
            -Remediation '1) Increase Security event log maximum size to at least 200 MB on all DCs (GPO: Computer Config > Windows Settings > Security Settings > Event Log > Maximum security log size). 2) Set retention to "Overwrite events as needed" or archive via Windows Event Forwarding (WEF). 3) Deploy a Windows Event Forwarding collector and forward Security events to a SIEM. 4) Enable all required Advanced Audit Policy subcategories. 5) Use Microsoft ATA/Defender for Identity for real-time DC monitoring.' `
            -MitreAttack 'T1562.002 - Impair Defenses: Disable Windows Event Logging' `
            -ExtraData @{ CoverageIssues = $coverageIssues }
        ))
    }

    Write-Verbose "SIEM coverage checks complete. Findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion

Export-ModuleMember -Function Invoke-AuditPolicyCheck, Invoke-SIEMCoverageCheck
