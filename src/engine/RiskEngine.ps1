#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Risk Scoring Engine
.DESCRIPTION
    Calculates risk scores for individual findings and an overall posture grade,
    provides quick-win prioritisation, and generates a remediation roadmap.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0

    Scoring model:
    Base score per finding = Severity weight × Exposure factor × Exploitability factor
    Overall score = Weighted average normalised to 0-100 (higher = worse)
    Grade = A (0-20), B (21-40), C (41-60), D (61-80), F (81-100)
#>

Set-StrictMode -Version Latest

#region Score Weights

$Script:SeverityWeights = @{
    Critical      = 40
    High          = 25
    Medium        = 15
    Low           = 5
    Informational = 1
}

$Script:ExploitabilityWeights = @{
    'T1558.003' = 1.3   # Kerberoasting — easy tooling available
    'T1558.004' = 1.3   # AS-REP Roasting
    'T1003.006' = 1.5   # DCSync — trivial with Mimikatz
    'T1649'     = 1.4   # AD CS — complex but high impact
    'T1210'     = 1.2   # RCE exploits
    'T1557.001' = 1.2   # NTLM relay
    'T1552.006' = 1.4   # GPP cPassword — trivial decryption
    'T1134.005' = 1.3   # SID History injection
    'T1556.001' = 1.5   # Skeleton Key — very high impact
    'T1207'     = 1.4   # Rogue DC
}

#endregion

#region Individual Finding Score

function Calculate-RiskScore {
    <#
    .SYNOPSIS
        Calculates a numeric risk score (0-100) for a single finding.
    .DESCRIPTION
        Score = min(100, SeverityWeight × ExploitFactor × AffectedRatio × AgeFactor)
        - SeverityWeight:  Base weight from severity level
        - ExploitFactor:   MITRE ATT&CK technique exploitability multiplier
        - AffectedRatio:   Log-scaled factor based on number of affected objects
        - AgeFactor:       1.0-1.3 based on how long the finding has persisted
    .PARAMETER Finding
        A single finding object.
    .PARAMETER TotalUserCount
        Total number of user accounts (for ratio calculation).
    .PARAMETER FirstSeenDate
        Optional datetime when this finding was first detected (for age factor).
    .EXAMPLE
        $score = Calculate-RiskScore -Finding $f -TotalUserCount 500
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [Parameter(Mandatory = $false)]
        [int]$TotalUserCount = 100,

        [Parameter(Mandatory = $false)]
        [datetime]$FirstSeenDate = [datetime]::MinValue
    )

    $baseWeight = $Script:SeverityWeights[$Finding.Severity]
    if ($null -eq $baseWeight) { $baseWeight = 1 }

    # Exploitability multiplier from MITRE ATT&CK mapping
    $exploitFactor = 1.0
    if (-not [string]::IsNullOrEmpty($Finding.MitreAttack)) {
        $techniqueId = ($Finding.MitreAttack -split ' ')[0]
        if ($Script:ExploitabilityWeights.ContainsKey($techniqueId)) {
            $exploitFactor = $Script:ExploitabilityWeights[$techniqueId]
        }
    }

    # Affected objects ratio (log scale to prevent huge counts from dominating)
    $affectedCount = [Math]::Max(1, $Finding.AffectedCount)
    $affectedRatio  = [Math]::Log($affectedCount + 1) / [Math]::Log([Math]::Max(2, $TotalUserCount + 1))
    $affectedFactor = 1.0 + ([Math]::Min(1.0, $affectedRatio) * 0.5)  # Range: 1.0 - 1.5

    # Age factor: findings that have persisted longer get a slight boost
    $ageFactor = 1.0
    if ($FirstSeenDate -ne [datetime]::MinValue) {
        $ageDays = ([datetime]::UtcNow - $FirstSeenDate).TotalDays
        if ($ageDays -gt 90)  { $ageFactor = 1.2 }
        elseif ($ageDays -gt 30) { $ageFactor = 1.1 }
    }

    $rawScore = $baseWeight * $exploitFactor * $affectedFactor * $ageFactor
    $capped   = [Math]::Min(100.0, [Math]::Round($rawScore, 2))

    return $capped
}

#endregion

#region Overall Posture Grade

function Get-OverallPostureGrade {
    <#
    .SYNOPSIS
        Calculates an overall security posture score and letter grade.
    .DESCRIPTION
        Aggregates all finding scores into a single 0-100 risk score and assigns
        a letter grade (A-F). Critical and High findings have the most impact.

        Grade bands:
        A = 0-20   (Good security posture)
        B = 21-40  (Acceptable, some improvement needed)
        C = 41-60  (Moderate risk, significant improvements needed)
        D = 61-80  (High risk, immediate action required)
        F = 81-100 (Critical risk, environment likely compromised)
    .PARAMETER Findings
        All finding objects.
    .PARAMETER TotalUserCount
        Total user accounts in domain.
    .EXAMPLE
        $grade = Get-OverallPostureGrade -Findings $allFindings -TotalUserCount 350
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [Parameter(Mandatory = $false)]
        [int]$TotalUserCount = 100
    )

    if ($Findings.Count -eq 0) {
        return [PSCustomObject]@{
            Score            = 0
            Grade            = 'A'
            Description      = 'No findings detected — excellent posture.'
            CriticalCount    = 0
            HighCount        = 0
            MediumCount      = 0
            LowCount         = 0
            InformationalCount = 0
            TotalFindings    = 0
        }
    }

    $severityCounts = @{ Critical=0; High=0; Medium=0; Low=0; Informational=0 }
    $findingScores  = [System.Collections.Generic.List[double]]::new()

    foreach ($finding in $Findings) {
        $sev = $finding.Severity
        if ($severityCounts.ContainsKey($sev)) { $severityCounts[$sev]++ }

        $score = Calculate-RiskScore -Finding $finding -TotalUserCount $TotalUserCount
        $findingScores.Add($score)
    }

    # Weighted overall score:
    # Critical contributes 50%, High 30%, Medium 15%, Low 5%
    $critScore   = if ($severityCounts.Critical    -gt 0) { [Math]::Min(100, $severityCounts.Critical    * 20) } else { 0 }
    $highScore   = if ($severityCounts.High        -gt 0) { [Math]::Min(100, $severityCounts.High        * 10) } else { 0 }
    $medScore    = if ($severityCounts.Medium      -gt 0) { [Math]::Min(100, $severityCounts.Medium      * 5)  } else { 0 }
    $lowScore    = if ($severityCounts.Low         -gt 0) { [Math]::Min(100, $severityCounts.Low         * 2)  } else { 0 }

    $severityScore = ($critScore * 0.50) + ($highScore * 0.30) + ($medScore * 0.15) + ($lowScore * 0.05)

    # Blend 70% severity-based score with 30% average per-finding score (which factors in
    # exploitability, affected-object count, and age multipliers via Calculate-RiskScore).
    $avgFindingScore = if ($findingScores.Count -gt 0) {
        ($findingScores | Measure-Object -Sum).Sum / $findingScores.Count
    } else { 0 }

    $compositeScore = ($severityScore * 0.70) + ($avgFindingScore * 0.30)
    $finalScore     = [Math]::Min(100, [Math]::Round($compositeScore, 1))

    $grade = switch ($true) {
        ($finalScore -le 20) { 'A' }
        ($finalScore -le 40) { 'B' }
        ($finalScore -le 60) { 'C' }
        ($finalScore -le 80) { 'D' }
        default              { 'F' }
    }

    $gradeDesc = switch ($grade) {
        'A' { 'Good security posture — maintain and monitor.' }
        'B' { 'Acceptable posture — some improvements needed.' }
        'C' { 'Moderate risk — significant improvements required.' }
        'D' { 'High risk — immediate remediation required.' }
        'F' { 'Critical risk — environment may be compromised. Treat as incident.' }
    }

    return [PSCustomObject]@{
        Score              = $finalScore
        Grade              = $grade
        Description        = $gradeDesc
        CriticalCount      = $severityCounts.Critical
        HighCount          = $severityCounts.High
        MediumCount        = $severityCounts.Medium
        LowCount           = $severityCounts.Low
        InformationalCount = $severityCounts.Informational
        TotalFindings      = $Findings.Count
        ComponentScores    = [PSCustomObject]@{
            CriticalComponent = $critScore
            HighComponent     = $highScore
            MediumComponent   = $medScore
            LowComponent      = $lowScore
        }
    }
}

#endregion

#region Quick Wins

function Get-QuickWins {
    <#
    .SYNOPSIS
        Returns the top quick-win remediation items ordered by impact vs effort.
    .DESCRIPTION
        Quick wins are high-impact findings that can be remediated with low effort.
        Scoring: Impact = risk score, Effort = estimated effort level (1-5).
        Returns top N findings sorted by Impact/Effort ratio.
    .PARAMETER Findings
        All findings.
    .PARAMETER TopN
        Number of quick wins to return. Default: 10.
    .EXAMPLE
        $quickWins = Get-QuickWins -Findings $allFindings -TopN 5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings,

        [int]$TopN = 10
    )

    # Effort scores (1=easy, 5=hard) per rule category/type
    $effortMap = @{
        'CG-004' = 1   # Disable SMBv1 — one command
        'CG-005' = 1   # Set LM compatibility — one GPO setting
        'CG-001' = 1   # Require SMB signing — one GPO setting
        'CG-002' = 1   # Require LDAP signing — one GPO setting
        'CG-003' = 1   # LDAP channel binding — one registry key
        'CG-010' = 2   # Remove cPassword — locate and delete
        'IP-016' = 1   # Clear PasswordNotRequired — attribute change
        'IP-017' = 2   # Enable pre-auth — attribute change, may need testing
        'IP-012' = 1   # Set lockout policy — one GPO setting
        'IP-015' = 2   # PasswordNeverExpires — bulk attribute change
        'EV-030' = 1   # Disable Print Spooler on DCs — one command/GPO
        'IP-003' = 2   # Empty Schema Admins — remove members
        'PB-040' = 3   # Rogue DC — investigation needed
        'PB-020' = 3   # DCSync rights — ACL change
        'IP-021' = 2   # Disable stale privileged accounts
        'EV-010' = 1   # Zerologon enforcement — one registry key
    }

    $scored = $Findings | ForEach-Object {
        $finding    = $_
        $riskScore  = Calculate-RiskScore -Finding $finding
        $effort     = if ($effortMap.ContainsKey($finding.RuleId)) { $effortMap[$finding.RuleId] } else { 3 }
        $ratio      = $riskScore / $effort

        [PSCustomObject]@{
            RuleId           = $finding.RuleId
            Title            = $finding.Title
            Severity         = $finding.Severity
            Category         = $finding.Category
            RiskScore        = $riskScore
            EffortLevel      = $effort
            QuickWinScore    = [Math]::Round($ratio, 2)
            Remediation      = $finding.Remediation
            AffectedCount    = $finding.AffectedCount
        }
    }

    return $scored | Sort-Object -Property QuickWinScore -Descending | Select-Object -First $TopN
}

#endregion

#region Critical Paths

function Get-CriticalPaths {
    <#
    .SYNOPSIS
        Identifies critical attack paths through finding relationships.
    .DESCRIPTION
        Analyses findings to identify chains of vulnerabilities that enable
        complete domain compromise. Returns prioritised attack path scenarios.
    .PARAMETER Findings
        All findings.
    .EXAMPLE
        $paths = Get-CriticalPaths -Findings $allFindings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $findingIds = @($Findings | Select-Object -ExpandProperty RuleId)
    $paths      = [System.Collections.Generic.List[object]]::new()

    # Path 1: Kerberoasting → Privileged account compromise → Domain Admin
    if ($findingIds -contains 'IP-041' -or ($findingIds -contains 'EV-001' -and $findingIds -contains 'IP-040')) {
        $paths.Add([PSCustomObject]@{
            PathId      = 'CP-001'
            Name        = 'Kerberoasting to Domain Admin'
            Description = 'Kerberoastable privileged accounts allow offline hash cracking to gain Domain Admin credentials without requiring prior elevated access.'
            Steps       = @(
                'Request TGS for SPN-bearing privileged account (any domain user can do this)',
                'Crack RC4 hash offline using hashcat/JtR',
                'Authenticate with recovered credentials'
            )
            FindingIds  = @('IP-040','IP-041','EV-001')
            Risk        = 'Critical'
        })
    }

    # Path 2: NTLM Relay → LDAP → Immediate Domain Admin (via RBCD or DCSync)
    if ($findingIds -contains 'CG-001' -and $findingIds -contains 'CG-002') {
        $paths.Add([PSCustomObject]@{
            PathId      = 'CP-002'
            Name        = 'NTLM Relay → Instant Privilege Escalation'
            Description = 'SMB and LDAP signing both disabled. An attacker can relay NTLM authentication from any host coercion (PetitPotam/PrinterBug) to LDAP and configure RBCD or add DCSync rights.'
            Steps       = @(
                'Set up Responder + ntlmrelayx targeting LDAP',
                'Coerce DC authentication (PetitPotam, PrinterBug, DFSCoerce)',
                'Relay to LDAP: configure RBCD or add DCSync rights',
                'Use RBCD/DCSync to obtain TGT or dump credentials'
            )
            FindingIds  = @('CG-001','CG-002','EV-020')
            Risk        = 'Critical'
        })
    }

    # Path 3: AD CS ESC1 → Domain Admin impersonation
    if ($findingIds -contains 'EV-040') {
        $paths.Add([PSCustomObject]@{
            PathId      = 'CP-003'
            Name        = 'AD CS ESC1 → Impersonate Domain Admin'
            Description = 'Certificate template with enrollee-supplied SAN enables any enrolled user to obtain a certificate as any domain user, including Domain Admins.'
            Steps       = @(
                'Find vulnerable ESC1 template (any domain user can enroll)',
                'Request certificate with Domain Admin UPN as SAN',
                'Use certificate to obtain TGT via PKINIT (pass-the-cert)',
                'DCSync or direct domain admin access'
            )
            FindingIds  = @('EV-040','EV-045')
            Risk        = 'Critical'
        })
    }

    # Path 4: Unconstrained delegation → DC compromise
    if ($findingIds -contains 'IP-030' -or $findingIds -contains 'IP-031') {
        $paths.Add([PSCustomObject]@{
            PathId      = 'CP-004'
            Name        = 'Unconstrained Delegation → DC Compromise'
            Description = 'Server with unconstrained delegation can capture TGTs. Coerce DC authentication to this server and extract DC TGT from memory for Golden Ticket or DCSync.'
            Steps       = @(
                'Compromise host with unconstrained delegation',
                'Coerce DC machine account auth to this host (PrinterBug/PetitPotam)',
                'Extract DC TGT from LSASS using Rubeus monitor/dump',
                'Use DC TGT to perform DCSync'
            )
            FindingIds  = @('IP-030','IP-031')
            Risk        = 'Critical'
        })
    }

    return $paths.ToArray()
}

#endregion

#region Remediation Priority Queue

function Get-RemediationRoadmap {
    <#
    .SYNOPSIS
        Generates a prioritised remediation roadmap.
    .DESCRIPTION
        Returns findings grouped into remediation phases:
        Phase 1 (Immediate): Critical findings, especially those in attack paths
        Phase 2 (30 days): High findings
        Phase 3 (90 days): Medium findings
        Phase 4 (180 days): Low and Informational findings
    .PARAMETER Findings
        All findings.
    .EXAMPLE
        $roadmap = Get-RemediationRoadmap -Findings $allFindings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Findings
    )

    $criticalPaths = Get-CriticalPaths -Findings $Findings
    $cpFindingIds  = @($criticalPaths | ForEach-Object { $_.FindingIds } | Sort-Object -Unique)

    $phase1 = @($Findings | Where-Object { $_.Severity -eq 'Critical' -or $_.RuleId -in $cpFindingIds })
    $phase2 = @($Findings | Where-Object { $_.Severity -eq 'High'     -and $_.RuleId -notin $cpFindingIds })
    $phase3 = @($Findings | Where-Object { $_.Severity -eq 'Medium' })
    $phase4 = @($Findings | Where-Object { $_.Severity -in @('Low','Informational') })

    return [PSCustomObject]@{
        Phase1_Immediate  = [PSCustomObject]@{
            Label     = 'Phase 1 — Immediate (0-7 days)'
            Timeframe = '0-7 days'
            Count     = $phase1.Count
            Findings  = $phase1 | Sort-Object { $Script:SeverityWeights[$_.Severity] } -Descending
        }
        Phase2_ShortTerm  = [PSCustomObject]@{
            Label     = 'Phase 2 — Short Term (8-30 days)'
            Timeframe = '8-30 days'
            Count     = $phase2.Count
            Findings  = $phase2
        }
        Phase3_MediumTerm = [PSCustomObject]@{
            Label     = 'Phase 3 — Medium Term (31-90 days)'
            Timeframe = '31-90 days'
            Count     = $phase3.Count
            Findings  = $phase3
        }
        Phase4_LongTerm   = [PSCustomObject]@{
            Label     = 'Phase 4 — Long Term (91-180 days)'
            Timeframe = '91-180 days'
            Count     = $phase4.Count
            Findings  = $phase4
        }
        CriticalPaths     = $criticalPaths
    }
}

#endregion

Export-ModuleMember -Function Calculate-RiskScore, Get-OverallPostureGrade, Get-QuickWins,
                               Get-CriticalPaths, Get-RemediationRoadmap
