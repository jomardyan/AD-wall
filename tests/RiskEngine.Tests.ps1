#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for src/engine/RiskEngine.ps1
.DESCRIPTION
    Tests Calculate-RiskScore and Get-OverallPostureGrade with synthetic finding
    objects so that no Active Directory connection is required.
#>

BeforeAll {
    . "$PSScriptRoot\..\src\core\FindingHelper.ps1"
    # Suppress Export-ModuleMember error (only valid inside .psm1 modules)
    try { . "$PSScriptRoot\..\src\engine\RiskEngine.ps1" } catch [System.InvalidOperationException] { }

    # Helper: build a minimal finding with an optional AffectedCount override.
    function script:_MakeFinding {
        param(
            [string]$RuleId    = 'T-001',
            [string]$Title     = 'Test',
            [string]$Severity  = 'High',
            [int]$AffectedCount = 0,
            [string]$MitreAttack = ''
        )
        $f = New-Finding -RuleId $RuleId -Title $Title -Severity $Severity `
            -Description 'D' -AffectedObjects @() -Remediation 'R' `
            -MitreAttack $MitreAttack
        # Override AffectedCount for scoring tests
        $f | Add-Member -NotePropertyName 'AffectedCount' -NotePropertyValue $AffectedCount -Force
        return $f
    }
}

# ---------------------------------------------------------------------------
Describe 'Calculate-RiskScore' {

    It 'Returns a numeric value between 0 and 100' {
        $f = _MakeFinding -Severity 'High' -AffectedCount 10
        $score = Calculate-RiskScore -Finding $f -TotalUserCount 100
        $score | Should -BeGreaterOrEqual 0
        $score | Should -BeLessOrEqual 100
    }

    It 'Critical severity scores higher than High severity (same conditions)' {
        $crit = _MakeFinding -Severity 'Critical' -AffectedCount 5
        $high = _MakeFinding -Severity 'High'     -AffectedCount 5
        $sCrit = Calculate-RiskScore -Finding $crit -TotalUserCount 100
        $sHigh = Calculate-RiskScore -Finding $high -TotalUserCount 100
        $sCrit | Should -BeGreaterThan $sHigh
    }

    It 'High severity scores higher than Medium severity' {
        $high = _MakeFinding -Severity 'High'   -AffectedCount 5
        $med  = _MakeFinding -Severity 'Medium' -AffectedCount 5
        $sHigh = Calculate-RiskScore -Finding $high -TotalUserCount 100
        $sMed  = Calculate-RiskScore -Finding $med  -TotalUserCount 100
        $sHigh | Should -BeGreaterThan $sMed
    }

    It 'More affected objects produces a higher or equal score (same severity)' {
        $few  = _MakeFinding -Severity 'High' -AffectedCount 1
        $many = _MakeFinding -Severity 'High' -AffectedCount 50
        $sFew  = Calculate-RiskScore -Finding $few  -TotalUserCount 100
        $sMany = Calculate-RiskScore -Finding $many -TotalUserCount 100
        $sMany | Should -BeGreaterOrEqual $sFew
    }

    It 'Applies an exploitability boost for known MITRE techniques (T1003.006 DCSync)' {
        $noBoost = _MakeFinding -Severity 'Critical' -AffectedCount 5 -MitreAttack ''
        $dcsync  = _MakeFinding -Severity 'Critical' -AffectedCount 5 -MitreAttack 'T1003.006'
        $sNone   = Calculate-RiskScore -Finding $noBoost -TotalUserCount 100
        $sDCSync = Calculate-RiskScore -Finding $dcsync  -TotalUserCount 100
        $sDCSync | Should -BeGreaterThan $sNone
    }

    It 'Returns a non-zero score for an Informational severity finding' {
        $f = _MakeFinding -Severity 'Informational' -AffectedCount 0
        $score = Calculate-RiskScore -Finding $f -TotalUserCount 100
        $score | Should -BeGreaterThan 0
    }

    It 'Age factor increases score after 90 days' {
        $f = _MakeFinding -Severity 'High' -AffectedCount 5
        $sBase = Calculate-RiskScore -Finding $f -TotalUserCount 100
        $sOld  = Calculate-RiskScore -Finding $f -TotalUserCount 100 `
            -FirstSeenDate ([datetime]::UtcNow.AddDays(-100))
        $sOld | Should -BeGreaterThan $sBase
    }
}

# ---------------------------------------------------------------------------
Describe 'Get-OverallPostureGrade' {

    It 'Returns a hashtable with Score, Grade, and CriticalCount' {
        $findings = @(
            _MakeFinding -Severity 'High'   -AffectedCount 5
            _MakeFinding -Severity 'Medium' -AffectedCount 2
        )
        $result = Get-OverallPostureGrade -Findings $findings -TotalUserCount 100
        $result.PSObject.Properties['Score']         | Should -Not -BeNull
        $result.PSObject.Properties['Grade']         | Should -Not -BeNull
        $result.PSObject.Properties['CriticalCount'] | Should -Not -BeNull
    }

    It 'Grade is one of A B C D F' {
        $findings = @(_MakeFinding -Severity 'Low' -AffectedCount 1)
        $result = Get-OverallPostureGrade -Findings $findings -TotalUserCount 100
        $result.Grade | Should -BeIn @('A', 'B', 'C', 'D', 'F')
    }

    It 'Score is between 0 and 100' {
        $findings = @(_MakeFinding -Severity 'Critical' -AffectedCount 50)
        $result = Get-OverallPostureGrade -Findings $findings -TotalUserCount 100
        $result.Score | Should -BeGreaterOrEqual 0
        $result.Score | Should -BeLessOrEqual 100
    }

    It 'Returns Grade A (score 0) for no findings' {
        $result = Get-OverallPostureGrade -Findings @() -TotalUserCount 100
        $result.Grade | Should -Be 'A'
        $result.Score | Should -Be 0
    }

    It 'CriticalCount matches number of Critical findings' {
        $findings = @(
            _MakeFinding -Severity 'Critical'
            _MakeFinding -Severity 'Critical'
            _MakeFinding -Severity 'High'
        )
        $result = Get-OverallPostureGrade -Findings $findings -TotalUserCount 100
        $result.CriticalCount | Should -Be 2
    }

    It 'Many Critical findings produce a worse grade than no findings' {
        $many = @(1..10 | ForEach-Object { _MakeFinding -Severity 'Critical' -AffectedCount 20 })
        $rMany = Get-OverallPostureGrade -Findings $many  -TotalUserCount 100
        $rNone = Get-OverallPostureGrade -Findings @()    -TotalUserCount 100
        $rMany.Score | Should -BeGreaterThan $rNone.Score
    }
}
