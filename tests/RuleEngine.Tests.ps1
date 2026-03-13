#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for src/engine/RuleEngine.ps1
.DESCRIPTION
    Tests Get-RuleCatalog, Test-Rule, Invoke-FindingEnrichment, and
    Invoke-FindingDeduplication using synthetic finding objects so that
    no Active Directory connection is required.
#>

BeforeAll {
    # Load the shared finding factory first (Invoke-FindingEnrichment relies on it)
    . "$PSScriptRoot\..\src\core\FindingHelper.ps1"
    # Load the rule engine; suppress Export-ModuleMember error (only valid inside .psm1 modules)
    try { . "$PSScriptRoot\..\src\engine\RuleEngine.ps1" } catch [System.InvalidOperationException] { }

    # Helper: build a minimal finding object for use in tests.
    # Defined inside BeforeAll so it is available in all child blocks under Pester 5.
    function script:_MakeFinding {
        param([string]$RuleId, [string]$Title = 'Test', [string]$Severity = 'High')
        New-Finding -RuleId $RuleId -Title $Title -Severity $Severity `
            -Description 'Test finding' -AffectedObjects @() -Remediation 'Test remediation'
    }
}

# ---------------------------------------------------------------------------
Describe 'Get-RuleCatalog' {

    It 'Returns at least 80 rules (sanity check)' {
        $rules = Get-RuleCatalog
        $rules.Count | Should -BeGreaterThan 80
    }

    It 'Each rule has RuleId, Category, Severity, and Enabled fields' {
        $rules = Get-RuleCatalog
        foreach ($rule in $rules) {
            $rule.RuleId   | Should -Not -BeNullOrEmpty
            $rule.Category | Should -Not -BeNullOrEmpty
            $rule.Severity | Should -Not -BeNullOrEmpty
            $rule.PSObject.Properties['Enabled'] | Should -Not -BeNull
        }
    }

    It 'Filters by Category (case-insensitive partial match)' {
        $rules = Get-RuleCatalog -Category 'Identity'
        $rules | Should -Not -BeNullOrEmpty
        $rules | ForEach-Object { $_.Category | Should -BeLike '*Identity*' }
    }

    It 'Filters by Severity' {
        $criticals = Get-RuleCatalog -Severity 'Critical'
        $criticals | Should -Not -BeNullOrEmpty
        $criticals | ForEach-Object { $_.Severity | Should -Be 'Critical' }
    }

    It 'Returns nothing when filter matches no rules' {
        $none = Get-RuleCatalog -Category 'NonExistentCategory12345'
        $none | Should -BeNullOrEmpty
    }
}

# ---------------------------------------------------------------------------
Describe 'Test-Rule' {

    It 'Returns $true for a known enabled rule' {
        # IP-001 is defined in the catalog and Enabled=$true
        Test-Rule -RuleId 'IP-001' | Should -Be $true
    }

    It 'Returns $false for an unknown rule ID' {
        Test-Rule -RuleId 'ZZ-999-UNKNOWN' | Should -Be $false
    }
}

# ---------------------------------------------------------------------------
Describe 'Invoke-FindingEnrichment' {

    It 'Adds RuleName for a known RuleId' {
        $findings = @(_MakeFinding 'IP-001' 'Excessive DA membership' 'High')
        $enriched = Invoke-FindingEnrichment -Findings $findings
        $enriched[0].RuleName | Should -Not -BeNullOrEmpty
    }

    It 'Adds RuleEnabled for a known RuleId' {
        $findings = @(_MakeFinding 'IP-001')
        $enriched = Invoke-FindingEnrichment -Findings $findings
        $enriched[0].PSObject.Properties['RuleEnabled'] | Should -Not -BeNull
    }

    It 'Sets Category from the rule catalog (overwriting empty default)' {
        # New-Finding sets Category = '' by default; enrichment must fix it.
        $findings = @(_MakeFinding 'IP-001')
        $findings[0].Category | Should -Be ''   # pre-enrichment

        $enriched = Invoke-FindingEnrichment -Findings $findings
        $enriched[0].Category | Should -Not -BeNullOrEmpty
        $enriched[0].Category | Should -Be 'Identity & Privilege'
    }

    It 'Adds VerificationCommand (may be empty) for each finding' {
        $findings = @(_MakeFinding 'IP-001')
        $enriched = Invoke-FindingEnrichment -Findings $findings
        $enriched[0].PSObject.Properties['VerificationCommand'] | Should -Not -BeNull
    }

    It 'Handles findings with an unknown RuleId without throwing' {
        $findings = @(_MakeFinding 'ZZ-999-UNKNOWN')
        { Invoke-FindingEnrichment -Findings $findings } | Should -Not -Throw
    }

    It 'Returns the same number of findings it received' {
        $findings = @(
            _MakeFinding 'IP-001'
            _MakeFinding 'CG-001'
            _MakeFinding 'PB-020'
        )
        $enriched = Invoke-FindingEnrichment -Findings $findings
        $enriched.Count | Should -Be 3
    }
}

# ---------------------------------------------------------------------------
Describe 'Invoke-FindingDeduplication' {

    It 'Returns all findings when there are no duplicates' {
        $findings = @(
            _MakeFinding 'IP-001' 'Finding A'
            _MakeFinding 'CG-001' 'Finding B'
        )
        $deduped = Invoke-FindingDeduplication -Findings $findings
        $deduped.Count | Should -Be 2
    }

    It 'Removes duplicate RuleId+Title pairs, keeping the most recent' {
        # Create two findings with the same RuleId and Title, different times
        $older  = _MakeFinding 'IP-001' 'Same Title'
        $older  | Add-Member -NotePropertyName 'DetectedAt' `
            -NotePropertyValue '2024-01-01T00:00:00.0000000Z' -Force
        $newer  = _MakeFinding 'IP-001' 'Same Title'
        $newer  | Add-Member -NotePropertyName 'DetectedAt' `
            -NotePropertyValue '2024-06-01T00:00:00.0000000Z' -Force

        $deduped = Invoke-FindingDeduplication -Findings @($older, $newer)
        $deduped | Should -HaveCount 1
        # The newer finding (higher timestamp) should be retained
        $deduped[0].DetectedAt | Should -Be '2024-06-01T00:00:00.0000000Z'
    }

    It 'Treats findings with same RuleId but different Titles as distinct' {
        $a = _MakeFinding 'IP-001' 'Title One'
        $b = _MakeFinding 'IP-001' 'Title Two'
        $deduped = Invoke-FindingDeduplication -Findings @($a, $b)
        $deduped | Should -HaveCount 2
    }

    It 'Returns an empty array for empty input' {
        $deduped = Invoke-FindingDeduplication -Findings @()
        $deduped | Should -HaveCount 0
    }
}
