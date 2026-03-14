#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for src/core/FindingHelper.ps1
.DESCRIPTION
    Validates that New-Finding and New-ATKFinding produce correctly structured
    finding objects with expected properties and values.
#>

BeforeAll {
    # Dot-source the helper under test
    . "$PSScriptRoot\..\src\core\FindingHelper.ps1"
}

Describe 'New-Finding' {

    Context 'Required fields are set correctly' {

        It 'Returns a PSCustomObject' {
            $f = New-Finding -RuleId 'T-001' -Title 'Test finding' -Severity 'High' `
                -Description 'A test description.' `
                -AffectedObjects @('obj1') `
                -Remediation 'Fix it.'
            $f | Should -BeOfType [PSCustomObject]
        }

        It 'Sets RuleId correctly' {
            $f = New-Finding -RuleId 'IP-001' -Title 'T' -Severity 'High' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.RuleId | Should -Be 'IP-001'
        }

        It 'Sets Title correctly' {
            $f = New-Finding -RuleId 'X-001' -Title 'My Title' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.Title | Should -Be 'My Title'
        }

        It 'Sets Severity correctly' {
            foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
                $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity $sev `
                    -Description 'D' -AffectedObjects @() -Remediation 'R'
                $f.Severity | Should -Be $sev
            }
        }

        It 'Sets Description correctly' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Medium' `
                -Description 'My description text.' -AffectedObjects @() -Remediation 'R'
            $f.Description | Should -Be 'My description text.'
        }

        It 'Sets Remediation correctly' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'Run this command.'
            $f.Remediation | Should -Be 'Run this command.'
        }

        It 'Populates DetectedAt as a valid ISO 8601 datetime string' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            { [datetime]::Parse($f.DetectedAt) } | Should -Not -Throw
        }
    }

    Context 'AffectedObjects and AffectedCount' {

        It 'Sets AffectedObjects and AffectedCount when objects are provided' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'High' `
                -Description 'D' -AffectedObjects @('user1', 'user2') -Remediation 'R'
            $f.AffectedObjects | Should -HaveCount 2
            $f.AffectedCount   | Should -Be 2
        }

        It 'Returns AffectedCount 0 for an empty array' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.AffectedCount | Should -Be 0
        }

        It 'Filters null entries from AffectedObjects' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @('user1', $null, 'user2', '') `
                -Remediation 'R'
            # null and empty-string should be removed
            $f.AffectedObjects | Should -Not -Contain $null
            $f.AffectedCount | Should -Be 2
        }
    }

    Context 'Optional compliance / vulnerability fields' {

        It 'Defaults Category to empty string' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.Category | Should -Be ''
        }

        It 'Accepts and returns a custom Category' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Category 'Identity & Privilege' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.Category | Should -Be 'Identity & Privilege'
        }

        It 'Defaults MitreAttack to empty string' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.MitreAttack | Should -Be ''
        }

        It 'Stores CISControl when provided' {
            $f = New-Finding -RuleId 'COMP-001' -Title 'T' -Severity 'High' `
                -Description 'D' -AffectedObjects @() -Remediation 'R' `
                -CISControl 'CIS-AD-1.1.1'
            $f.CISControl | Should -Be 'CIS-AD-1.1.1'
        }

        It 'Stores NISTControl when provided' {
            $f = New-Finding -RuleId 'COMP-001' -Title 'T' -Severity 'High' `
                -Description 'D' -AffectedObjects @() -Remediation 'R' `
                -NISTControl 'IA-5(1)'
            $f.NISTControl | Should -Be 'IA-5(1)'
        }

        It 'Defaults CISControl and NISTControl to empty string' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.CISControl  | Should -Be ''
            $f.NISTControl | Should -Be ''
        }

        It 'Stores CVEReferences array when provided' {
            $cves = @('CVE-2020-1472', 'CVE-2021-42278')
            $f = New-Finding -RuleId 'EV-010' -Title 'T' -Severity 'Critical' `
                -Description 'D' -AffectedObjects @() -Remediation 'R' `
                -CVEReferences $cves
            $f.CVEReferences | Should -Be $cves
        }

        It 'Defaults CVEReferences to an empty array' {
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.CVEReferences | Should -HaveCount 0
        }

        It 'Stores ExtraData hashtable when provided' {
            $extra = @{ Key = 'Value'; Num = 42 }
            $f = New-Finding -RuleId 'X-001' -Title 'T' -Severity 'Low' `
                -Description 'D' -AffectedObjects @() -Remediation 'R' `
                -ExtraData $extra
            $f.ExtraData.Key | Should -Be 'Value'
            $f.ExtraData.Num | Should -Be 42
        }
    }

    Context 'Severity validation' {

        It 'Throws for an invalid Severity value' {
            { New-Finding -RuleId 'X-001' -Title 'T' -Severity 'SuperCritical' `
                -Description 'D' -AffectedObjects @() -Remediation 'R' } |
                Should -Throw
        }
    }
}

Describe 'New-ATKFinding' {

    Context 'Category is always Attack Techniques' {

        It 'Returns a PSCustomObject' {
            $f = New-ATKFinding -RuleId 'ATK-001' -Title 'T' -Severity 'Critical' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f | Should -BeOfType [PSCustomObject]
        }

        It 'Sets Category to Attack Techniques regardless of caller' {
            $f = New-ATKFinding -RuleId 'ATK-001' -Title 'T' -Severity 'High' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.Category | Should -Be 'Attack Techniques'
        }

        It 'Passes RuleId through correctly' {
            $f = New-ATKFinding -RuleId 'ATK-007' -Title 'T' -Severity 'Critical' `
                -Description 'D' -AffectedObjects @() -Remediation 'R'
            $f.RuleId | Should -Be 'ATK-007'
        }

        It 'Passes MitreAttack through correctly' {
            $f = New-ATKFinding -RuleId 'ATK-001' -Title 'T' -Severity 'High' `
                -Description 'D' -AffectedObjects @() -Remediation 'R' `
                -MitreAttack 'T1110.003'
            $f.MitreAttack | Should -Be 'T1110.003'
        }

        It 'Filters null entries from AffectedObjects' {
            $f = New-ATKFinding -RuleId 'ATK-002' -Title 'T' -Severity 'High' `
                -Description 'D' -AffectedObjects @('host1', $null) -Remediation 'R'
            $f.AffectedObjects | Should -Not -Contain $null
            $f.AffectedCount   | Should -Be 1
        }
    }
}
