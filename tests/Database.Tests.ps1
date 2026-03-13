#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for src/core/Database.ps1
.DESCRIPTION
    Tests Initialize-ADWallDatabase, Save-Finding, Get-Findings, Save-Snapshot,
    Get-Snapshots, and Compare-Snapshots using a temporary directory so that no
    persistent state is written to the repository.
#>

BeforeAll {
    . "$PSScriptRoot\..\src\core\FindingHelper.ps1"
    # Suppress Export-ModuleMember error (only valid inside .psm1 modules)
    try { . "$PSScriptRoot\..\src\core\Database.ps1" } catch [System.InvalidOperationException] { }

    # Each test run uses a fresh temp directory to avoid cross-test pollution.
    $script:TempDbPath = Join-Path ([System.IO.Path]::GetTempPath()) "ADWallTest_$(Get-Random)"
    Initialize-ADWallDatabase -OutputPath $script:TempDbPath

    function script:_MakeFinding {
        param([string]$RuleId = 'T-001', [string]$Severity = 'High', [string]$Title = 'Test finding')
        New-Finding -RuleId $RuleId -Title $Title -Severity $Severity `
            -Description 'Test description' -AffectedObjects @('obj1') `
            -Remediation 'Test remediation'
    }
}

AfterAll {
    if ($script:TempDbPath -and (Test-Path $script:TempDbPath)) {
        Remove-Item -Path $script:TempDbPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
Describe 'Initialize-ADWallDatabase' {

    It 'Creates the db/findings directory' {
        Test-Path (Join-Path $script:TempDbPath 'db\findings') | Should -Be $true
    }

    It 'Creates the db/snapshots directory' {
        Test-Path (Join-Path $script:TempDbPath 'db\snapshots') | Should -Be $true
    }

    It 'Creates the index.json file' {
        Test-Path (Join-Path $script:TempDbPath 'db\index.json') | Should -Be $true
    }

    It 'Is idempotent (calling twice does not throw)' {
        { Initialize-ADWallDatabase -OutputPath $script:TempDbPath } | Should -Not -Throw
    }
}

# ---------------------------------------------------------------------------
Describe 'Save-Finding and Get-Findings' {

    It 'Saves a single finding without error' {
        $f = _MakeFinding -RuleId 'IP-001' -Severity 'High' -Title 'Save test'
        { Save-Finding -Findings @($f) -RunId 'RUN-SAVE-001' -Domain 'corp.local' } |
            Should -Not -Throw
    }

    It 'Retrieves a saved finding by RunId' {
        $f = _MakeFinding -RuleId 'IP-002' -Severity 'Critical' -Title 'Retrieve test'
        Save-Finding -Findings @($f) -RunId 'RUN-RETR-001' -Domain 'corp.local'

        $loaded = Get-Findings -RunId 'RUN-RETR-001'
        $loaded | Should -Not -BeNullOrEmpty
        ($loaded | Where-Object { $_.RuleId -eq 'IP-002' }) | Should -Not -BeNull
    }

    It 'Retrieves findings via the pipeline' {
        $f = _MakeFinding -RuleId 'CG-001' -Severity 'High' -Title 'Pipeline test'
        $f | Save-Finding -RunId 'RUN-PIPE-001' -Domain 'corp.local'

        $loaded = Get-Findings -RunId 'RUN-PIPE-001'
        ($loaded | Where-Object { $_.RuleId -eq 'CG-001' }) | Should -Not -BeNull
    }

    It 'Returns nothing (or empty) for an unknown RunId' {
        $loaded = Get-Findings -RunId 'RUN-DOES-NOT-EXIST-XYZ'
        $loaded | Should -BeNullOrEmpty
    }

    It 'Stores multiple findings in a single run' {
        $f1 = _MakeFinding 'T-F1' 'High' 'Finding 1'
        $f2 = _MakeFinding 'T-F2' 'Medium' 'Finding 2'
        Save-Finding -Findings @($f1, $f2) -RunId 'RUN-MULTI-001' -Domain 'corp.local'

        $loaded = Get-Findings -RunId 'RUN-MULTI-001'
        $loaded | Should -HaveCount 2
    }
}

# ---------------------------------------------------------------------------
Describe 'Save-Snapshot and Get-Snapshots' {

    It 'Saves a snapshot without error' {
        $data = @{
            Users = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local'; Enabled = $true }
            )
        }
        { Save-Snapshot -SnapshotData $data -Label 'baseline' -Domain 'corp.local' } |
            Should -Not -Throw
    }

    It 'Retrieves the snapshot list' {
        $snapshots = Get-Snapshots
        $snapshots | Should -Not -BeNull
    }

    It 'Retrieves a specific snapshot by ID' {
        $data = @{ Groups = @([PSCustomObject]@{ DistinguishedName = 'CN=DA,DC=corp,DC=local' }) }
        $snapId = Save-Snapshot -SnapshotData $data -Label 'snap-retrieve-test' -Domain 'corp.local'

        $loaded = Get-Snapshots -SnapshotId $snapId
        $loaded | Should -Not -BeNull
    }
}

# ---------------------------------------------------------------------------
Describe 'Compare-Snapshots' {

    It 'Detects a newly added object' {
        $base = @{
            Users = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local'; Enabled = $true }
            )
        }
        $curr = @{
            Users = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local'; Enabled = $true }
                [PSCustomObject]@{ DistinguishedName = 'CN=Bob,DC=corp,DC=local';   Enabled = $true }
            )
        }

        $baseId = Save-Snapshot -SnapshotData $base -Label 'drift-base' -Domain 'corp.local'
        Start-Sleep -Milliseconds 1100   # ensure distinct second-precision IDs
        $currId = Save-Snapshot -SnapshotData $curr -Label 'drift-curr' -Domain 'corp.local'

        $report = Compare-Snapshots -BaselineId $baseId -CurrentId $currId
        $report.TotalAdded | Should -Be 1
        $report.TotalRemoved | Should -Be 0
    }

    It 'Detects a removed object' {
        $base = @{
            Users = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local' }
                [PSCustomObject]@{ DistinguishedName = 'CN=Bob,DC=corp,DC=local' }
            )
        }
        $curr = @{
            Users = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local' }
            )
        }

        $baseId = Save-Snapshot -SnapshotData $base -Label 'rem-base' -Domain 'corp.local'
        Start-Sleep -Milliseconds 1100
        $currId = Save-Snapshot -SnapshotData $curr -Label 'rem-curr' -Domain 'corp.local'

        $report = Compare-Snapshots -BaselineId $baseId -CurrentId $currId
        $report.TotalRemoved | Should -Be 1
    }

    It 'Detects a modified property value' {
        $base = @{
            Users = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local'; Enabled = $true }
            )
        }
        $curr = @{
            Users = @(
                [PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local'; Enabled = $false }
            )
        }

        $baseId = Save-Snapshot -SnapshotData $base -Label 'mod-base' -Domain 'corp.local'
        Start-Sleep -Milliseconds 1100
        $currId = Save-Snapshot -SnapshotData $curr -Label 'mod-curr' -Domain 'corp.local'

        $report = Compare-Snapshots -BaselineId $baseId -CurrentId $currId
        $report.TotalModified | Should -Be 1
    }

    It 'Reports zero drift when snapshots are identical' {
        $data = @{
            Users = @([PSCustomObject]@{ DistinguishedName = 'CN=Alice,DC=corp,DC=local' })
        }
        $id1 = Save-Snapshot -SnapshotData $data -Label 'same-snap1' -Domain 'corp.local'
        Start-Sleep -Milliseconds 1100
        $id2 = Save-Snapshot -SnapshotData $data -Label 'same-snap2' -Domain 'corp.local'

        $report = Compare-Snapshots -BaselineId $id1 -CurrentId $id2
        $report.TotalAdded    | Should -Be 0
        $report.TotalRemoved  | Should -Be 0
        $report.TotalModified | Should -Be 0
    }
}
