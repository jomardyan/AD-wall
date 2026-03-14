#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Data Persistence Module (JSON-based Evidence Store)
.DESCRIPTION
    Provides a lightweight, file-based data store for AD-Wall findings, snapshots, and
    drift detection. Uses JSON files organized in a structured directory layout.
    Designed to be portable and require no external database dependencies.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0

    Directory layout under the output path:
        <OutputPath>/
            db/
                findings/          # One JSON file per scan run
                snapshots/         # Point-in-time snapshots for drift detection
                index.json         # Index of all runs and snapshots
#>

Set-StrictMode -Version Latest

#region Module State

$Script:DbPath     = $null
$Script:IndexPath  = $null
$Script:DbIndex    = $null

#endregion

#region Initialization

function Initialize-ADWallDatabase {
    <#
    .SYNOPSIS
        Initializes the JSON-based evidence store directory structure.
    .DESCRIPTION
        Creates the necessary folder layout and index file. Idempotent — safe to call
        multiple times.
    .PARAMETER OutputPath
        Root output directory for AD-Wall results. Default: .\ADWall-Output
    .EXAMPLE
        Initialize-ADWallDatabase -OutputPath C:\ADWall\Results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = '.\ADWall-Output'
    )

    try {
        $Script:DbPath = Join-Path $OutputPath 'db'
        $findingsDir   = Join-Path $Script:DbPath 'findings'
        $snapshotsDir  = Join-Path $Script:DbPath 'snapshots'

        foreach ($dir in @($Script:DbPath, $findingsDir, $snapshotsDir)) {
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Write-Verbose "Created directory: $dir"
            }
        }

        $Script:IndexPath = Join-Path $Script:DbPath 'index.json'
        if (-not (Test-Path $Script:IndexPath)) {
            $Script:DbIndex = [ordered]@{
                Version   = '1.0'
                Created   = (Get-Date -Format 'o')
                Runs      = [System.Collections.Generic.List[object]]::new()
                Snapshots = [System.Collections.Generic.List[object]]::new()
            }
            Save-DbIndex
        }
        else {
            $Script:DbIndex = Get-Content $Script:IndexPath -Raw | ConvertFrom-Json -AsHashtable
            # ConvertFrom-Json deserialises arrays as fixed-size PowerShell arrays.
            # Always re-wrap as a generic list so that .Add() works at runtime.
            # Using explicit if-statements for PS5.1 compatibility (the ?? operator
            # and $(if ...) sub-expressions are not available in Windows PS 5.1).
            if ($null -eq $Script:DbIndex.Runs)      { $Script:DbIndex.Runs      = @() }
            if ($null -eq $Script:DbIndex.Snapshots) { $Script:DbIndex.Snapshots = @() }
            $Script:DbIndex.Runs      = [System.Collections.Generic.List[object]]::new(
                [object[]]$Script:DbIndex.Runs)
            $Script:DbIndex.Snapshots = [System.Collections.Generic.List[object]]::new(
                [object[]]$Script:DbIndex.Snapshots)
        }

        Write-Verbose "Database initialized at: $Script:DbPath"
        return [PSCustomObject]@{ Success = $true; Path = $Script:DbPath }
    }
    catch {
        Write-Error "Failed to initialize database: $_"
        return [PSCustomObject]@{ Success = $false; Path = $null }
    }
}

#endregion

#region Findings

function Save-Finding {
    <#
    .SYNOPSIS
        Saves one or more findings to the evidence store.
    .DESCRIPTION
        Appends findings to the current run's findings file. If no run ID is provided,
        a new run is created. Each finding is stamped with a RunId and timestamp.
    .PARAMETER Findings
        Array of finding objects to persist.
    .PARAMETER RunId
        Identifier for the current scan run. Auto-generated if not specified.
    .PARAMETER Domain
        Domain name associated with this run.
    .EXAMPLE
        Save-Finding -Findings $myFindings -RunId '20240101-120000' -Domain 'corp.local'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$Findings,

        [Parameter(Mandatory = $false)]
        [string]$RunId,

        [Parameter(Mandatory = $false)]
        [string]$Domain = 'Unknown'
    )

    begin {
        Ensure-Initialized
        if ([string]::IsNullOrEmpty($RunId)) {
            $RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
        }
        $allFindings = [System.Collections.Generic.List[object]]::new()
        $findingsFile = Join-Path $Script:DbPath "findings\$RunId.json"
    }

    process {
        foreach ($finding in $Findings) {
            $finding | Add-Member -NotePropertyName 'RunId'     -NotePropertyValue $RunId -Force
            $finding | Add-Member -NotePropertyName 'Timestamp' -NotePropertyValue (Get-Date -Format 'o') -Force
            $allFindings.Add($finding)
        }
    }

    end {
        try {
            $existing = [System.Collections.Generic.List[object]]::new()
            if (Test-Path $findingsFile) {
                $raw = Get-Content $findingsFile -Raw | ConvertFrom-Json
                if ($raw) { $raw | ForEach-Object { $existing.Add($_) } }
            }
            foreach ($f in $allFindings) { $existing.Add($f) }

            $existing | ConvertTo-Json -Depth 15 | Set-Content -Path $findingsFile -Encoding UTF8

            # Update index
            $runEntry = $Script:DbIndex.Runs | Where-Object { $_.RunId -eq $RunId } | Select-Object -First 1
            if ($null -eq $runEntry) {
                $newEntry = @{
                    RunId   = $RunId
                    Domain  = $Domain
                    Created = (Get-Date -Format 'o')
                    File    = "findings\$RunId.json"
                    Count   = $existing.Count
                }
                $Script:DbIndex.Runs.Add($newEntry)
            }
            else {
                $runEntry.Count = $existing.Count
            }
            Save-DbIndex
            Write-Verbose "Saved $($allFindings.Count) findings to run $RunId (total: $($existing.Count))."
        }
        catch {
            Write-Error "Failed to save findings: $_"
        }
    }
}

function Get-Findings {
    <#
    .SYNOPSIS
        Retrieves findings from the evidence store.
    .DESCRIPTION
        Returns findings filtered by run ID, severity, category, or domain.
        If no RunId is specified, returns findings from the most recent run.
    .PARAMETER RunId
        Specific run ID to load. Defaults to the latest run.
    .PARAMETER Severity
        Filter by severity: Critical | High | Medium | Low | Informational
    .PARAMETER Category
        Filter by finding category.
    .PARAMETER Domain
        Filter by domain name.
    .EXAMPLE
        Get-Findings
        Get-Findings -RunId '20240101-120000' -Severity 'Critical'
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$RunId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity,

        [Parameter(Mandatory = $false)]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string]$Domain
    )

    Ensure-Initialized

    try {
        if ([string]::IsNullOrEmpty($RunId)) {
            $latest = $Script:DbIndex.Runs | Select-Object -Last 1
            if ($null -eq $latest) { return @() }
            $RunId = $latest.RunId
        }

        $findingsFile = Join-Path $Script:DbPath "findings\$RunId.json"
        if (-not (Test-Path $findingsFile)) {
            Write-Warning "No findings file found for run: $RunId"
            return @()
        }

        $findings = Get-Content $findingsFile -Raw | ConvertFrom-Json

        if ($PSBoundParameters.ContainsKey('Severity')) {
            $findings = $findings | Where-Object { $_.Severity -eq $Severity }
        }
        if ($PSBoundParameters.ContainsKey('Category')) {
            $findings = $findings | Where-Object { $_.Category -like "*$Category*" }
        }
        if ($PSBoundParameters.ContainsKey('Domain')) {
            $findings = $findings | Where-Object { $_.Domain -like "*$Domain*" }
        }

        return $findings
    }
    catch {
        Write-Error "Failed to retrieve findings: $_"
        return @()
    }
}

function Get-RunHistory {
    <#
    .SYNOPSIS
        Returns the list of all scan runs stored in the index.
    #>
    [CmdletBinding()]
    param()
    Ensure-Initialized
    return $Script:DbIndex.Runs
}

#endregion

#region Snapshots & Drift Detection

function Save-Snapshot {
    <#
    .SYNOPSIS
        Saves a point-in-time AD state snapshot for drift detection.
    .DESCRIPTION
        Serializes a collection of AD objects (users, groups, GPOs, etc.) to a timestamped
        JSON snapshot file. Snapshots can later be compared to detect configuration drift.
    .PARAMETER SnapshotData
        Hashtable containing categorized AD objects (e.g., Users, Groups, GPOs).
    .PARAMETER Label
        Human-readable label for this snapshot (e.g., 'pre-change', 'baseline').
    .PARAMETER Domain
        Domain name for this snapshot.
    .EXAMPLE
        Save-Snapshot -SnapshotData $adObjects -Label 'baseline' -Domain 'corp.local'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$SnapshotData,

        [Parameter(Mandatory = $false)]
        [string]$Label = '',

        [Parameter(Mandatory = $false)]
        [string]$Domain = 'Unknown'
    )

    Ensure-Initialized

    try {
        # Include milliseconds (fff) so rapid calls in tests produce distinct IDs
        # without callers needing to sleep between snapshots.
        $snapshotId   = Get-Date -Format 'yyyyMMdd-HHmmssfff'
        $snapshotFile = Join-Path $Script:DbPath "snapshots\$snapshotId.json"

        $snapshot = @{
            SnapshotId  = $snapshotId
            Label       = $Label
            Domain      = $Domain
            CreatedAt   = (Get-Date -Format 'o')
            Data        = $SnapshotData
        }

        $snapshot | ConvertTo-Json -Depth 20 | Set-Content -Path $snapshotFile -Encoding UTF8

        $indexEntry = @{
            SnapshotId = $snapshotId
            Label      = $Label
            Domain     = $Domain
            Created    = (Get-Date -Format 'o')
            File       = "snapshots\$snapshotId.json"
        }
        $Script:DbIndex.Snapshots.Add($indexEntry)
        Save-DbIndex

        Write-Verbose "Snapshot '$snapshotId' saved (Label: '$Label')."
        return $snapshotId
    }
    catch {
        Write-Error "Failed to save snapshot: $_"
        return $null
    }
}

function Get-Snapshots {
    <#
    .SYNOPSIS
        Returns the list of saved snapshots or loads a specific snapshot.
    .PARAMETER SnapshotId
        If specified, loads and returns the full snapshot data for that ID.
    .EXAMPLE
        Get-Snapshots
        Get-Snapshots -SnapshotId '20240101-120000'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SnapshotId
    )

    Ensure-Initialized

    if ([string]::IsNullOrEmpty($SnapshotId)) {
        return $Script:DbIndex.Snapshots
    }

    $snapshotFile = Join-Path $Script:DbPath "snapshots\$SnapshotId.json"
    if (-not (Test-Path $snapshotFile)) {
        Write-Warning "Snapshot not found: $SnapshotId"
        return $null
    }

    return Get-Content $snapshotFile -Raw | ConvertFrom-Json
}

function Compare-Snapshots {
    <#
    .SYNOPSIS
        Compares two AD snapshots to detect configuration drift.
    .DESCRIPTION
        Performs a deep diff of two snapshots, identifying added, removed, and modified
        objects in each tracked category (Users, Groups, GPOs, etc.).
    .PARAMETER BaselineId
        Snapshot ID of the baseline (earlier) snapshot.
    .PARAMETER CurrentId
        Snapshot ID of the current (later) snapshot. Defaults to the most recent snapshot.
    .EXAMPLE
        Compare-Snapshots -BaselineId '20240101-120000' -CurrentId '20240115-090000'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselineId,

        [Parameter(Mandatory = $false)]
        [string]$CurrentId
    )

    Ensure-Initialized

    if ([string]::IsNullOrEmpty($CurrentId)) {
        $latest = $Script:DbIndex.Snapshots | Select-Object -Last 1
        if ($null -eq $latest) { Write-Error "No snapshots available."; return $null }
        $CurrentId = $latest.SnapshotId
    }

    $baseline = Get-Snapshots -SnapshotId $BaselineId
    $current  = Get-Snapshots -SnapshotId $CurrentId

    if ($null -eq $baseline) { Write-Error "Baseline snapshot '$BaselineId' not found."; return $null }
    if ($null -eq $current)  { Write-Error "Current snapshot '$CurrentId' not found.";  return $null }

    $driftReport = [PSCustomObject]@{
        BaselineId   = $BaselineId
        CurrentId    = $CurrentId
        BaselineDate = $baseline.CreatedAt
        CurrentDate  = $current.CreatedAt
        Domain       = $current.Domain
        Categories   = [System.Collections.Generic.List[object]]::new()
        TotalAdded   = 0
        TotalRemoved = 0
        TotalModified = 0
        GeneratedAt  = (Get-Date -Format 'o')
    }

    $baseData = $baseline.Data
    $currData = $current.Data

    # Build the union of all category names so categories present in only one
    # snapshot (i.e. completely new or fully removed object types) are included.
    $allCategories = @($baseData.PSObject.Properties.Name) + @($currData.PSObject.Properties.Name) | Sort-Object -Unique

    foreach ($category in $allCategories) {
        # Use DistinguishedName as the stable primary key for each AD object.
        $baseItems = if ($baseData.PSObject.Properties[$category]) { @($baseData.$category) } else { @() }
        $currItems = if ($currData.PSObject.Properties[$category]) { @($currData.$category) } else { @() }

        $baseKeys = $baseItems | ForEach-Object { "$($_.DistinguishedName)" }
        $currKeys = $currItems | ForEach-Object { "$($_.DistinguishedName)" }

        # Added: present in current but absent from baseline (DN not in baseline key set).
        $added   = $currItems | Where-Object { $_.DistinguishedName -notin $baseKeys }
        # Removed: present in baseline but absent from current (DN not in current key set).
        $removed = $baseItems | Where-Object { $_.DistinguishedName -notin $currKeys }

        # Modified: DN exists in both snapshots but one or more property values differ.
        $modified = [System.Collections.Generic.List[object]]::new()
        foreach ($curr in $currItems) {
            $base = $baseItems | Where-Object { $_.DistinguishedName -eq $curr.DistinguishedName } | Select-Object -First 1
            if ($null -ne $base) {
                $changes = Compare-ObjectProperties -Base $base -Current $curr
                # Guard against $null: PowerShell flattens an empty array returned from
                # a function into $null, so we check for null before accessing .Count.
                if (($null -ne $changes) -and (@($changes).Count -gt 0)) {
                    $modified.Add([PSCustomObject]@{
                        DistinguishedName = $curr.DistinguishedName
                        Changes           = $changes
                    })
                }
            }
        }

        $categoryDrift = [PSCustomObject]@{
            Category  = $category
            Added     = @($added)
            Removed   = @($removed)
            Modified  = $modified.ToArray()
            AddedCount   = @($added).Count
            RemovedCount = @($removed).Count
            ModifiedCount = $modified.Count
        }

        $driftReport.Categories.Add($categoryDrift)
        $driftReport.TotalAdded    += $categoryDrift.AddedCount
        $driftReport.TotalRemoved  += $categoryDrift.RemovedCount
        $driftReport.TotalModified += $categoryDrift.ModifiedCount
    }

    Write-Verbose ("Drift analysis complete. Added: {0}, Removed: {1}, Modified: {2}" -f
        $driftReport.TotalAdded, $driftReport.TotalRemoved, $driftReport.TotalModified)

    return $driftReport
}

#endregion

#region Private Helpers

function Ensure-Initialized {
    if ($null -eq $Script:DbPath) {
        Write-Verbose "Database not initialized; initializing with default path."
        Initialize-ADWallDatabase | Out-Null
    }
}

function Save-DbIndex {
    try {
        $Script:DbIndex | ConvertTo-Json -Depth 10 | Set-Content -Path $Script:IndexPath -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to save database index: $_"
    }
}

function Compare-ObjectProperties {
    <#
    .SYNOPSIS
        Deep-compares two PSCustomObjects and returns a list of changed properties.
    .DESCRIPTION
        Iterates over the union of all property names from both objects and serialises
        each value to a compact JSON string so that nested collections (arrays,
        hashtables) are compared by value rather than by object reference.  Only
        properties whose serialised representations differ are included in the output.
    .PARAMETER Base
        The earlier (baseline) object.
    .PARAMETER Current
        The later (current) object.
    .OUTPUTS
        Array of [PSCustomObject] records with Property, OldValue, and NewValue fields.
        Returns an empty array when objects are identical.  Note: PowerShell may collapse
        the output to $null when there are zero results; callers should wrap the result
        in @() when they need a guaranteed array (e.g. @($changes).Count).
    #>
    param($Base, $Current)

    $changes = [System.Collections.Generic.List[object]]::new()

    # Build the union of all property names from both snapshots so that
    # newly added or removed properties are also detected as changes.
    $props = @($Current.PSObject.Properties.Name) + @($Base.PSObject.Properties.Name) | Sort-Object -Unique

    foreach ($prop in $props) {
        $baseVal = if ($Base.PSObject.Properties[$prop])    { $Base.$prop }    else { $null }
        $currVal = if ($Current.PSObject.Properties[$prop]) { $Current.$prop } else { $null }

        # Serialise to JSON for a content-aware deep comparison.
        # Depth 3 is sufficient for AD attribute values (strings, arrays, nested objects).
        $baseStr = if ($null -ne $baseVal) { $baseVal | ConvertTo-Json -Compress -Depth 3 } else { 'null' }
        $currStr = if ($null -ne $currVal) { $currVal | ConvertTo-Json -Compress -Depth 3 } else { 'null' }

        if ($baseStr -ne $currStr) {
            $changes.Add([PSCustomObject]@{
                Property = $prop
                OldValue = $baseVal
                NewValue = $currVal
            })
        }
    }

    return $changes.ToArray()
}

#endregion

Export-ModuleMember -Function Initialize-ADWallDatabase, Save-Finding, Get-Findings,
                               Get-RunHistory, Save-Snapshot, Get-Snapshots, Compare-Snapshots
