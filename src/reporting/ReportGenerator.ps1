#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Report Generator Module
.DESCRIPTION
    Generates HTML, CSV, JSON, and Markdown assessment reports from AD-Wall findings.
    The HTML report is self-contained with embedded CSS and Chart.js visualizations.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region Helpers

function Get-SeverityColour {
    param([string]$Severity)
    switch ($Severity) {
        'Critical'      { return '#d32f2f' }
        'High'          { return '#f57c00' }
        'Medium'        { return '#fbc02d' }
        'Low'           { return '#388e3c' }
        'Informational' { return '#1976d2' }
        default         { return '#757575' }
    }
}

function Get-SeverityBadge {
    param([string]$Severity)
    $colour = Get-SeverityColour $Severity
    return "<span class='badge' style='background-color:$colour;color:#fff;padding:3px 8px;border-radius:4px;font-size:0.8em;font-weight:bold'>$Severity</span>"
}

function Format-AffectedList {
    param([object[]]$Objects, [int]$Max = 5)
    if ($null -eq $Objects -or $Objects.Count -eq 0) { return '<em>None</em>' }
    $shown = $Objects | Select-Object -First $Max | ForEach-Object { "<code>$_</code>" }
    $extra = if ($Objects.Count -gt $Max) { " <small>+$($Objects.Count - $Max) more</small>" } else { '' }
    return ($shown -join ', ') + $extra
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

#endregion

#region HTML Report

function New-HTMLReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML security assessment report.
    .DESCRIPTION
        Creates a single HTML file with embedded CSS/JS including Chart.js charts,
        an executive summary, severity-grouped findings, and a remediation roadmap.
    .PARAMETER Findings
        Array of finding objects from Invoke-AllChecks.
    .PARAMETER PostureGrade
        Grade object from Get-OverallPostureGrade.
    .PARAMETER RemediationRoadmap
        Roadmap object from Get-RemediationRoadmap.
    .PARAMETER QuickWins
        Quick wins from Get-QuickWins.
    .PARAMETER OutputPath
        Directory to save the HTML file.
    .PARAMETER ReportTitle
        Title shown in the report header.
    .PARAMETER OrgName
        Organisation name shown in the report.
    .EXAMPLE
        New-HTMLReport -Findings $findings -PostureGrade $grade -OutputPath 'C:\Reports'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,

        [Parameter(Mandatory = $false)]
        [object]$PostureGrade,

        [Parameter(Mandatory = $false)]
        [object]$RemediationRoadmap,

        [Parameter(Mandatory = $false)]
        [object[]]$QuickWins = @(),

        [string]$OutputPath   = '.',
        [string]$ReportTitle  = 'AD Security Assessment',
        [string]$OrgName      = ''
    )

    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $fileName    = "ADWall_Report_$timestamp.html"
    $outputFile  = Join-Path $OutputPath $fileName
    $genDate     = [DateTime]::UtcNow.ToString('dd MMMM yyyy HH:mm') + ' UTC'

    $grade       = if ($PostureGrade) { $PostureGrade.Grade } else { 'N/A' }
    $score       = if ($PostureGrade) { $PostureGrade.Score } else { 0 }
    $gradeColour = switch ($grade) {
        'A' { '#388e3c' } 'B' { '#689f38' } 'C' { '#fbc02d' } 'D' { '#f57c00' } 'F' { '#d32f2f' }
        default { '#757575' }
    }

    $critCount = if ($PostureGrade) { $PostureGrade.CriticalCount }    else { @($Findings | Where-Object Severity -eq 'Critical').Count }
    $highCount = if ($PostureGrade) { $PostureGrade.HighCount }        else { @($Findings | Where-Object Severity -eq 'High').Count }
    $medCount  = if ($PostureGrade) { $PostureGrade.MediumCount }      else { @($Findings | Where-Object Severity -eq 'Medium').Count }
    $lowCount  = if ($PostureGrade) { $PostureGrade.LowCount }         else { @($Findings | Where-Object Severity -eq 'Low').Count }
    $infoCount = if ($PostureGrade) { $PostureGrade.InformationalCount } else { @($Findings | Where-Object Severity -eq 'Informational').Count }

    # Build findings HTML
    $findingsHtml = [System.Text.StringBuilder]::new()

    foreach ($sev in @('Critical','High','Medium','Low','Informational')) {
        $sevFindings = @($Findings | Where-Object { $_.Severity -eq $sev })
        if ($sevFindings.Count -eq 0) { continue }

        $colour = Get-SeverityColour $sev
        [void]$findingsHtml.AppendLine("<div class='severity-section'>")
        [void]$findingsHtml.AppendLine("<h3 style='border-left:5px solid $colour;padding-left:10px'>$sev Findings ($($sevFindings.Count))</h3>")

        foreach ($f in $sevFindings) {
            $badge        = Get-SeverityBadge $f.Severity
            $safeTitle    = ConvertTo-HtmlSafe $f.Title
            $safeDesc     = ConvertTo-HtmlSafe $f.Description
            $safeRemed    = ConvertTo-HtmlSafe $f.Remediation
            $affectedHtml = Format-AffectedList $f.AffectedObjects
            $mitre        = if ($f.MitreAttack) { "<a href='https://attack.mitre.org/techniques/$(($f.MitreAttack -split ' ')[0].Replace('.','/'))' target='_blank'>$($f.MitreAttack)</a>" } else { 'N/A' }

            [void]$findingsHtml.AppendLine(@"
<div class='finding-card' id='$($f.RuleId)'>
  <div class='finding-header'>
    <span class='finding-id'>[$($f.RuleId)]</span>
    $badge
    <strong>$safeTitle</strong>
  </div>
  <div class='finding-body'>
    <table class='finding-table'>
      <tr><td><strong>Category</strong></td><td>$($f.Category)</td></tr>
      <tr><td><strong>Affected ($($f.AffectedCount))</strong></td><td>$affectedHtml</td></tr>
      <tr><td><strong>Description</strong></td><td>$safeDesc</td></tr>
      <tr><td><strong>Remediation</strong></td><td>$safeRemed</td></tr>
      <tr><td><strong>MITRE ATT&amp;CK</strong></td><td>$mitre</td></tr>
    </table>
  </div>
</div>
"@)
        }
        [void]$findingsHtml.AppendLine("</div>")
    }

    # Quick Wins table
    $qwHtml = [System.Text.StringBuilder]::new()
    if ($QuickWins.Count -gt 0) {
        [void]$qwHtml.AppendLine("<table class='table'><thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Risk Score</th><th>Effort</th><th>Quick Win Score</th></tr></thead><tbody>")
        $i = 1
        foreach ($qw in $QuickWins) {
            $badge = Get-SeverityBadge $qw.Severity
            $effortLabel = @{1='Very Easy';2='Easy';3='Moderate';4='Hard';5='Very Hard'}[[int]$qw.EffortLevel]
            [void]$qwHtml.AppendLine("<tr><td>$i</td><td><a href='#$($qw.RuleId)'>$(ConvertTo-HtmlSafe $qw.Title)</a></td><td>$badge</td><td>$($qw.RiskScore)</td><td>$effortLabel</td><td><strong>$($qw.QuickWinScore)</strong></td></tr>")
            $i++
        }
        [void]$qwHtml.AppendLine("</tbody></table>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$ReportTitle</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  :root { --primary:#1a237e; --bg:#f5f5f5; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:var(--bg); color:#212121; }
  .header { background:var(--primary); color:#fff; padding:20px 40px; display:flex; justify-content:space-between; align-items:center; }
  .header h1 { font-size:1.8em; }
  .header .meta { font-size:0.85em; opacity:0.85; text-align:right; }
  .container { max-width:1400px; margin:0 auto; padding:20px 30px; }
  .score-card { background:#fff; border-radius:8px; padding:30px; margin-bottom:20px; box-shadow:0 2px 4px rgba(0,0,0,.1); display:flex; gap:30px; align-items:center; flex-wrap:wrap; }
  .grade-circle { width:120px; height:120px; border-radius:50%; border:8px solid $gradeColour; display:flex; flex-direction:column; align-items:center; justify-content:center; flex-shrink:0; }
  .grade-circle .grade { font-size:3em; font-weight:bold; color:$gradeColour; line-height:1; }
  .grade-circle .score { font-size:0.9em; color:#757575; }
  .summary-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:15px; flex:1; min-width:300px; }
  .summary-item { text-align:center; padding:15px 10px; border-radius:6px; }
  .summary-item .count { font-size:2em; font-weight:bold; }
  .summary-item .label { font-size:0.75em; text-transform:uppercase; letter-spacing:0.05em; opacity:0.85; }
  .charts-row { display:grid; grid-template-columns:1fr 2fr; gap:20px; margin-bottom:20px; }
  .chart-card { background:#fff; border-radius:8px; padding:20px; box-shadow:0 2px 4px rgba(0,0,0,.1); }
  .chart-card h3 { margin-bottom:15px; color:var(--primary); }
  .chart-container { position:relative; height:260px; }
  .section-title { font-size:1.3em; color:var(--primary); margin:30px 0 15px; font-weight:bold; border-bottom:2px solid var(--primary); padding-bottom:5px; }
  .finding-card { background:#fff; border-radius:6px; margin-bottom:12px; box-shadow:0 1px 3px rgba(0,0,0,.1); overflow:hidden; }
  .finding-header { padding:12px 16px; background:#fafafa; border-bottom:1px solid #eee; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .finding-id { font-family:monospace; font-size:0.8em; color:#757575; background:#eee; padding:2px 6px; border-radius:3px; }
  .finding-body { padding:0; }
  .finding-table { width:100%; border-collapse:collapse; font-size:0.88em; }
  .finding-table td { padding:8px 16px; border-bottom:1px solid #f0f0f0; vertical-align:top; }
  .finding-table td:first-child { font-weight:bold; width:140px; color:#555; white-space:nowrap; }
  .badge { display:inline-block; }
  .table { width:100%; border-collapse:collapse; background:#fff; border-radius:6px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1); font-size:0.88em; }
  .table th { background:var(--primary); color:#fff; padding:10px 12px; text-align:left; }
  .table td { padding:9px 12px; border-bottom:1px solid #eee; }
  .table tr:hover td { background:#f5f7ff; }
  .severity-section { margin-bottom:20px; }
  nav { background:#fff; padding:10px 30px; box-shadow:0 1px 3px rgba(0,0,0,.1); position:sticky; top:0; z-index:100; display:flex; gap:20px; flex-wrap:wrap; }
  nav a { color:var(--primary); text-decoration:none; font-size:0.9em; font-weight:500; padding:4px 0; border-bottom:2px solid transparent; }
  nav a:hover { border-bottom-color:var(--primary); }
  code { background:#f0f0f0; padding:1px 4px; border-radius:3px; font-size:0.9em; }
  @media(max-width:768px) { .charts-row,.summary-grid { grid-template-columns:1fr; } }
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>$ReportTitle</h1>
    $(if ($OrgName) { "<div>$OrgName</div>" })
  </div>
  <div class="meta">
    Generated: $genDate<br>
    AD-Wall v1.0.0<br>
    Total Findings: $($Findings.Count)
  </div>
</div>

<nav>
  <a href="#summary">Summary</a>
  <a href="#quickwins">Quick Wins</a>
  <a href="#findings">Findings</a>
  <a href="#roadmap">Roadmap</a>
</nav>

<div class="container">

  <!-- SCORE SUMMARY -->
  <div id="summary" class="score-card">
    <div class="grade-circle">
      <div class="grade">$grade</div>
      <div class="score">$score/100</div>
    </div>
    <div>
      <h2 style="margin-bottom:8px">Security Posture: $(if ($PostureGrade) { $PostureGrade.Description } else { 'Assessment complete' })</h2>
      <p style="color:#555;font-size:0.9em">Score based on finding severity, exploitability, and affected scope.</p>
    </div>
    <div class="summary-grid">
      <div class="summary-item" style="background:#ffebee"><div class="count" style="color:#d32f2f">$critCount</div><div class="label" style="color:#d32f2f">Critical</div></div>
      <div class="summary-item" style="background:#fff3e0"><div class="count" style="color:#f57c00">$highCount</div><div class="label" style="color:#f57c00">High</div></div>
      <div class="summary-item" style="background:#fffde7"><div class="count" style="color:#f9a825">$medCount</div><div class="label" style="color:#f9a825">Medium</div></div>
      <div class="summary-item" style="background:#e8f5e9"><div class="count" style="color:#388e3c">$lowCount</div><div class="label" style="color:#388e3c">Low</div></div>
      <div class="summary-item" style="background:#e3f2fd"><div class="count" style="color:#1976d2">$infoCount</div><div class="label" style="color:#1976d2">Info</div></div>
    </div>
  </div>

  <!-- CHARTS -->
  <div class="charts-row">
    <div class="chart-card">
      <h3>Severity Distribution</h3>
      <div class="chart-container">
        <canvas id="severityChart"></canvas>
      </div>
    </div>
    <div class="chart-card">
      <h3>Findings by Category</h3>
      <div class="chart-container">
        <canvas id="categoryChart"></canvas>
      </div>
    </div>
  </div>

  <!-- QUICK WINS -->
  <div id="quickwins">
    <div class="section-title">&#9889; Quick Wins (High Impact, Low Effort)</div>
    $($qwHtml.ToString())
  </div>

  <!-- FINDINGS -->
  <div id="findings">
    <div class="section-title">&#128270; Detailed Findings</div>
    $($findingsHtml.ToString())
  </div>

  <!-- ROADMAP -->
  $(if ($RemediationRoadmap) {
    $r = $RemediationRoadmap
    @"
  <div id="roadmap">
    <div class="section-title">&#128338; Remediation Roadmap</div>
    <div class="finding-card">
      <div class="finding-header"><strong>Phase 1 — Immediate (0-7 days)</strong> <span class="badge" style="background:#d32f2f;color:#fff;padding:3px 8px;border-radius:4px">$($r.Phase1_Immediate.Count) findings</span></div>
      <div class="finding-body"><div style="padding:10px 16px;font-size:0.88em">$( ($r.Phase1_Immediate.Findings | Select-Object -First 10 | ForEach-Object { "<div style='padding:4px 0;border-bottom:1px solid #f0f0f0'>&#8226; $(ConvertTo-HtmlSafe $_.Title)</div>" }) -join '' )</div></div>
    </div>
    <div class="finding-card">
      <div class="finding-header"><strong>Phase 2 — Short Term (8-30 days)</strong> <span class="badge" style="background:#f57c00;color:#fff;padding:3px 8px;border-radius:4px">$($r.Phase2_ShortTerm.Count) findings</span></div>
      <div class="finding-body"><div style="padding:10px 16px;font-size:0.88em">$( ($r.Phase2_ShortTerm.Findings | Select-Object -First 10 | ForEach-Object { "<div style='padding:4px 0;border-bottom:1px solid #f0f0f0'>&#8226; $(ConvertTo-HtmlSafe $_.Title)</div>" }) -join '' )</div></div>
    </div>
    <div class="finding-card">
      <div class="finding-header"><strong>Phase 3 — Medium Term (31-90 days)</strong> <span class="badge" style="background:#fbc02d;color:#000;padding:3px 8px;border-radius:4px">$($r.Phase3_MediumTerm.Count) findings</span></div>
    </div>
  </div>
"@
  })

</div><!-- /container -->

<script>
// Severity pie chart
const sevCtx = document.getElementById('severityChart').getContext('2d');
new Chart(sevCtx, {
  type: 'doughnut',
  data: {
    labels: ['Critical','High','Medium','Low','Informational'],
    datasets:[{ data:[$critCount,$highCount,$medCount,$lowCount,$infoCount],
      backgroundColor:['#d32f2f','#f57c00','#fbc02d','#388e3c','#1976d2'],
      borderWidth:2, borderColor:'#fff' }]
  },
  options:{ responsive:true, maintainAspectRatio:false,
    plugins:{ legend:{ position:'right' } } }
});

// Category bar chart
$(
    $catGroups = $Findings | Group-Object -Property Category
    $catLabels  = ($catGroups | ForEach-Object { "'$($_.Name)'" }) -join ','
    $catCounts  = ($catGroups | ForEach-Object { $_.Count }) -join ','
    "const catLabels = [$catLabels]; const catData = [$catCounts];"
)
const catCtx = document.getElementById('categoryChart').getContext('2d');
new Chart(catCtx, {
  type: 'bar',
  data: {
    labels: catLabels,
    datasets:[{ label:'Findings', data:catData,
      backgroundColor:'#1a237e', borderRadius:4 }]
  },
  options:{ responsive:true, maintainAspectRatio:false, indexAxis:'y',
    plugins:{ legend:{ display:false } },
    scales:{ x:{ beginAtZero:true, ticks:{ stepSize:1 } } } }
});
</script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Verbose "HTML report saved: $outputFile"
        return $outputFile
    }
    catch {
        Write-Error "Failed to write HTML report: $_"
        return $null
    }
}

#endregion

#region CSV Report

function New-CSVReport {
    <#
    .SYNOPSIS
        Exports findings to a CSV file for use in spreadsheets and ticketing systems.
    .PARAMETER Findings
        Array of finding objects.
    .PARAMETER OutputPath
        Directory to save the CSV.
    .EXAMPLE
        New-CSVReport -Findings $findings -OutputPath 'C:\Reports'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        [string]$OutputPath = '.'
    )

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputFile = Join-Path $OutputPath "ADWall_Findings_$timestamp.csv"

    $rows = $Findings | ForEach-Object {
        [PSCustomObject]@{
            RuleId          = $_.RuleId
            Severity        = $_.Severity
            Category        = $_.Category
            Title           = $_.Title
            AffectedCount   = $_.AffectedCount
            AffectedObjects = ($_.AffectedObjects | Select-Object -First 10) -join '; '
            Description     = $_.Description -replace "`r`n",' ' -replace "`n",' '
            Remediation     = $_.Remediation -replace "`r`n",' ' -replace "`n",' '
            MitreAttack     = $_.MitreAttack
            DetectedAt      = $_.DetectedAt
        }
    }

    try {
        $rows | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Verbose "CSV report saved: $outputFile"
        return $outputFile
    }
    catch {
        Write-Error "Failed to write CSV report: $_"
        return $null
    }
}

#endregion

#region JSON Report

function New-JSONReport {
    <#
    .SYNOPSIS
        Exports the full assessment data as a structured JSON file (evidence store).
    .PARAMETER Findings
        Array of finding objects.
    .PARAMETER PostureGrade
        Grade object.
    .PARAMETER RemediationRoadmap
        Roadmap object.
    .PARAMETER Metadata
        Additional metadata hashtable to include.
    .PARAMETER OutputPath
        Directory to save the JSON.
    .EXAMPLE
        New-JSONReport -Findings $findings -PostureGrade $grade -OutputPath 'C:\Reports'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,

        [Parameter(Mandatory = $false)]
        [object]$PostureGrade,

        [Parameter(Mandatory = $false)]
        [object]$RemediationRoadmap,

        [Parameter(Mandatory = $false)]
        [hashtable]$Metadata = @{},

        [string]$OutputPath = '.'
    )

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputFile = Join-Path $OutputPath "ADWall_Assessment_$timestamp.json"

    $report = [PSCustomObject]@{
        SchemaVersion    = '1.0'
        GeneratedAt      = (Get-Date -Format 'o')
        Tool             = 'AD-Wall v1.0.0'
        Metadata         = $Metadata
        PostureGrade     = $PostureGrade
        TotalFindings    = $Findings.Count
        Findings         = $Findings
        RemediationRoadmap = if ($RemediationRoadmap) {
            [PSCustomObject]@{
                Phase1Count  = $RemediationRoadmap.Phase1_Immediate.Count
                Phase2Count  = $RemediationRoadmap.Phase2_ShortTerm.Count
                Phase3Count  = $RemediationRoadmap.Phase3_MediumTerm.Count
                Phase4Count  = $RemediationRoadmap.Phase4_LongTerm.Count
                CriticalPaths = $RemediationRoadmap.CriticalPaths
            }
        } else { $null }
    }

    try {
        $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Verbose "JSON report saved: $outputFile"
        return $outputFile
    }
    catch {
        Write-Error "Failed to write JSON report: $_"
        return $null
    }
}

#endregion

#region Markdown Report

function New-MarkdownReport {
    <#
    .SYNOPSIS
        Generates a Markdown-format assessment report suitable for wikis and PRs.
    .PARAMETER Findings
        Array of finding objects.
    .PARAMETER PostureGrade
        Grade object.
    .PARAMETER OutputPath
        Directory to save the Markdown file.
    .EXAMPLE
        New-MarkdownReport -Findings $findings -PostureGrade $grade -OutputPath 'C:\Reports'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,
        [Parameter(Mandatory = $false)]
        [object]$PostureGrade,
        [string]$OutputPath  = '.',
        [string]$ReportTitle = 'AD Security Assessment'
    )

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputFile = Join-Path $OutputPath "ADWall_Report_$timestamp.md"
    $genDate    = Get-Date -Format 'dd MMMM yyyy HH:mm UTC'

    $md = [System.Text.StringBuilder]::new()

    [void]$md.AppendLine("# $ReportTitle")
    [void]$md.AppendLine()
    [void]$md.AppendLine("**Generated:** $genDate | **Tool:** AD-Wall v1.0.0")
    [void]$md.AppendLine()

    if ($PostureGrade) {
        [void]$md.AppendLine("## Executive Summary")
        [void]$md.AppendLine()
        [void]$md.AppendLine("| Metric | Value |")
        [void]$md.AppendLine("|--------|-------|")
        [void]$md.AppendLine("| Overall Grade | **$($PostureGrade.Grade)** ($($PostureGrade.Score)/100) |")
        [void]$md.AppendLine("| Assessment | $($PostureGrade.Description) |")
        [void]$md.AppendLine("| Critical | $($PostureGrade.CriticalCount) |")
        [void]$md.AppendLine("| High | $($PostureGrade.HighCount) |")
        [void]$md.AppendLine("| Medium | $($PostureGrade.MediumCount) |")
        [void]$md.AppendLine("| Low | $($PostureGrade.LowCount) |")
        [void]$md.AppendLine("| Informational | $($PostureGrade.InformationalCount) |")
        [void]$md.AppendLine()
    }

    foreach ($sev in @('Critical','High','Medium','Low','Informational')) {
        $sevFindings = @($Findings | Where-Object { $_.Severity -eq $sev })
        if ($sevFindings.Count -eq 0) { continue }

        [void]$md.AppendLine("## $sev Findings ($($sevFindings.Count))")
        [void]$md.AppendLine()

        foreach ($f in $sevFindings) {
            [void]$md.AppendLine("### [$($f.RuleId)] $($f.Title)")
            [void]$md.AppendLine()
            [void]$md.AppendLine("- **Category:** $($f.Category)")
            [void]$md.AppendLine("- **Severity:** $($f.Severity)")
            [void]$md.AppendLine("- **Affected Objects:** $($f.AffectedCount)")
            [void]$md.AppendLine("- **MITRE ATT&CK:** $($f.MitreAttack)")
            [void]$md.AppendLine()
            [void]$md.AppendLine("**Description:** $($f.Description)")
            [void]$md.AppendLine()
            [void]$md.AppendLine("**Remediation:** $($f.Remediation)")
            [void]$md.AppendLine()
            if ($f.AffectedObjects.Count -gt 0) {
                [void]$md.AppendLine("**Sample Affected Objects:**")
                $f.AffectedObjects | Select-Object -First 5 | ForEach-Object {
                    [void]$md.AppendLine("- ``$_``")
                }
                [void]$md.AppendLine()
            }
            [void]$md.AppendLine("---")
            [void]$md.AppendLine()
        }
    }

    try {
        $md.ToString() | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Verbose "Markdown report saved: $outputFile"
        return $outputFile
    }
    catch {
        Write-Error "Failed to write Markdown report: $_"
        return $null
    }
}

#endregion

Export-ModuleMember -Function New-HTMLReport, New-CSVReport, New-JSONReport, New-MarkdownReport
