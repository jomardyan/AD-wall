<#
.SYNOPSIS
    AD-Wall — Active Directory Security Assessment Framework
.DESCRIPTION
    Performs a comprehensive, READ-ONLY security assessment of an Active Directory
    environment. Identifies misconfigurations, vulnerabilities, and persistence
    mechanisms across four categories: Identity & Privilege, Configuration & GPO,
    Exploits & Vulnerabilities, and Persistence & Backdoors.

    Use -RedTeam switch to enable write/destructive tests (requires explicit opt-in).
    Use -SafeMode:$false to suppress the read-only guard (use with caution).

.PARAMETER DomainController
    FQDN or IP of a domain controller. If omitted, auto-discovered.

.PARAMETER Credential
    PSCredential for authentication. If omitted, current user context is used.

.PARAMETER OutputPath
    Directory to save report files. Defaults to './output'.

.PARAMETER Mode
    Assessment: full one-time assessment (default)
    Validation:  targeted checks against known findings
    Monitoring:  lightweight checks suitable for scheduled runs

.PARAMETER RedTeam
    Enables write operations and extended destructive tests. USE WITH EXTREME CAUTION.
    Must also specify -SafeMode:$false.

.PARAMETER SafeMode
    Default $true. All operations are read-only. Set to $false only when RedTeam mode is needed.

.PARAMETER Modules
    Comma-separated list of modules to run: Identity, Config, Exploit, Persistence, Detection.
    Defaults to all modules.

.PARAMETER Format
    Output format(s): HTML, JSON, CSV, Markdown, CEF, Splunk, All. Defaults to HTML,JSON.

.PARAMETER LaunchDashboard
    If specified, launches the Python Flask web dashboard after the assessment.

.PARAMETER ConfigFile
    Path to a JSON configuration file created by Save-ADWallConfig.

.PARAMETER StaleAccountDays
    Number of days of inactivity before flagging accounts as stale. Default: 90.

.PARAMETER OrgName
    Organisation name for report headers.

.PARAMETER SIEMExport
    If specified, generates CEF and Splunk-compatible export files in addition to the standard reports.

.PARAMETER JiraUrl
    Jira base URL. When provided along with JiraProject, JiraUser, JiraToken, creates Jira issues for High+ findings.

.PARAMETER JiraProject
    Jira project key (e.g. SEC). Required when JiraUrl is specified.

.PARAMETER JiraUser
    Jira username or email. Required when JiraUrl is specified.

.PARAMETER JiraToken
    Jira API token. Required when JiraUrl is specified.

.PARAMETER ServiceNowUrl
    ServiceNow instance URL. When provided along with ServiceNowUser and ServiceNowPass, creates incidents.

.PARAMETER ServiceNowUser
    ServiceNow username. Required when ServiceNowUrl is specified.

.PARAMETER ServiceNowPass
    ServiceNow password. Required when ServiceNowUrl is specified.

.EXAMPLE
    .\Invoke-ADWall.ps1 -DomainController dc01.corp.local

.EXAMPLE
    .\Invoke-ADWall.ps1 -DomainController dc01.corp.local -Credential (Get-Credential) `
        -OutputPath C:\ADWall\Reports -Format All -LaunchDashboard

.EXAMPLE
    .\Invoke-ADWall.ps1 -Modules Identity,Exploit -Format JSON

.NOTES
    Author  : AD-Wall Project
    Version : 1.0.0
    Requires: PowerShell 5.1+, Network access to target DC
    Safe:     All operations are READ-ONLY by default
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$DomainController,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath      = (Join-Path (Get-Location) 'output'),
    [ValidateSet('Assessment','Validation','Monitoring')]
    [string]$Mode            = 'Assessment',
    [switch]$RedTeam,
    [bool]$SafeMode          = $true,
    [ValidateSet('Identity','Config','Exploit','Persistence','Detection','Compliance','OffensiveTechniques','RedTeam')]
    [string[]]$Modules       = @('Identity','Config','Exploit','Persistence','Detection','Compliance'),
    [ValidateSet('HTML','JSON','CSV','Markdown','CEF','Splunk','All')]
    [string[]]$Format        = @('HTML','JSON'),
    [switch]$LaunchDashboard,
    [string]$ConfigFile,
    [int]$StaleAccountDays   = 90,
    [string]$OrgName         = '',
    [int]$DashboardPort      = 5000,
    [switch]$SIEMExport,
    [string]$JiraUrl,
    [string]$JiraProject,
    [string]$JiraUser,
    [string]$JiraToken,
    [string]$ServiceNowUrl,
    [string]$ServiceNowUser,
    [string]$ServiceNowPass,
    # Monitoring mode alerting
    [string]$AlertEmail,
    [string]$AlertSmtpServer,
    [int]$AlertSmtpPort      = 587,
    [System.Management.Automation.PSCredential]$AlertSmtpCredential,
    [switch]$AlertOnDrift
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Bootstrap

$ScriptRoot = $PSScriptRoot
$Script:StartTime = Get-Date

function Write-Banner {
    $ver = '1.0.0'
    Write-Host "`n" -NoNewline
    Write-Host " ╔═══════════════════════════════════════╗" -ForegroundColor DarkBlue
    Write-Host " ║     AD-Wall Security Assessment       ║" -ForegroundColor DarkBlue
    Write-Host " ║     Active Directory Audit Tool       ║" -ForegroundColor DarkBlue
    Write-Host " ║     Version $ver   READ-ONLY MODE     ║" -ForegroundColor DarkBlue
    Write-Host " ╚═══════════════════════════════════════╝" -ForegroundColor DarkBlue
    Write-Host ""
}

function Write-Step {
    param([string]$Message, [string]$Status = 'INFO')
    $ts  = (Get-Date).ToString('HH:mm:ss')
    $col = switch ($Status) {
        'INFO'    { 'Cyan' }
        'OK'      { 'Green' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SECTION' { 'Magenta' }
        default   { 'White' }
    }
    Write-Host "[$ts][$Status] $Message" -ForegroundColor $col
}

function Import-ADWallModule {
    param([string]$Path)
    $full = Join-Path $ScriptRoot $Path
    if (Test-Path $full) {
        . $full
        Write-Verbose "Loaded module: $full"
    }
    else {
        Write-Warning "Module not found: $full"
    }
}

#endregion

#region Safety Guard

if ($RedTeam -and $SafeMode) {
    Write-Error "ERROR: -RedTeam requires -SafeMode:`$false. This prevents accidental use of destructive operations.`nIf you intend to run RedTeam tests, re-run with -RedTeam -SafeMode:`$false"
    exit 1
}

if ($RedTeam) {
    Write-Warning "⚠  RED TEAM MODE ENABLED — write operations are permitted."
    Write-Warning "   Ensure you have explicit written authorisation before continuing."
    if (-not $PSCmdlet.ShouldContinue("Enable Red Team mode with write permissions?", "Confirm")) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

#endregion

Write-Banner

Write-Step "AD-Wall Assessment started at $($Script:StartTime.ToString('dd MMM yyyy HH:mm:ss'))" 'SECTION'
Write-Step "Mode: $Mode | Modules: $($Modules -join ', ') | SafeMode: $SafeMode" 'INFO'

#region Load modules

Write-Step "Loading modules…" 'INFO'

Import-ADWallModule 'src\core\Config.ps1'
Import-ADWallModule 'src\core\Database.ps1'
Import-ADWallModule 'src\core\FindingHelper.ps1'   # shared New-Finding / New-ATKFinding factory
Import-ADWallModule 'src\collectors\LdapCollector.ps1'
Import-ADWallModule 'src\collectors\SmbCollector.ps1'
Import-ADWallModule 'src\collectors\EventLogCollector.ps1'
Import-ADWallModule 'src\collectors\AdcsCollector.ps1'
Import-ADWallModule 'src\modules\IdentityPrivilege.ps1'
Import-ADWallModule 'src\modules\ConfigGpo.ps1'
Import-ADWallModule 'src\modules\ExploitVuln.ps1'
Import-ADWallModule 'src\modules\PersistenceBackdoor.ps1'
Import-ADWallModule 'src\modules\DetectionEngineering.ps1'
Import-ADWallModule 'src\modules\ComplianceCheck.ps1'
Import-ADWallModule 'src\modules\OffensiveTechniques.ps1'
Import-ADWallModule 'src\engine\RuleEngine.ps1'
Import-ADWallModule 'src\engine\RiskEngine.ps1'
Import-ADWallModule 'src\engine\AttackGraphEngine.ps1'
Import-ADWallModule 'src\reporting\ReportGenerator.ps1'
Import-ADWallModule 'src\reporting\WorkflowExport.ps1'

#endregion

#region Config

Write-Step "Initialising configuration…" 'INFO'

if ($ConfigFile) {
    Load-ADWallConfig -Path $ConfigFile
}

$configOverrides = @{
    Mode             = $Mode
    RedTeam          = [bool]$RedTeam
    SafeMode         = $SafeMode
    Modules          = $Modules
    StaleAccountDays = $StaleAccountDays
    OutputPath       = $OutputPath
    OrganisationName = $OrgName
    DashboardPort    = $DashboardPort
    EnableSnapshots  = $true
}
if ($DomainController) { $configOverrides.DomainController = $DomainController }
Set-ADWallConfig -Settings $configOverrides

$config = Get-ADWallConfig

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Step "Created output directory: $OutputPath" 'INFO'
}

#endregion

#region Initialise evidence database

Write-Step "Initialising evidence store…" 'INFO'
Initialize-ADWallDatabase -OutputPath $OutputPath

#endregion

#region LDAP Collection

Write-Step "=== Phase 1: LDAP Data Collection ===" 'SECTION'

$collectedData = @{}

$ldapParams = @{ Verbose = $VerbosePreference -eq 'Continue' }
if ($DomainController)  { $ldapParams.Server     = $DomainController }
if ($Credential)        { $ldapParams.Credential = $Credential }
if ($config.SearchBase) { $ldapParams.SearchBase  = $config.SearchBase }

try {
    Write-Step "Collecting user accounts…" 'INFO'
    $collectedData.Users = Get-ADUsers @ldapParams
    Write-Step "  → $($collectedData.Users.Count) users" 'OK'
}
catch { Write-Step "User collection failed: $_" 'WARN'; $collectedData.Users = @() }

try {
    Write-Step "Collecting groups…" 'INFO'
    $collectedData.Groups = Get-ADGroups @ldapParams
    Write-Step "  → $($collectedData.Groups.Count) groups" 'OK'
}
catch { Write-Step "Group collection failed: $_" 'WARN'; $collectedData.Groups = @() }

try {
    Write-Step "Collecting computer accounts…" 'INFO'
    $collectedData.Computers = Get-ADComputers @ldapParams
    Write-Step "  → $($collectedData.Computers.Count) computers" 'OK'
}
catch { Write-Step "Computer collection failed: $_" 'WARN'; $collectedData.Computers = @() }

try {
    Write-Step "Collecting domain controllers…" 'INFO'
    $collectedData.DomainControllers = Get-ADDomainControllers @ldapParams
    Write-Step "  → $($collectedData.DomainControllers.Count) DCs" 'OK'
}
catch { Write-Step "DC collection failed: $_" 'WARN'; $collectedData.DomainControllers = @() }

try {
    Write-Step "Collecting trusts…" 'INFO'
    $collectedData.Trusts = Get-ADTrusts @ldapParams
    Write-Step "  → $($collectedData.Trusts.Count) trusts" 'OK'
}
catch { Write-Step "Trust collection failed: $_" 'WARN'; $collectedData.Trusts = @() }

try {
    Write-Step "Collecting GPOs…" 'INFO'
    $collectedData.GPOs = Get-ADGPOs @ldapParams
    Write-Step "  → $($collectedData.GPOs.Count) GPOs" 'OK'
}
catch { Write-Step "GPO collection failed: $_" 'WARN'; $collectedData.GPOs = @() }

try {
    Write-Step "Collecting domain ACLs…" 'INFO'
    $collectedData.ACLs = Get-ADACLs @ldapParams
    Write-Step "  → $($collectedData.ACLs.Count) ACEs" 'OK'
}
catch { Write-Step "ACL collection failed: $_" 'WARN'; $collectedData.ACLs = @() }

try {
    Write-Step "Collecting password policies…" 'INFO'
    $collectedData.PasswordPolicies = Get-ADPasswordPolicies @ldapParams
    Write-Step "  → $($collectedData.PasswordPolicies.Count) policies" 'OK'
}
catch { Write-Step "Password policy collection failed: $_" 'WARN'; $collectedData.PasswordPolicies = @() }

#endregion

#region SMB / Protocol Collection

Write-Step "=== Phase 2: Protocol & Configuration Collection ===" 'SECTION'

$smbParams = @{}
if ($DomainController) { $smbParams.ComputerName = $DomainController }
if ($Credential)       { $smbParams.Credential   = $Credential }

try {
    Write-Step "Checking SMB signing…" 'INFO'
    $targets = if ($collectedData.DomainControllers.Count -gt 0) {
        $collectedData.DomainControllers | Select-Object -ExpandProperty DnsHostName -First 5
    }
    else { @($DomainController | Where-Object { $_ }) }

    $collectedData.SmbSigning = @($targets | Where-Object { $_ } | ForEach-Object {
        Get-SMBSigningStatus -ComputerName $_ -Credential $Credential
    })
    Write-Step "  → $($collectedData.SmbSigning.Count) hosts checked" 'OK'
}
catch { Write-Step "SMB signing check failed: $_" 'WARN'; $collectedData.SmbSigning = @() }

try {
    Write-Step "Checking LDAP signing policy…" 'INFO'
    $targets = if ($collectedData.DomainControllers.Count -gt 0) {
        $collectedData.DomainControllers | Select-Object -ExpandProperty DnsHostName -First 5
    }
    else { @($DomainController | Where-Object { $_ }) }

    $collectedData.LdapSigning = @($targets | Where-Object { $_ } | ForEach-Object {
        Get-LDAPSigningPolicy -ComputerName $_ -Credential $Credential
    })
    Write-Step "  → $($collectedData.LdapSigning.Count) DCs checked" 'OK'
}
catch { Write-Step "LDAP signing check failed: $_" 'WARN'; $collectedData.LdapSigning = @() }

try {
    Write-Step "Checking SMBv1 status…" 'INFO'
    $collectedData.SmbV1 = @($collectedData.DomainControllers | Select-Object -ExpandProperty DnsHostName -First 5 | ForEach-Object {
        Get-SMBv1Status -ComputerName $_ -Credential $Credential
    })
    Write-Step "  → $($collectedData.SmbV1.Count) hosts checked" 'OK'
}
catch { Write-Step "SMBv1 check failed: $_" 'WARN'; $collectedData.SmbV1 = @() }

try {
    Write-Step "Checking NTLM settings…" 'INFO'
    $collectedData.NtlmSettings = @($collectedData.DomainControllers | Select-Object -ExpandProperty DnsHostName -First 3 | ForEach-Object {
        Get-NTLMSettings -ComputerName $_ -Credential $Credential
    })
    Write-Step "  → $($collectedData.NtlmSettings.Count) hosts checked" 'OK'
}
catch { Write-Step "NTLM settings check failed: $_" 'WARN'; $collectedData.NtlmSettings = @() }

#endregion

#region ADCS Collection

if ('Exploit' -in $Modules) {
    Write-Step "=== Phase 3: AD Certificate Services Collection ===" 'SECTION'

    $adcsParams = @{}
    if ($DomainController) { $adcsParams.Server     = $DomainController }
    if ($Credential)       { $adcsParams.Credential = $Credential }

    try {
        Write-Step "Enumerating Certificate Authorities…" 'INFO'
        $collectedData.CertificateAuthorities = Get-ADCSCertificateAuthorities @adcsParams
        Write-Step "  → $($collectedData.CertificateAuthorities.Count) CAs" 'OK'
    }
    catch { Write-Step "CA enumeration failed: $_" 'WARN'; $collectedData.CertificateAuthorities = @() }

    try {
        Write-Step "Enumerating Certificate Templates…" 'INFO'
        $collectedData.CertificateTemplates = Get-CertificateTemplates @adcsParams
        Write-Step "  → $($collectedData.CertificateTemplates.Count) templates" 'OK'
    }
    catch { Write-Step "Template enumeration failed: $_" 'WARN'; $collectedData.CertificateTemplates = @() }

    try {
        Write-Step "Collecting template enrollment permissions…" 'INFO'
        $collectedData.EnrollmentPermissions = Get-ADCSEnrollmentPermissions @adcsParams
        Write-Step "  → $($collectedData.EnrollmentPermissions.Count) ACEs" 'OK'
    }
    catch { Write-Step "Enrollment permissions failed: $_" 'WARN'; $collectedData.EnrollmentPermissions = @() }
}

#endregion

#region Run Security Checks

Write-Step "=== Phase 4: Running Security Checks ===" 'SECTION'

$domainName = if ($config.DomainName) { $config.DomainName } else { $env:USERDNSDOMAIN }
$allFindings = @()

try {
    $allFindings = Invoke-AllChecks `
        -CollectedData $collectedData `
        -Modules $Modules `
        -DomainName $domainName `
        -Verbose:($VerbosePreference -eq 'Continue')

    Write-Step "Security checks complete. Total findings: $($allFindings.Count)" 'OK'
}
catch {
    Write-Step "Security checks error: $_" 'ERROR'
    Write-Step "Partial findings may be available." 'WARN'
    $allFindings = @()
}

# Display summary
$sevGroups = $allFindings | Group-Object -Property Severity
foreach ($sg in @('Critical','High','Medium','Low','Informational')) {
    $g = $sevGroups | Where-Object Name -eq $sg
    $n = if ($g) { $g.Count } else { 0 }
    $col = switch ($sg) {
        'Critical' { 'Red' } 'High' { 'Yellow' } 'Medium' { 'Cyan' }
        'Low' { 'Green' } default { 'White' }
    }
    if ($n -gt 0) { Write-Host "  ${sg}: $n" -ForegroundColor $col }
}

#endregion

#region Compliance Checks

if ('Compliance' -in $Modules) {
    Write-Step "=== Phase 4b: Compliance Checks (CIS/NIST) ===" 'SECTION'
    try {
        $complianceFindings = Invoke-AllComplianceChecks -CollectedData $collectedData
        $allFindings = @($allFindings) + @($complianceFindings)
        Write-Step "Compliance checks complete. $($complianceFindings.Count) finding(s)" 'OK'
    }
    catch { Write-Step "Compliance checks error: $_" 'WARN' }
}

#endregion

#region Attack Graph Analysis

Write-Step "=== Phase 4c: Attack Graph Analysis ===" 'SECTION'

$attackGraph    = $null
$attackPaths    = @()
$graphSummary   = $null

try {
    $attackGraph  = Build-AttackGraph -CollectedData $collectedData -DomainName $domainName
    $attackPaths  = Find-AttackPaths  -Graph $attackGraph -MaxDepth 5 -MaxPaths 30
    $graphSummary = Get-GraphSummary  -Graph $attackGraph -AttackPaths $attackPaths

    Write-Step "Attack graph: $($graphSummary.TotalNodes) nodes, $($graphSummary.TotalEdges) edges" 'INFO'
    Write-Step "Attack paths found: $($graphSummary.AttackPathCount) (Critical: $($graphSummary.CriticalPathCount), High: $($graphSummary.HighPathCount))" 'OK'

    # Save graph summary alongside reports
    $graphFile = Join-Path $OutputPath 'attack_graph.json'
    @{ Graph = $graphSummary; Paths = $attackPaths } | ConvertTo-Json -Depth 10 |
        Set-Content -Path $graphFile -Encoding UTF8
    Write-Step "  → Attack graph saved: $graphFile" 'OK'
}
catch { Write-Step "Attack graph analysis error: $_" 'WARN' }

#endregion

#region Risk Scoring

Write-Step "=== Phase 5: Risk Scoring ===" 'SECTION'

$postureGrade    = $null
$remediationRoad = $null
$quickWins       = @()

try {
    $totalUsers = $collectedData.Users.Count
    $postureGrade    = Get-OverallPostureGrade  -Findings $allFindings -TotalUserCount $totalUsers
    $remediationRoad = Get-RemediationRoadmap   -Findings $allFindings
    $quickWins       = Get-QuickWins            -Findings $allFindings -TopN 10

    Write-Step "Overall grade: $($postureGrade.Grade) ($($postureGrade.Score)/100) — $($postureGrade.Description)" 'OK'
    Write-Step "Remediation phases: P1=$($remediationRoad.Phase1_Immediate.Count) P2=$($remediationRoad.Phase2_ShortTerm.Count) P3=$($remediationRoad.Phase3_MediumTerm.Count)" 'INFO'
}
catch { Write-Step "Risk scoring error: $_" 'WARN' }

#endregion

#region Save to Evidence Store

Write-Step "Saving findings to evidence store…" 'INFO'
$runId = Get-Date -Format 'yyyyMMdd-HHmmss'
try {
    if ($allFindings.Count -gt 0) {
        $allFindings | Save-Finding -RunId $runId -Domain $domainName
    }
    if ($config.EnableSnapshots) {
        Save-Snapshot -SnapshotData $collectedData -Label "scan-$runId" -Domain $domainName
    }
    Write-Step "Evidence store updated (run: $runId)" 'OK'
}
catch { Write-Step "Evidence store error: $_" 'WARN' }

#endregion

#region Red Team Simulation

$redTeamResults = @()
if ($RedTeam) {
    Write-Step "=== Phase 5b: Red Team Simulation ===" 'SECTION'
    try {
        Import-ADWallModule 'src\modules\RedTeam.ps1'
        if (Get-Command Invoke-AllRedTeamChecks -ErrorAction SilentlyContinue) {
            $redTeamResults = Invoke-AllRedTeamChecks -ADData $collectedData -SafeMode $SafeMode
            Write-Step "Red Team simulation complete. $($redTeamResults.Count) attack checks run." 'OK'
            # Map MITRE IDs to ATK-* RuleIds where possible
            $mitreToRuleId = @{
                'T1110.003' = 'ATK-001'; 'T1136.001' = 'ATK-002'; 'T1558.001' = 'ATK-003'
                'T1558.002' = 'ATK-005'; 'T1649'     = 'ATK-006'; 'T1003.003' = 'ATK-007'
                'T1606.002' = 'ATK-008'; 'T1098.001' = 'ATK-009'; 'T1550.002' = 'ATK-010'
                'T1550.003' = 'ATK-011'; 'T1207'     = 'ATK-012'; 'T1557.001' = 'ATK-013'
            }
            # Add red team results as findings to the pipeline
            foreach ($rt in $redTeamResults) {
                $ruleId = if ($mitreToRuleId.ContainsKey($rt.MITRE)) { $mitreToRuleId[$rt.MITRE] } else { "ATK-RT-$($rt.MITRE -replace '[^A-Z0-9]','-')" }
                $rtFinding = [PSCustomObject]@{
                    RuleId          = $ruleId
                    Title           = "[Red Team] $($rt.AttackType)"
                    Severity        = $rt.RiskLevel
                    Category        = 'Red Team'
                    Description     = $rt.AttackPath
                    AffectedObjects = $rt.Findings | ForEach-Object { if ($_.Account) { $_.Account } elseif ($_.Note) { $_.Note } else { '' } } | Where-Object { $_ }
                    AffectedCount   = $rt.ExploitableCount
                    Remediation     = $rt.Mitigations -join '; '
                    MitreAttack     = $rt.MITRE
                    DetectedAt      = $rt.RunAt
                }
                $allFindings = @($allFindings) + @($rtFinding)
            }
        }
    }
    catch { Write-Step "Red Team simulation error: $_" 'WARN' }
}

#endregion

#region Report Generation

Write-Step "=== Phase 6: Generating Reports ===" 'SECTION'

$reportFormats = if ($Format -contains 'All') { @('HTML','JSON','CSV','Markdown','CEF','Splunk') } else { $Format }
$generatedFiles = @()

$reportMeta = @{
    Domain           = $domainName
    DomainController = $DomainController
    Mode             = $Mode
    Modules          = $Modules
    ScanDate         = $Script:StartTime.ToString('o')
    OrgName          = $OrgName
    RedTeam          = [bool]$RedTeam
    RedTeamCount     = $redTeamResults.Count
}

# Generate reports in parallel using PowerShell runspaces when multiple formats are requested
if ($reportFormats.Count -gt 1) {
    Write-Step "Generating $($reportFormats.Count) reports in parallel…" 'INFO'
    $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [Math]::Min($reportFormats.Count, 4))
    $runspacePool.Open()
    $jobs = @()

    foreach ($fmt in $reportFormats) {
        $ps = [PowerShell]::Create().AddScript({
            param($Format, $Findings, $PostureGrade, $RemediationRoadmap, $QuickWins, $OutputPath, $OrgName, $ReportMeta, $ScriptRoot)
            # Re-load functions in the runspace
            . (Join-Path $ScriptRoot 'src\reporting\ReportGenerator.ps1')
            . (Join-Path $ScriptRoot 'src\reporting\WorkflowExport.ps1')
            switch ($Format) {
                'HTML'     { New-HTMLReport    -Findings $Findings -PostureGrade $PostureGrade -RemediationRoadmap $RemediationRoadmap -QuickWins $QuickWins -OutputPath $OutputPath -ReportTitle 'AD Security Assessment' -OrgName $OrgName }
                'JSON'     { New-JSONReport    -Findings $Findings -PostureGrade $PostureGrade -RemediationRoadmap $RemediationRoadmap -Metadata $ReportMeta  -OutputPath $OutputPath }
                'CSV'      { New-CSVReport     -Findings $Findings -OutputPath $OutputPath }
                'Markdown' { New-MarkdownReport -Findings $Findings -PostureGrade $PostureGrade -OutputPath $OutputPath }
                'CEF'      { New-CEFReport      -Findings $Findings -OutputPath $OutputPath }
                'Splunk'   { New-SplunkReport   -Findings $Findings -OutputPath $OutputPath }
            }
        }).AddArgument($fmt).AddArgument($allFindings).AddArgument($postureGrade).AddArgument($remediationRoad).AddArgument($quickWins).AddArgument($OutputPath).AddArgument($OrgName).AddArgument($reportMeta).AddArgument($ScriptRoot)
        $ps.RunspacePool = $runspacePool
        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke(); Format = $fmt }
    }

    foreach ($job in $jobs) {
        try {
            $file = $job.PS.EndInvoke($job.Handle)
            if ($file) {
                $generatedFiles += $file
                Write-Step "  → $file" 'OK'
            }
        }
        catch { Write-Step "  Failed to generate $($job.Format) report: $_" 'WARN' }
        finally { $job.PS.Dispose() }
    }
    $runspacePool.Close()
    $runspacePool.Dispose()
}
else {
    foreach ($fmt in $reportFormats) {
        Write-Step "Generating $fmt report…" 'INFO'
        try {
            $file = switch ($fmt) {
                'HTML'     { New-HTMLReport    -Findings $allFindings -PostureGrade $postureGrade -RemediationRoadmap $remediationRoad -QuickWins $quickWins -OutputPath $OutputPath -ReportTitle 'AD Security Assessment' -OrgName $OrgName }
                'JSON'     { New-JSONReport    -Findings $allFindings -PostureGrade $postureGrade -RemediationRoadmap $remediationRoad -Metadata $reportMeta  -OutputPath $OutputPath }
                'CSV'      { New-CSVReport     -Findings $allFindings -OutputPath $OutputPath }
                'Markdown' { New-MarkdownReport -Findings $allFindings -PostureGrade $postureGrade -OutputPath $OutputPath }
                'CEF'      { New-CEFReport      -Findings $allFindings -OutputPath $OutputPath }
                'Splunk'   { New-SplunkReport   -Findings $allFindings -OutputPath $OutputPath }
            }
            if ($file) {
                $generatedFiles += $file
                Write-Step "  → $file" 'OK'
            }
        }
        catch { Write-Step "  Failed to generate $fmt report: $_" 'WARN' }
    }
}

# SIEM export if requested
if ($SIEMExport -and $reportFormats -notcontains 'CEF') {
    Write-Step "Generating SIEM export (CEF + Splunk)…" 'INFO'
    try {
        $cefFile    = New-CEFReport    -Findings $allFindings -OutputPath $OutputPath
        $splunkFile = New-SplunkReport -Findings $allFindings -OutputPath $OutputPath
        $generatedFiles += $cefFile, $splunkFile
        Write-Step "  → CEF: $cefFile" 'OK'
        Write-Step "  → Splunk: $splunkFile" 'OK'
    }
    catch { Write-Step "  SIEM export failed: $_" 'WARN' }
}

#endregion

#region Workflow Integration

# Jira integration
if (-not [string]::IsNullOrEmpty($JiraUrl) -and -not [string]::IsNullOrEmpty($JiraProject)) {
    Write-Step "=== Workflow Integration: Jira ===" 'SECTION'
    if ([string]::IsNullOrEmpty($JiraUser) -or [string]::IsNullOrEmpty($JiraToken)) {
        Write-Step "JiraUser and JiraToken are required for Jira integration." 'WARN'
    }
    else {
        try {
            $jiraIssues = Export-ToJira -Findings $allFindings `
                -JiraUrl $JiraUrl -ProjectKey $JiraProject `
                -Username $JiraUser -ApiToken $JiraToken `
                -MinSeverity 'High'
            Write-Step "Created $($jiraIssues.Count) Jira issue(s)" 'OK'
            foreach ($issue in $jiraIssues) {
                Write-Step "  → $($issue.JiraKey): $($issue.JiraUrl)" 'INFO'
            }
        }
        catch { Write-Step "Jira integration failed: $_" 'WARN' }
    }
}

# ServiceNow integration
if (-not [string]::IsNullOrEmpty($ServiceNowUrl)) {
    Write-Step "=== Workflow Integration: ServiceNow ===" 'SECTION'
    if ([string]::IsNullOrEmpty($ServiceNowUser) -or [string]::IsNullOrEmpty($ServiceNowPass)) {
        Write-Step "ServiceNowUser and ServiceNowPass are required for ServiceNow integration." 'WARN'
    }
    else {
        try {
            $snowRecords = Export-ToServiceNow -Findings $allFindings `
                -InstanceUrl $ServiceNowUrl `
                -Username $ServiceNowUser -Password $ServiceNowPass `
                -MinSeverity 'High'
            Write-Step "Created $($snowRecords.Count) ServiceNow incident(s)" 'OK'
            foreach ($rec in $snowRecords) {
                Write-Step "  → $($rec.Number): $($rec.RecordUrl)" 'INFO'
            }
        }
        catch { Write-Step "ServiceNow integration failed: $_" 'WARN' }
    }
}

#endregion

#region Monitoring Mode Alerting

if ($Mode -eq 'Monitoring' -and -not [string]::IsNullOrEmpty($AlertEmail)) {
    Write-Step "=== Monitoring: Drift Alerting ===" 'SECTION'

    try {
        # Compare current snapshot to the previous one
        $snapshots = Get-Snapshots
        $driftData = $null

        if ($snapshots.Count -ge 2) {
            $prev    = @($snapshots)[-2]
            $current = @($snapshots)[-1]
            $driftData = Compare-Snapshots -BaselineId $prev.SnapshotId -CurrentId $current.SnapshotId
        }

        # Collect findings that cross the alerting threshold
        $critHigh = @($allFindings | Where-Object { $_.Severity -in @('Critical','High') })
        $hasDrift = $null -ne $driftData -and (
            $driftData.TotalAdded -gt 0 -or $driftData.TotalRemoved -gt 0 -or $driftData.TotalModified -gt 0)

        $shouldAlert = ($critHigh.Count -gt 0) -or ($AlertOnDrift -and $hasDrift)

        if ($shouldAlert) {
            Write-Step "Alert threshold reached. Sending email to $AlertEmail…" 'INFO'
            $subject = "[AD-Wall] $Mode Alert — Domain: $domainName — $(Get-Date -Format 'dd MMM yyyy HH:mm')"

            $body = @"
AD-Wall Security Alert
======================
Domain    : $domainName
Mode      : $Mode
Scan Time : $(Get-Date -Format 'dd MMM yyyy HH:mm:ss')
Grade     : $(if ($postureGrade) { "$($postureGrade.Grade) ($($postureGrade.Score)/100)" } else { 'N/A' })

Critical Findings : $(@($allFindings | Where-Object Severity -eq 'Critical').Count)
High Findings     : $(@($allFindings | Where-Object Severity -eq 'High').Count)
Total Findings    : $($allFindings.Count)

$(if ($hasDrift) {
"--- DRIFT DETECTED ---
Added   : $($driftData.TotalAdded)
Removed : $($driftData.TotalRemoved)
Modified: $($driftData.TotalModified)
"})

Top Critical/High Findings:
$($critHigh | Select-Object -First 10 | ForEach-Object { "  [$($_.Severity)] $($_.RuleId) — $($_.Title)" } | Out-String)

Review the full report at: $OutputPath
"@

            $mailParams = @{
                To         = $AlertEmail
                Subject    = $subject
                Body       = $body
                SmtpServer = if ($AlertSmtpServer) { $AlertSmtpServer } else { 'localhost' }
                Port       = $AlertSmtpPort
                UseSsl     = ($AlertSmtpPort -eq 587 -or $AlertSmtpPort -eq 465)
            }
            if ($AlertSmtpCredential) { $mailParams.Credential = $AlertSmtpCredential }

            try {
                Send-MailMessage @mailParams
                Write-Step "Alert email sent to $AlertEmail" 'OK'
            }
            catch { Write-Step "Email send failed: $_" 'WARN' }
        }
        else {
            Write-Step "No alerting threshold reached for this scan." 'INFO'
        }
    }
    catch { Write-Step "Monitoring alerting error: $_" 'WARN' }
}

#endregion

#region Dashboard

if ($LaunchDashboard) {
    Write-Step "=== Phase 7: Launching Web Dashboard ===" 'SECTION'

    $appPy = Join-Path $ScriptRoot 'src\dashboard\app.py'
    if (-not (Test-Path $appPy)) {
        Write-Step "Dashboard app.py not found at: $appPy" 'WARN'
    }
    else {
        # Determine Python executable
        $pythonCmd = $null
        foreach ($py in @('python3','python','py')) {
            if (Get-Command $py -ErrorAction SilentlyContinue) {
                $pythonCmd = $py; break
            }
        }

        if ($null -eq $pythonCmd) {
            Write-Step "Python not found. Install Python 3 to use the dashboard." 'WARN'
        }
        else {
            Write-Step "Installing Python dependencies…" 'INFO'
            try {
                $reqPath = Join-Path $ScriptRoot 'requirements.txt'
                & $pythonCmd -m pip install -r $reqPath --quiet
            }
            catch { Write-Step "pip install warning: $_" 'WARN' }

            Write-Step "Starting dashboard on http://localhost:$DashboardPort" 'INFO'
            $env:ADWALL_DATA_DIR = $OutputPath
            $env:ADWALL_PORT     = "$DashboardPort"

            $job = Start-Process -FilePath $pythonCmd `
                -ArgumentList $appPy `
                -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $OutputPath 'dashboard.log') `
                -RedirectStandardError  (Join-Path $OutputPath 'dashboard_err.log')

            Start-Sleep -Seconds 2
            Write-Step "Dashboard launched (PID: $($job.Id)). Open: http://localhost:$DashboardPort" 'OK'

            try { Start-Process "http://localhost:$DashboardPort" } catch {}
        }
    }
}

#endregion

#region Summary

$elapsed = ((Get-Date) - $Script:StartTime).ToString('mm\:ss')

Write-Host ""
Write-Host " ═══════════════════════════════════════════" -ForegroundColor DarkBlue
Write-Host "   AD-Wall Assessment Complete ($elapsed)" -ForegroundColor DarkBlue
Write-Host " ═══════════════════════════════════════════" -ForegroundColor DarkBlue
Write-Host ""

if ($postureGrade) {
    $gradeColour = switch ($postureGrade.Grade) {
        'A' { 'Green' } 'B' { 'Cyan' } 'C' { 'Yellow' } 'D' { 'Red' } 'F' { 'Red' } default { 'White' }
    }
    Write-Host "  Overall Grade : " -NoNewline
    Write-Host "$($postureGrade.Grade) ($($postureGrade.Score)/100)" -ForegroundColor $gradeColour
    Write-Host "  Assessment    : $($postureGrade.Description)"
    Write-Host "  Critical      : $($postureGrade.CriticalCount)" -ForegroundColor Red
    Write-Host "  High          : $($postureGrade.HighCount)"     -ForegroundColor Yellow
    Write-Host "  Medium        : $($postureGrade.MediumCount)"   -ForegroundColor Cyan
    Write-Host "  Low           : $($postureGrade.LowCount)"      -ForegroundColor Green
    Write-Host ""
}

Write-Host "  Generated files:" -ForegroundColor DarkCyan
foreach ($f in $generatedFiles) {
    Write-Host "    $f"
}
Write-Host ""

# Return findings for pipeline use
return $allFindings

#endregion
