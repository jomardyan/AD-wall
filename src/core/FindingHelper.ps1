#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Finding Helper — shared factory function for security finding objects.
.DESCRIPTION
    Provides a single, canonical New-Finding function used by every analysis module.
    Centralising the factory eliminates the six near-identical local copies that
    previously lived in ComplianceCheck, ConfigGpo, DetectionEngineering, ExploitVuln,
    IdentityPrivilege, and PersistenceBackdoor.

    Each module loads this file first (dot-sourced via Invoke-ADWall.ps1), then calls
    New-Finding with the parameters relevant to its domain.  Optional parameters
    (CISControl, NISTControl, CVEReferences) default to empty values so modules that
    do not need them incur no overhead.

    New-ATKFinding is a thin convenience wrapper used by OffensiveTechniques.ps1 that
    fixes the Category to 'Attack Techniques' so callers in that module do not need
    to repeat the string on every call.

.NOTES
    Author  : AD-Wall Project
    Version : 1.0.0
#>

Set-StrictMode -Version Latest

function New-Finding {
    <#
    .SYNOPSIS
        Creates a normalised security-finding object.
    .DESCRIPTION
        Constructs a [PSCustomObject] with all fields expected by the RuleEngine,
        RiskEngine, ReportGenerator, and WorkflowExport subsystems.  Every module
        in AD-Wall calls this function instead of building the object inline so that
        the schema remains consistent.

        Mandatory fields: RuleId, Title, Severity, Description, Remediation.
        AffectedObjects is optional and defaults to an empty array — pass an explicit
        list when the finding relates to specific AD objects.  All other parameters are
        optional and default to empty values.
    .PARAMETER RuleId
        Unique rule identifier (e.g. 'IP-001', 'CG-001', 'ATK-003').
    .PARAMETER Title
        Short human-readable title for the finding.
    .PARAMETER Severity
        Severity level — one of: Critical, High, Medium, Low, Informational.
    .PARAMETER Category
        Logical category string used for grouping in reports (e.g. 'Identity & Privilege').
        Defaults to empty string; Invoke-FindingEnrichment in RuleEngine.ps1 overwrites
        this with the canonical value from the rule catalog.
    .PARAMETER Description
        Full prose description of the issue.
    .PARAMETER AffectedObjects
        Array of affected AD object names, DNs, or description strings.
        Null / empty entries are filtered out automatically.
    .PARAMETER Remediation
        Actionable remediation guidance.
    .PARAMETER MitreAttack
        MITRE ATT&CK technique reference (e.g. 'T1558.003 - Kerberoasting').
    .PARAMETER CISControl
        CIS Benchmark control reference (e.g. 'CIS-AD-1.1.1').  Used by ComplianceCheck.
    .PARAMETER NISTControl
        NIST SP 800-53 control reference (e.g. 'IA-5(1)').  Used by ComplianceCheck.
    .PARAMETER CVEReferences
        Array of CVE IDs related to the finding (e.g. @('CVE-2020-1472')).
        Used by ExploitVuln.
    .PARAMETER ExtraData
        Free-form hashtable for module-specific supplemental data that does not fit
        the standard fields.
    .EXAMPLE
        New-Finding -RuleId 'IP-001' -Title 'Excessive DA membership' -Severity 'High' `
            -Description 'Too many accounts in Domain Admins.' `
            -AffectedObjects @('jsmith','svc_backup') `
            -Remediation 'Remove non-essential accounts.' `
            -MitreAttack 'T1078.002'
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleId,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity,

        # Category is intentionally optional here; RuleEngine enrichment populates it
        # from the rule catalog so every finding always ends up with the canonical value.
        [string]$Category = '',

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$AffectedObjects = @(),

        [Parameter(Mandatory = $true)]
        [string]$Remediation,

        [string]$MitreAttack    = '',

        # Compliance-specific (ComplianceCheck.ps1)
        [string]$CISControl     = '',
        [string]$NISTControl    = '',

        # Vulnerability-specific (ExploitVuln.ps1)
        [string[]]$CVEReferences = @(),

        [hashtable]$ExtraData   = @{}
    )

    # Filter nulls/empties from affected-objects list once so consumers can rely on the count.
    $cleanObjects = @($AffectedObjects | Where-Object { $_ })

    return [PSCustomObject]@{
        RuleId          = $RuleId
        Title           = $Title
        Severity        = $Severity
        Category        = $Category
        Description     = $Description
        AffectedObjects = $cleanObjects
        AffectedCount   = $cleanObjects.Count
        Remediation     = $Remediation
        MitreAttack     = $MitreAttack
        CISControl      = $CISControl
        NISTControl     = $NISTControl
        CVEReferences   = $CVEReferences
        ExtraData       = $ExtraData
        DetectedAt      = (Get-Date -Format 'o')
    }
}

function New-ATKFinding {
    <#
    .SYNOPSIS
        Convenience wrapper around New-Finding for the Attack Techniques module.
    .DESCRIPTION
        Fixes Category to 'Attack Techniques' so that callers in OffensiveTechniques.ps1
        do not need to repeat the string on every call.  All parameters are forwarded
        to New-Finding verbatim.
    .PARAMETER RuleId
        ATK-series rule identifier (e.g. 'ATK-001').
    .PARAMETER Title
        Short human-readable title.
    .PARAMETER Severity
        Severity level — Critical, High, Medium, Low, or Informational.
    .PARAMETER Description
        Full prose description.
    .PARAMETER AffectedObjects
        Array of affected AD object names or descriptions.
    .PARAMETER Remediation
        Actionable remediation guidance.
    .PARAMETER MitreAttack
        MITRE ATT&CK technique reference.
    .PARAMETER ExtraData
        Free-form hashtable for supplemental data.
    .EXAMPLE
        New-ATKFinding -RuleId 'ATK-002' -Title 'MachineAccountQuota > 0' -Severity 'High' ...
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]  [string]$RuleId,
        [Parameter(Mandatory = $true)]  [string]$Title,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity,
        [Parameter(Mandatory = $true)]  [string]$Description,
        [Parameter(Mandatory = $false)]
        [AllowNull()][AllowEmptyCollection()]
        [object[]]$AffectedObjects = @(),
        [Parameter(Mandatory = $true)]  [string]$Remediation,
        [string]$MitreAttack = '',
        [hashtable]$ExtraData = @{}
    )

    # Delegate to New-Finding with the fixed category for this module.
    return New-Finding `
        -RuleId          $RuleId `
        -Title           $Title `
        -Severity        $Severity `
        -Category        'Attack Techniques' `
        -Description     $Description `
        -AffectedObjects $AffectedObjects `
        -Remediation     $Remediation `
        -MitreAttack     $MitreAttack `
        -ExtraData       $ExtraData
}
