#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Configuration Management Module
.DESCRIPTION
    Provides centralized configuration management for the AD-Wall security assessment tool.
    Handles reading, writing, validating, and persisting configuration settings.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region Default Configuration

$Script:ADWallConfigDefaults = @{
    # Domain Settings
    Domain = @{
        Controller      = $null          # Target DC FQDN/IP; auto-discovered if null
        Name            = $null          # FQDN of domain; auto-discovered if null
        Credential      = $null          # PSCredential object; uses current user if null
        Port            = 389            # LDAP port (389 or 636 for LDAPS)
        UseSSL          = $false         # Use LDAPS
        UseGlobalCatalog = $false        # Use GC port (3268/3269)
        ConnectTimeout  = 30             # Seconds
        SearchTimeout   = 120            # Seconds
        PageSize        = 1000           # LDAP query page size
    }

    # Scan Settings
    Scan = @{
        Mode            = 'Assessment'   # Assessment | Validation | Monitoring
        RedTeam         = $false         # Enable write/exploit operations
        SafeMode        = $true          # Enforce read-only operations
        Modules         = @('Identity','Config','Exploit','Persistence')
        MaxThreads      = 4              # Parallel collection threads
        StaleThresholdDays = 90          # Days inactive before account flagged stale
        EnableEventLogs = $true          # Collect event logs
        EventLogDays    = 7              # Days of event logs to collect
        AdcsEnabled     = $true          # Collect AD CS data
        SmbCollect      = $true          # Collect SMB/WMI data
    }

    # Output Settings
    Output = @{
        Path            = '.\ADWall-Output'
        Formats         = @('HTML','JSON')   # HTML | JSON | CSV | Markdown | All
        ReportTitle     = 'AD-Wall Security Assessment'
        IncludeRawData  = $false
        CompressOutput  = $false
        TimestampFormat = 'yyyyMMdd-HHmmss'
    }

    # Risk Engine Settings
    Risk = @{
        CriticalThreshold = 80
        HighThreshold     = 60
        MediumThreshold   = 40
        LowThreshold      = 20
        BusinessCriticalityWeight = 0.20
        ExploitabilityWeight      = 0.35
        SeverityWeight            = 0.35
        ExposureAgeWeight         = 0.10
    }

    # Dashboard Settings
    Dashboard = @{
        Enabled  = $false
        Port     = 5000
        Host     = '127.0.0.1'
        AutoOpen = $true
    }

    # Logging
    Logging = @{
        Level       = 'Info'   # Debug | Info | Warning | Error
        ToFile      = $true
        LogPath     = '.\ADWall-Output\adwall.log'
        MaxSizeMB   = 10
    }
}

#endregion

#region Module State

$Script:CurrentConfig = $null
$Script:ConfigFilePath = $null

#endregion

#region Functions

function Get-ADWallConfig {
    <#
    .SYNOPSIS
        Returns the current AD-Wall configuration.
    .DESCRIPTION
        Returns the active configuration hashtable. Initializes defaults if no config has been loaded.
    .PARAMETER Section
        Optional. Returns only the specified top-level configuration section.
    .EXAMPLE
        $cfg = Get-ADWallConfig
        $domainCfg = Get-ADWallConfig -Section Domain
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Domain','Scan','Output','Risk','Dashboard','Logging')]
        [string]$Section
    )

    if ($null -eq $Script:CurrentConfig) {
        Write-Verbose "No configuration loaded; initializing with defaults."
        $Script:CurrentConfig = Copy-HashtableDeep $Script:ADWallConfigDefaults
    }

    if ($PSBoundParameters.ContainsKey('Section')) {
        return $Script:CurrentConfig[$Section]
    }

    return $Script:CurrentConfig
}

function Set-ADWallConfig {
    <#
    .SYNOPSIS
        Updates one or more configuration values.
    .DESCRIPTION
        Merges supplied key/value pairs into the current configuration. Validates the resulting
        configuration before applying changes.
    .PARAMETER Section
        The top-level configuration section to update (e.g., 'Domain', 'Scan').
    .PARAMETER Key
        The setting key within the section.
    .PARAMETER Value
        The new value.
    .PARAMETER ConfigHash
        A full or partial configuration hashtable to merge into the current config.
    .EXAMPLE
        Set-ADWallConfig -Section Scan -Key RedTeam -Value $true
        Set-ADWallConfig -ConfigHash @{ Scan = @{ Mode = 'Monitoring' } }
    #>
    [CmdletBinding(DefaultParameterSetName = 'KeyValue', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'KeyValue')]
        [ValidateSet('Domain','Scan','Output','Risk','Dashboard','Logging')]
        [string]$Section,

        [Parameter(Mandatory = $true, ParameterSetName = 'KeyValue')]
        [string]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = 'KeyValue')]
        [object]$Value,

        [Parameter(Mandatory = $true, ParameterSetName = 'Hash')]
        [hashtable]$ConfigHash
    )

    if ($null -eq $Script:CurrentConfig) {
        $Script:CurrentConfig = Copy-HashtableDeep $Script:ADWallConfigDefaults
    }

    if ($PSCmdlet.ParameterSetName -eq 'KeyValue') {
        if ($PSCmdlet.ShouldProcess("Configuration[$Section][$Key]", "Set value to '$Value'")) {
            $Script:CurrentConfig[$Section][$Key] = $Value
            Write-Verbose "Configuration updated: [$Section][$Key] = '$Value'"
        }
    }
    else {
        if ($PSCmdlet.ShouldProcess("Configuration", "Merge configuration hashtable")) {
            foreach ($sectionKey in $ConfigHash.Keys) {
                if ($Script:CurrentConfig.ContainsKey($sectionKey)) {
                    foreach ($itemKey in $ConfigHash[$sectionKey].Keys) {
                        $Script:CurrentConfig[$sectionKey][$itemKey] = $ConfigHash[$sectionKey][$itemKey]
                        Write-Verbose "Configuration updated: [$sectionKey][$itemKey]"
                    }
                }
                else {
                    $Script:CurrentConfig[$sectionKey] = $ConfigHash[$sectionKey]
                    Write-Verbose "Configuration section added: [$sectionKey]"
                }
            }
        }
    }

    $validation = Test-ADWallConfig -Config $Script:CurrentConfig
    if (-not $validation.IsValid) {
        Write-Warning "Configuration validation failed:"
        $validation.Errors | ForEach-Object { Write-Warning "  - $_" }
    }
}

function Save-ADWallConfig {
    <#
    .SYNOPSIS
        Persists the current configuration to a JSON file.
    .DESCRIPTION
        Serializes the current configuration (excluding credentials) to a JSON file for
        reuse across sessions.
    .PARAMETER Path
        File path to save the configuration. Defaults to .\adwall.config.json.
    .EXAMPLE
        Save-ADWallConfig -Path C:\ADWall\myconfig.json
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Path = '.\adwall.config.json'
    )

    if ($null -eq $Script:CurrentConfig) {
        Write-Warning "No configuration to save. Using defaults."
        $Script:CurrentConfig = Copy-HashtableDeep $Script:ADWallConfigDefaults
    }

    # Deep-copy, strip credentials to avoid storing secrets
    $configToSave = Copy-HashtableDeep $Script:CurrentConfig
    if ($configToSave.Domain.ContainsKey('Credential')) {
        $configToSave.Domain['Credential'] = $null
    }

    if ($PSCmdlet.ShouldProcess($Path, "Save AD-Wall configuration")) {
        try {
            $parentDir = Split-Path -Parent $Path
            if ($parentDir -and -not (Test-Path $parentDir)) {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
            }
            $configToSave | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
            $Script:ConfigFilePath = $Path
            Write-Verbose "Configuration saved to: $Path"
        }
        catch {
            Write-Error "Failed to save configuration to '$Path': $_"
        }
    }
}

function Load-ADWallConfig {
    <#
    .SYNOPSIS
        Loads configuration from a JSON file.
    .DESCRIPTION
        Reads a previously saved configuration file and merges it with defaults.
        Missing keys are filled in with default values.
    .PARAMETER Path
        File path of the configuration to load.
    .EXAMPLE
        Load-ADWallConfig -Path C:\ADWall\myconfig.json
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$Path
    )

    try {
        Write-Verbose "Loading configuration from: $Path"
        $raw = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json

        # Start with defaults and overlay saved values
        $loaded = Copy-HashtableDeep $Script:ADWallConfigDefaults
        $rawHash = ConvertPSObjectToHashtable $raw

        foreach ($section in $rawHash.Keys) {
            if ($loaded.ContainsKey($section)) {
                foreach ($key in $rawHash[$section].Keys) {
                    $loaded[$section][$key] = $rawHash[$section][$key]
                }
            }
            else {
                $loaded[$section] = $rawHash[$section]
            }
        }

        $validation = Test-ADWallConfig -Config $loaded
        if (-not $validation.IsValid) {
            Write-Warning "Loaded configuration has validation errors:"
            $validation.Errors | ForEach-Object { Write-Warning "  - $_" }
        }

        $Script:CurrentConfig = $loaded
        $Script:ConfigFilePath = $Path
        Write-Verbose "Configuration loaded successfully."
        return $Script:CurrentConfig
    }
    catch {
        Write-Error "Failed to load configuration from '$Path': $_"
        return $null
    }
}

function Test-ADWallConfig {
    <#
    .SYNOPSIS
        Validates a configuration hashtable.
    .DESCRIPTION
        Checks that required fields have valid types and acceptable values.
    .PARAMETER Config
        The configuration hashtable to validate.
    .OUTPUTS
        PSCustomObject with IsValid (bool) and Errors (string[]) properties.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    # Validate Domain section
    if ($Config.ContainsKey('Domain')) {
        $d = $Config.Domain
        if ($d.Port -isnot [int] -or $d.Port -lt 1 -or $d.Port -gt 65535) {
            $errors.Add("Domain.Port must be an integer between 1 and 65535.")
        }
        if ($d.ConnectTimeout -isnot [int] -or $d.ConnectTimeout -lt 1) {
            $errors.Add("Domain.ConnectTimeout must be a positive integer.")
        }
        if ($d.PageSize -isnot [int] -or $d.PageSize -lt 100 -or $d.PageSize -gt 10000) {
            $errors.Add("Domain.PageSize must be between 100 and 10000.")
        }
    }

    # Validate Scan section
    if ($Config.ContainsKey('Scan')) {
        $s = $Config.Scan
        $validModes = @('Assessment','Validation','Monitoring')
        if ($s.Mode -notin $validModes) {
            $errors.Add("Scan.Mode must be one of: $($validModes -join ', ').")
        }
        if ($s.RedTeam -eq $true -and $s.SafeMode -eq $true) {
            $errors.Add("Scan.RedTeam and Scan.SafeMode cannot both be true. Disable SafeMode explicitly to enable RedTeam operations.")
        }
        if ($s.MaxThreads -isnot [int] -or $s.MaxThreads -lt 1 -or $s.MaxThreads -gt 16) {
            $errors.Add("Scan.MaxThreads must be between 1 and 16.")
        }
        if ($s.StaleThresholdDays -isnot [int] -or $s.StaleThresholdDays -lt 1) {
            $errors.Add("Scan.StaleThresholdDays must be a positive integer.")
        }
    }

    # Validate Risk section
    if ($Config.ContainsKey('Risk')) {
        $r = $Config.Risk
        $weights = @('BusinessCriticalityWeight','ExploitabilityWeight','SeverityWeight','ExposureAgeWeight')
        $totalWeight = 0
        foreach ($w in $weights) {
            if ($r[$w] -isnot [double] -and $r[$w] -isnot [decimal] -and $r[$w] -isnot [float] -and $r[$w] -isnot [int]) {
                $errors.Add("Risk.$w must be a numeric value.")
            }
            else {
                $totalWeight += [double]$r[$w]
            }
        }
        if ([Math]::Abs($totalWeight - 1.0) -gt 0.01) {
            $errors.Add("Risk weight factors must sum to 1.0 (current sum: $totalWeight).")
        }
    }

    # Validate Output section
    if ($Config.ContainsKey('Output')) {
        $validFormats = @('HTML','JSON','CSV','Markdown','All')
        foreach ($fmt in $Config.Output.Formats) {
            if ($fmt -notin $validFormats) {
                $errors.Add("Output.Formats contains invalid format '$fmt'. Valid: $($validFormats -join ', ').")
            }
        }
    }

    return [PSCustomObject]@{
        IsValid = ($errors.Count -eq 0)
        Errors  = $errors.ToArray()
    }
}

#endregion

#region Private Helpers

function Copy-HashtableDeep {
    <#
    .SYNOPSIS
        Creates a deep copy of a hashtable.
    #>
    param([hashtable]$Source)

    $copy = @{}
    foreach ($key in $Source.Keys) {
        if ($Source[$key] -is [hashtable]) {
            $copy[$key] = Copy-HashtableDeep $Source[$key]
        }
        elseif ($Source[$key] -is [array]) {
            $copy[$key] = $Source[$key].Clone()
        }
        else {
            $copy[$key] = $Source[$key]
        }
    }
    return $copy
}

function ConvertPSObjectToHashtable {
    <#
    .SYNOPSIS
        Recursively converts a PSCustomObject (from ConvertFrom-Json) to a hashtable.
    #>
    param([object]$InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $hash = @{}
        $InputObject.PSObject.Properties | ForEach-Object {
            $hash[$_.Name] = ConvertPSObjectToHashtable $_.Value
        }
        return $hash
    }
    elseif ($InputObject -is [array]) {
        return $InputObject | ForEach-Object { ConvertPSObjectToHashtable $_ }
    }
    else {
        return $InputObject
    }
}

#endregion

Export-ModuleMember -Function Get-ADWallConfig, Set-ADWallConfig, Save-ADWallConfig,
                               Load-ADWallConfig, Test-ADWallConfig
