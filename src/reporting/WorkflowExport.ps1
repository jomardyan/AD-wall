#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Workflow & SIEM Export Module
.DESCRIPTION
    Provides integrations for exporting AD-Wall findings to external systems:
    - Jira (REST API v2): creates issues for critical/high findings
    - ServiceNow (REST API): creates incidents for critical/high findings
    - CEF (Common Event Format): generates SIEM-compatible syslog messages
    - Splunk JSON: generates Splunk HEC-compatible JSON events
    - Windows Event Log: forwards findings as local Windows events

    All functions support -WhatIf to preview without making changes.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region CEF / SIEM Export

function New-CEFReport {
    <#
    .SYNOPSIS
        Generates a CEF (Common Event Format) file for SIEM ingestion.
    .DESCRIPTION
        Exports all findings as CEF-formatted syslog messages that can be ingested
        by any SIEM supporting CEF (ArcSight, Splunk, QRadar, Sentinel, etc.).

        CEF format:
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

        Severity mapping: Critical=10, High=8, Medium=5, Low=3, Informational=1
    .PARAMETER Findings
        Array of finding objects from Invoke-AllChecks.
    .PARAMETER OutputPath
        Directory to save the .cef file.
    .PARAMETER SyslogHost
        Optional. If provided, sends CEF messages to this syslog host (UDP 514).
    .PARAMETER SyslogPort
        Syslog port. Default: 514.
    .EXAMPLE
        New-CEFReport -Findings $findings -OutputPath 'C:\ADWall\Reports'
        New-CEFReport -Findings $findings -OutputPath 'C:\ADWall\Reports' -SyslogHost 'siem.corp.local'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$SyslogHost,

        [Parameter(Mandatory = $false)]
        [int]$SyslogPort = 514
    )

    $severityMap = @{ Critical=10; High=8; Medium=5; Low=3; Informational=1 }
    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputFile  = Join-Path $OutputPath "ADWall_SIEM_${timestamp}.cef"

    $cefLines = [System.Collections.Generic.List[string]]::new()

    foreach ($finding in $Findings) {
        $sev    = if ($severityMap.ContainsKey($finding.Severity)) { $severityMap[$finding.Severity] } else { 1 }
        $ruleId = if ($null -ne $finding.RuleId)        { $finding.RuleId }        else { 'UNKNOWN' }
        $title  = (if ($null -ne $finding.Title)        { $finding.Title }        else { '' }) -replace '\|','/'
        $desc   = (if ($null -ne $finding.Description)  { $finding.Description }  else { '' }) -replace '\|','/' -replace '\r?\n',' '
        $remedi = (if ($null -ne $finding.Remediation)  { $finding.Remediation }  else { '' }) -replace '\|','/' -replace '\r?\n',' '
        $mitre  = (if ($null -ne $finding.MitreAttack)  { $finding.MitreAttack }  else { '' }) -replace '\|','/'
        $affCnt = if ($null -ne $finding.AffectedCount) { $finding.AffectedCount } else { 0 }
        $detAt  = if ($null -ne $finding.DetectedAt)    { $finding.DetectedAt }    else { Get-Date -Format 'o' }

        # CEF extension fields (key=value pairs, space separated)
        $ext = "msg=$desc act=$remedi cs1=$mitre cs1Label=MitreAttack cnt=$affCnt rt=$detAt"

        $cefLine = "CEF:0|AD-Wall|AD-Wall|1.0.0|$ruleId|$title|$sev|$ext"
        $cefLines.Add($cefLine)

        # Optionally send to syslog host
        if ($PSBoundParameters.ContainsKey('SyslogHost') -and -not [string]::IsNullOrEmpty($SyslogHost)) {
            if ($PSCmdlet.ShouldProcess("$SyslogHost:$SyslogPort", "Send CEF syslog: $ruleId")) {
                try {
                    $udpClient = [System.Net.Sockets.UdpClient]::new()
                    $bytes     = [System.Text.Encoding]::ASCII.GetBytes("<14>$cefLine")
                    $udpClient.Send($bytes, $bytes.Length, $SyslogHost, $SyslogPort) | Out-Null
                    $udpClient.Close()
                }
                catch { Write-Warning "Syslog send failed for $ruleId : $_" }
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($outputFile, 'Write CEF report')) {
        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $cefLines | Set-Content -Path $outputFile -Encoding UTF8
        Write-Verbose "CEF report written: $outputFile ($($cefLines.Count) events)"
    }

    return $outputFile
}

#endregion

#region Splunk JSON Export

function New-SplunkReport {
    <#
    .SYNOPSIS
        Generates Splunk HTTP Event Collector (HEC)-compatible JSON for each finding.
    .DESCRIPTION
        Creates a NDJSON file (newline-delimited JSON) where each line is a valid
        Splunk HEC event payload. Can also POST directly to a Splunk HEC endpoint.
    .PARAMETER Findings
        Array of finding objects from Invoke-AllChecks.
    .PARAMETER OutputPath
        Directory to save the .json file.
    .PARAMETER HECUrl
        Optional Splunk HEC URL (e.g. https://splunk.corp.local:8088/services/collector/event)
    .PARAMETER HECToken
        Splunk HEC token. Required when HECUrl is provided.
    .PARAMETER SourceType
        Splunk sourcetype. Default: 'adwall:finding'
    .PARAMETER Index
        Splunk index. Default: 'security'
    .EXAMPLE
        New-SplunkReport -Findings $findings -OutputPath 'C:\ADWall\Reports'
        New-SplunkReport -Findings $findings -OutputPath '.' -HECUrl 'https://splunk:8088/...' -HECToken 'abc123'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$HECUrl,

        [Parameter(Mandatory = $false)]
        [string]$HECToken,

        [Parameter(Mandatory = $false)]
        [string]$SourceType = 'adwall:finding',

        [Parameter(Mandatory = $false)]
        [string]$Index = 'security'
    )

    $timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputFile  = Join-Path $OutputPath "ADWall_Splunk_${timestamp}.json"
    $events      = [System.Collections.Generic.List[string]]::new()

    foreach ($finding in $Findings) {
        $epochTime = [Math]::Round(([DateTimeOffset](Get-Date)).ToUnixTimeMilliseconds() / 1000.0, 3)

        $event = @{
            time       = $epochTime
            sourcetype = $SourceType
            index      = $Index
            source     = 'ADWall'
            event      = @{
                rule_id              = $finding.RuleId
                title                = $finding.Title
                severity             = $finding.Severity
                category             = $finding.Category
                description          = $finding.Description
                affected_objects     = $finding.AffectedObjects
                affected_count       = $finding.AffectedCount
                remediation          = $finding.Remediation
                mitre_attack         = $finding.MitreAttack
                detected_at          = $finding.DetectedAt
                verification_command = if ($finding.VerificationCommand) { $finding.VerificationCommand } else { '' }
            }
        }

        $events.Add(($event | ConvertTo-Json -Compress -Depth 5))
    }

    if ($PSCmdlet.ShouldProcess($outputFile, 'Write Splunk JSON')) {
        if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $events | Set-Content -Path $outputFile -Encoding UTF8
    }

    # POST to Splunk HEC if configured
    if (-not [string]::IsNullOrEmpty($HECUrl) -and -not [string]::IsNullOrEmpty($HECToken)) {
        if ($PSCmdlet.ShouldProcess($HECUrl, 'POST findings to Splunk HEC')) {
            $headers = @{ Authorization = "Splunk $HECToken"; 'Content-Type' = 'application/json' }
            $batchSize = 50
            for ($i = 0; $i -lt $events.Count; $i += $batchSize) {
                $batch = $events[$i..([Math]::Min($i + $batchSize - 1, $events.Count - 1))] -join "`n"
                try {
                    Invoke-RestMethod -Uri $HECUrl -Method POST -Headers $headers -Body $batch -ErrorAction Stop | Out-Null
                    Write-Verbose "Sent batch $([Math]::Floor($i/$batchSize)+1) to Splunk HEC"
                }
                catch { Write-Warning "Splunk HEC POST failed (batch $([Math]::Floor($i/$batchSize)+1)): $_" }
            }
        }
    }

    Write-Verbose "Splunk report written: $outputFile ($($events.Count) events)"
    return $outputFile
}

#endregion

#region Jira Integration

function Export-ToJira {
    <#
    .SYNOPSIS
        Creates Jira issues for Critical and High AD-Wall findings.
    .DESCRIPTION
        Uses the Jira REST API v2 to create issues for findings at or above the
        specified minimum severity. One issue is created per finding. Labels,
        priority, and description fields are populated from finding data.

        A "fix guide" section in the Jira description provides:
        - Why it matters (Description)
        - Exact AD objects affected (AffectedObjects)
        - Rollback-safe remediation steps (Remediation)
        - MITRE ATT&CK reference

        Requires: Jira URL, project key, and authentication (Basic or API token).
    .PARAMETER Findings
        Array of finding objects.
    .PARAMETER JiraUrl
        Base Jira URL (e.g. https://corp.atlassian.net).
    .PARAMETER ProjectKey
        Jira project key (e.g. SEC).
    .PARAMETER Username
        Jira username or email.
    .PARAMETER ApiToken
        Jira API token (Atlassian Cloud) or password (Jira Server).
    .PARAMETER MinSeverity
        Minimum severity to export. Default: High.
    .PARAMETER IssueType
        Jira issue type name. Default: Task.
    .PARAMETER Labels
        Additional labels to add to created issues.
    .PARAMETER DryRun
        Preview issues without creating them.
    .EXAMPLE
        Export-ToJira -Findings $findings -JiraUrl 'https://corp.atlassian.net' `
            -ProjectKey 'SEC' -Username 'admin@corp.com' -ApiToken 'abc123'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$JiraUrl,

        [Parameter(Mandatory = $true)]
        [string]$ProjectKey,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$ApiToken,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical','High','Medium','Low')]
        [string]$MinSeverity = 'High',

        [Parameter(Mandatory = $false)]
        [string]$IssueType = 'Task',

        [Parameter(Mandatory = $false)]
        [string[]]$Labels = @('AD-Wall','Security','ActiveDirectory'),

        [switch]$DryRun
    )

    $severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
    $minOrder      = $severityOrder[$MinSeverity]

    $filteredFindings = @($Findings | Where-Object {
        $severityOrder[$_.Severity] -le $minOrder
    })

    if ($filteredFindings.Count -eq 0) {
        Write-Verbose "No findings at or above '$MinSeverity' severity."
        return @()
    }

    # Build auth header
    $authBytes  = [System.Text.Encoding]::ASCII.GetBytes("${Username}:${ApiToken}")
    $authBase64 = [Convert]::ToBase64String($authBytes)
    $headers    = @{
        Authorization  = "Basic $authBase64"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }

    $priorityMap = @{ Critical='Highest'; High='High'; Medium='Medium'; Low='Low'; Informational='Lowest' }
    $apiUrl      = "$($JiraUrl.TrimEnd('/'))/rest/api/2/issue"
    $created     = [System.Collections.Generic.List[object]]::new()

    foreach ($finding in $filteredFindings) {
        $affectedStr = if (@($finding.AffectedObjects).Count -gt 0) {
            "* " + ($finding.AffectedObjects | Select-Object -First 20 | ForEach-Object { "`"$_`"" }) -join "`n* "
        } else { "None identified" }

        $description = @"
h2. Summary
$($finding.Description)

h2. Why it Matters
*Rule ID:* $($finding.RuleId) | *Severity:* $($finding.Severity) | *Category:* $($finding.Category)
*MITRE ATT&CK:* $($finding.MitreAttack)
*Detected At:* $($finding.DetectedAt)

h2. Affected AD Objects ($($finding.AffectedCount))
$affectedStr

h2. Rollback-Safe Remediation Steps
$($finding.Remediation)

h2. References
* MITRE ATT&CK: $($finding.MitreAttack)
* Generated by AD-Wall Security Assessment Platform
"@

        $payload = @{
            fields = @{
                project     = @{ key = $ProjectKey }
                summary     = "[AD-Wall] [$($finding.Severity)] $($finding.Title)"
                description = $description
                issuetype   = @{ name = $IssueType }
                priority    = @{ name = $priorityMap[$finding.Severity] }
                labels      = @($Labels + @("ADWall-$($finding.RuleId)", "Severity-$($finding.Severity)"))
            }
        } | ConvertTo-Json -Depth 5

        if ($DryRun) {
            Write-Host "[DRY RUN] Would create Jira issue: [AD-Wall] [$($finding.Severity)] $($finding.Title)"
            continue
        }

        if ($PSCmdlet.ShouldProcess($apiUrl, "Create Jira issue for $($finding.RuleId)")) {
            try {
                $response = Invoke-RestMethod -Uri $apiUrl -Method POST -Headers $headers -Body $payload -ErrorAction Stop
                $created.Add([PSCustomObject]@{
                    RuleId   = $finding.RuleId
                    JiraKey  = $response.key
                    JiraUrl  = "$($JiraUrl.TrimEnd('/'))/browse/$($response.key)"
                })
                Write-Verbose "Created Jira issue: $($response.key) for $($finding.RuleId)"
            }
            catch {
                Write-Warning "Failed to create Jira issue for $($finding.RuleId): $($_.Exception.Message)"
            }
        }
    }

    return $created.ToArray()
}

#endregion

#region ServiceNow Integration

function Export-ToServiceNow {
    <#
    .SYNOPSIS
        Creates ServiceNow incidents for Critical and High AD-Wall findings.
    .DESCRIPTION
        Uses the ServiceNow Table API to create Security Incidents (or standard
        Incidents) for findings at or above the specified minimum severity.

        A fix guide section in the work notes provides the complete remediation
        context: why it matters, affected objects, rollback-safe steps.
    .PARAMETER Findings
        Array of finding objects.
    .PARAMETER InstanceUrl
        ServiceNow instance URL (e.g. https://corp.service-now.com).
    .PARAMETER Username
        ServiceNow username.
    .PARAMETER Password
        ServiceNow password.
    .PARAMETER MinSeverity
        Minimum severity to export. Default: High.
    .PARAMETER Table
        ServiceNow table to create records in. Default: incident.
    .PARAMETER AssignmentGroup
        Optional assignment group name.
    .PARAMETER Category
        Incident category. Default: Security.
    .PARAMETER DryRun
        Preview incidents without creating them.
    .EXAMPLE
        Export-ToServiceNow -Findings $findings `
            -InstanceUrl 'https://corp.service-now.com' `
            -Username 'admin' -Password 'secret'
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$InstanceUrl,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical','High','Medium','Low')]
        [string]$MinSeverity = 'High',

        [Parameter(Mandatory = $false)]
        [string]$Table = 'incident',

        [Parameter(Mandatory = $false)]
        [string]$AssignmentGroup,

        [Parameter(Mandatory = $false)]
        [string]$Category = 'Security',

        [switch]$DryRun
    )

    $severityOrder  = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
    $minOrder       = $severityOrder[$MinSeverity]
    $urgencyMap     = @{ Critical=1; High=2; Medium=3; Low=4; Informational=4 }
    $impactMap      = @{ Critical=1; High=1; Medium=2; Low=3; Informational=3 }

    $filteredFindings = @($Findings | Where-Object {
        $severityOrder[$_.Severity] -le $minOrder
    })

    if ($filteredFindings.Count -eq 0) {
        Write-Verbose "No findings at or above '$MinSeverity' severity."
        return @()
    }

    $authBytes  = [System.Text.Encoding]::ASCII.GetBytes("${Username}:${Password}")
    $authBase64 = [Convert]::ToBase64String($authBytes)
    $headers    = @{
        Authorization  = "Basic $authBase64"
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
    }

    $apiUrl  = "$($InstanceUrl.TrimEnd('/'))/api/now/table/$Table"
    $created = [System.Collections.Generic.List[object]]::new()

    foreach ($finding in $filteredFindings) {
        $affectedStr = ($finding.AffectedObjects | Select-Object -First 20) -join ', '

        $workNotes = @"
=== AD-Wall Security Finding Fix Guide ===

Rule ID  : $($finding.RuleId)
Category : $($finding.Category)
Severity : $($finding.Severity)
Detected : $($finding.DetectedAt)
MITRE    : $($finding.MitreAttack)

--- WHY IT MATTERS ---
$($finding.Description)

--- AFFECTED AD OBJECTS ($($finding.AffectedCount)) ---
$affectedStr

--- ROLLBACK-SAFE REMEDIATION STEPS ---
$($finding.Remediation)

Generated by AD-Wall Security Assessment Platform
"@

        $payload = @{
            short_description = "[AD-Wall] [$($finding.Severity)] $($finding.Title)"
            description       = $finding.Description
            work_notes        = $workNotes
            category          = $Category
            urgency           = "$($urgencyMap[$finding.Severity])"
            impact            = "$($impactMap[$finding.Severity])"
        }

        if (-not [string]::IsNullOrEmpty($AssignmentGroup)) {
            $payload.assignment_group = $AssignmentGroup
        }

        $payloadJson = $payload | ConvertTo-Json -Depth 3

        if ($DryRun) {
            Write-Host "[DRY RUN] Would create ServiceNow $Table: [AD-Wall] [$($finding.Severity)] $($finding.Title)"
            continue
        }

        if ($PSCmdlet.ShouldProcess($apiUrl, "Create ServiceNow $Table for $($finding.RuleId)")) {
            try {
                $response = Invoke-RestMethod -Uri $apiUrl -Method POST -Headers $headers -Body $payloadJson -ErrorAction Stop
                $sysId    = $response.result.sys_id
                $number   = $response.result.number
                $created.Add([PSCustomObject]@{
                    RuleId    = $finding.RuleId
                    SysId     = $sysId
                    Number    = $number
                    RecordUrl = "$($InstanceUrl.TrimEnd('/'))/nav_to.do?uri=/$Table.do?sys_id=$sysId"
                })
                Write-Verbose "Created ServiceNow $Table: $number for $($finding.RuleId)"
            }
            catch {
                Write-Warning "Failed to create ServiceNow $Table for $($finding.RuleId): $($_.Exception.Message)"
            }
        }
    }

    return $created.ToArray()
}

#endregion

#region Fix Guide Generator

function Get-FindingFixGuide {
    <#
    .SYNOPSIS
        Generates a comprehensive fix guide for a single finding.
    .DESCRIPTION
        Returns a structured fix guide object and optionally a formatted text block
        covering all fields required by arch2.md:
        1. Why it matters (impact statement)
        2. Exact AD objects affected
        3. Rollback-safe remediation steps
        4. Verification commands (PowerShell commands to verify the fix)
    .PARAMETER Finding
        A single finding object.
    .PARAMETER Format
        Output format: Object (default), Text, HTML, Markdown.
    .EXAMPLE
        Get-FindingFixGuide -Finding $finding -Format Markdown
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Finding,

        [ValidateSet('Object','Text','HTML','Markdown')]
        [string]$Format = 'Object'
    )

    # Lookup table for verification commands by RuleId
    $verificationCmds = @{
        'IP-001' = 'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object SamAccountName, objectClass'
        'IP-002' = 'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object { $_.objectClass -eq "user" } | Get-ADUser -Properties ServicePrincipalNames | Where-Object { $_.ServicePrincipalNames }'
        'IP-003' = 'Get-ADGroupMember -Identity "Schema Admins" | Select-Object SamAccountName'
        'IP-010' = 'Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, ComplexityEnabled, LockoutThreshold'
        'IP-015' = 'Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | Select-Object SamAccountName'
        'IP-016' = 'Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} | Select-Object SamAccountName'
        'IP-017' = 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} | Select-Object SamAccountName'
        'IP-030' = 'Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select-Object SamAccountName, TrustedForDelegation'
        'IP-031' = 'Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Where-Object { $_.Name -notin (Get-ADDomainController -Filter *).Name } | Select-Object SamAccountName'
        'IP-040' = 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null" -and Enabled -eq $true} | Select-Object SamAccountName, ServicePrincipalNames'
        'IP-050' = 'Get-ADGroup -Filter {Name -eq "Domain Admins"} | Get-ADGroupMember -Recursive | Select-Object SamAccountName, objectClass'
        'IP-060' = 'Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=2097152)" | Select-Object SamAccountName, UserAccountControl'
        'IP-061' = 'Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { $_.PSObject.Properties["msDS-SupportedEncryptionTypes"] -and $_."msDS-SupportedEncryptionTypes" -gt 0 -and -not ($_."msDS-SupportedEncryptionTypes" -band 24) } | Select-Object SamAccountName, "msDS-SupportedEncryptionTypes"'
        'CG-001' = 'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature'
        'CG-002' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue'
        'CG-004' = 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'
        'CG-005' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"'
        'CG-010' = 'Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Filter "*.xml" | Select-String "cpassword"'
        'CG-020' = 'Get-ADTrust -Filter * | Select-Object Name, TrustAttributes, SIDFilteringForestAware, SIDFilteringQuarantined'
        'CG-030' = '(Get-ACL "AD:DC=corp,DC=local").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl" } | Select-Object IdentityReference, ActiveDirectoryRights'
        'CG-040' = 'Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Filter "GptTmpl.inf" | Select-String "SeDebugPrivilege|SeTcbPrivilege"'
        'EV-001' = 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null"} | Select-Object SamAccountName, ServicePrincipalNames, PasswordLastSet'
        'EV-010' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "FullSecureChannelProtection" -ErrorAction SilentlyContinue'
        'EV-020' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue'
        'EV-030' = 'Get-Service -ComputerName (Get-ADDomainController -Filter *).HostName -Name "Spooler" | Select-Object MachineName, Status'
        'PB-001' = '(Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl" } | Select-Object IdentityReference, ActiveDirectoryRights'
        'PB-010' = 'Get-ADUser -Filter {SIDHistory -like "*"} -Properties SIDHistory | Select-Object SamAccountName, SIDHistory'
        'PB-020' = '(Get-ACL "AD:DC=corp,DC=local").Access | Where-Object { $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" } | Select-Object IdentityReference'
        'PB-030' = 'Get-Process -ComputerName (Get-ADDomainController -Filter *).HostName | Where-Object { $_.Name -in @("mimikatz","mimilib","wce","fgdump") }'
        'PB-050' = 'Get-ChildItem "\\$env:USERDNSDOMAIN\NETLOGON" | Select-Object Name, LastWriteTime, Attributes'
        'PB-060' = 'Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\*" -and $_.Principal.UserId -match "SYSTEM" } | Select-Object TaskName, TaskPath, @{N="RunAs";E={$_.Principal.UserId}}'
        'DE-001' = 'auditpol /get /category:"Account Logon","Logon/Logoff","DS Access","Account Management","Privilege Use","Policy Change","Detailed Tracking"'
        'DE-002' = 'Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, RecordCount, IsEnabled'
    }

    $verCmd = if ($verificationCmds.ContainsKey($Finding.RuleId)) {
        $verificationCmds[$Finding.RuleId]
    }
    else {
        "# No specific verification command available for $($Finding.RuleId)"
    }

    $guide = [PSCustomObject]@{
        RuleId              = $Finding.RuleId
        Title               = $Finding.Title
        Severity            = $Finding.Severity
        WhyItMatters        = $Finding.Description
        AffectedObjects     = $Finding.AffectedObjects
        AffectedCount       = $Finding.AffectedCount
        RemediationSteps    = $Finding.Remediation
        VerificationCommand = $verCmd
        MitreAttack         = $Finding.MitreAttack
        Category            = $Finding.Category
    }

    switch ($Format) {
        'Text' {
            return @"
================================================================================
[$($guide.Severity)] $($guide.Title)  [$($guide.RuleId)]
================================================================================

WHY IT MATTERS:
$($guide.WhyItMatters)

AFFECTED AD OBJECTS ($($guide.AffectedCount)):
$(($guide.AffectedObjects | Select-Object -First 20 | ForEach-Object { "  - $_" }) -join "`n")

ROLLBACK-SAFE REMEDIATION STEPS:
$($guide.RemediationSteps)

VERIFICATION COMMAND (run after remediation):
  $($guide.VerificationCommand)

MITRE ATT&CK: $($guide.MitreAttack)
================================================================================
"@
        }
        'Markdown' {
            $affectedMd = ($guide.AffectedObjects | Select-Object -First 20 | ForEach-Object { "- ``$_``" }) -join "`n"
            return @"
## [$($guide.Severity)] $($guide.Title) ``[$($guide.RuleId)]``

### Why it Matters
$($guide.WhyItMatters)

### Affected AD Objects ($($guide.AffectedCount))
$affectedMd

### Rollback-Safe Remediation Steps
$($guide.RemediationSteps)

### Verification Command
```powershell
$($guide.VerificationCommand)
```

**MITRE ATT&CK:** $($guide.MitreAttack)
"@
        }
        'HTML' {
            $affectedHtml = ($guide.AffectedObjects | Select-Object -First 20 | ForEach-Object { "<li><code>$_</code></li>" }) -join ''
            return "<div class='fix-guide'><h3>[$($guide.Severity)] $($guide.Title)</h3><h4>Why it Matters</h4><p>$($guide.WhyItMatters)</p><h4>Affected Objects ($($guide.AffectedCount))</h4><ul>$affectedHtml</ul><h4>Remediation</h4><pre>$($guide.RemediationSteps)</pre><h4>Verification</h4><pre class='powershell'>$($guide.VerificationCommand)</pre><p><strong>MITRE:</strong> $($guide.MitreAttack)</p></div>"
        }
        default { return $guide }
    }
}

#endregion

Export-ModuleMember -Function New-CEFReport, New-SplunkReport, Export-ToJira,
                               Export-ToServiceNow, Get-FindingFixGuide
