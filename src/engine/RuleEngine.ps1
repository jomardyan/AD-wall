#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Rule Engine
.DESCRIPTION
    Orchestrates all security check modules, maintains a rule catalog with MITRE ATT&CK
    mappings, deduplicates findings, enriches with rule metadata, and provides filtering.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region Rule Catalog

$Script:RuleCatalog = @(
    # Identity & Privilege
    [PSCustomObject]@{ RuleId='IP-001'; Category='Identity & Privilege'; Name='Excessive Privileged Group Membership'; Severity='High';     MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-002'; Category='Identity & Privilege'; Name='Service Account in Privileged Group';   Severity='Critical'; MitreAttack='T1558.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-003'; Category='Identity & Privilege'; Name='Schema Admins Not Empty';               Severity='Critical'; MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-010'; Category='Identity & Privilege'; Name='Weak Minimum Password Length';          Severity='High';     MitreAttack='T1110';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-011'; Category='Identity & Privilege'; Name='Password Complexity Disabled';          Severity='High';     MitreAttack='T1110';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-012'; Category='Identity & Privilege'; Name='Account Lockout Not Configured';        Severity='High';     MitreAttack='T1110.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-013'; Category='Identity & Privilege'; Name='Reversible Password Encryption';        Severity='Critical'; MitreAttack='T1003.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-014'; Category='Identity & Privilege'; Name='Domain Passwords Never Expire';         Severity='Medium';   MitreAttack='T1078';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-015'; Category='Identity & Privilege'; Name='PasswordNeverExpires on Accounts';      Severity='Medium';   MitreAttack='T1078';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-016'; Category='Identity & Privilege'; Name='PasswordNotRequired on Accounts';       Severity='High';     MitreAttack='T1110.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-017'; Category='Identity & Privilege'; Name='AS-REP Roastable Accounts';             Severity='High';     MitreAttack='T1558.004'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-020'; Category='Identity & Privilege'; Name='Stale Enabled User Accounts';           Severity='Medium';   MitreAttack='T1078';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-021'; Category='Identity & Privilege'; Name='Stale Privileged Accounts';             Severity='Critical'; MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-022'; Category='Identity & Privilege'; Name='Stale Computer Accounts';               Severity='Low';      MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-030'; Category='Identity & Privilege'; Name='Unconstrained Delegation (Users)';      Severity='Critical'; MitreAttack='T1558';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-031'; Category='Identity & Privilege'; Name='Unconstrained Delegation (Computers)';  Severity='High';     MitreAttack='T1558';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-032'; Category='Identity & Privilege'; Name='Constrained Delegation to Sensitive SPN'; Severity='High';   MitreAttack='T1558';     Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-040'; Category='Identity & Privilege'; Name='Kerberoastable Accounts';               Severity='High';     MitreAttack='T1558.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-041'; Category='Identity & Privilege'; Name='Privileged Kerberoastable Accounts';    Severity='Critical'; MitreAttack='T1558.003'; Enabled=$true }
    # Configuration & GPO
    [PSCustomObject]@{ RuleId='CG-001'; Category='Configuration & GPO'; Name='SMB Signing Not Required';              Severity='High';     MitreAttack='T1557.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-002'; Category='Configuration & GPO'; Name='LDAP Signing Not Required';             Severity='High';     MitreAttack='T1557';     Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-003'; Category='Configuration & GPO'; Name='LDAP Channel Binding Not Enforced';     Severity='Medium';   MitreAttack='T1557';     Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-004'; Category='Configuration & GPO'; Name='SMBv1 Enabled';                         Severity='Critical'; MitreAttack='T1210';     Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-005'; Category='Configuration & GPO'; Name='NTLMv1 Allowed';                        Severity='High';     MitreAttack='T1557.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-010'; Category='Configuration & GPO'; Name='cPassword in SYSVOL (MS14-025)';        Severity='Critical'; MitreAttack='T1552.006'; Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-011'; Category='Configuration & GPO'; Name='Disabled GPOs Exist';                   Severity='Informational'; MitreAttack='';   Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-012'; Category='Configuration & GPO'; Name='Empty Enabled GPOs';                    Severity='Low';      MitreAttack='';          Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-020'; Category='Configuration & GPO'; Name='SID Filtering Disabled on Trust';       Severity='Critical'; MitreAttack='T1134.005'; Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-021'; Category='Configuration & GPO'; Name='Bidirectional Trust';                   Severity='Medium';   MitreAttack='T1199';     Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-022'; Category='Configuration & GPO'; Name='External Trust';                        Severity='Medium';   MitreAttack='T1199';     Enabled=$true }
    # Exploit & Vulnerability
    [PSCustomObject]@{ RuleId='EV-001'; Category='Exploit & Vulnerability'; Name='Kerberoastable Accounts';           Severity='High';     MitreAttack='T1558.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-010'; Category='Exploit & Vulnerability'; Name='Zerologon Enforcement Not Active';  Severity='Critical'; MitreAttack='T1210';     Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-020'; Category='Exploit & Vulnerability'; Name='PetitPotam / NTLM Relay Risk';      Severity='High';     MitreAttack='T1557';     Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-030'; Category='Exploit & Vulnerability'; Name='Print Spooler on DC';               Severity='Critical'; MitreAttack='T1210';     Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-040'; Category='Exploit & Vulnerability'; Name='ESC1 - AD CS SAN Template';         Severity='Critical'; MitreAttack='T1649';     Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-041'; Category='Exploit & Vulnerability'; Name='ESC2 - Any Purpose EKU';            Severity='High';     MitreAttack='T1649';     Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-042'; Category='Exploit & Vulnerability'; Name='ESC3 - Cert Request Agent';         Severity='High';     MitreAttack='T1649';     Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-043'; Category='Exploit & Vulnerability'; Name='ESC4 - Weak Template ACL';          Severity='Critical'; MitreAttack='T1649';     Enabled=$true }
    [PSCustomObject]@{ RuleId='EV-045'; Category='Exploit & Vulnerability'; Name='ESC6 - CA SANEditFlag';             Severity='Critical'; MitreAttack='T1649';     Enabled=$true }
    # Persistence & Backdoor
    [PSCustomObject]@{ RuleId='PB-001'; Category='Persistence & Backdoor'; Name='Suspicious AdminSDHolder ACE';       Severity='Critical'; MitreAttack='T1098';     Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-002'; Category='Persistence & Backdoor'; Name='Orphaned AdminCount=1 Accounts';     Severity='High';     MitreAttack='T1098';     Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-010'; Category='Persistence & Backdoor'; Name='SID History Present';                Severity='Medium';   MitreAttack='T1134.005'; Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-011'; Category='Persistence & Backdoor'; Name='Privileged SID in SID History';      Severity='Critical'; MitreAttack='T1134.005'; Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-020'; Category='Persistence & Backdoor'; Name='Unauthorized DCSync Rights';         Severity='Critical'; MitreAttack='T1003.006'; Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-030'; Category='Persistence & Backdoor'; Name='Skeleton Key Indicators';            Severity='Critical'; MitreAttack='T1556.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-040'; Category='Persistence & Backdoor'; Name='Potential Rogue DC in DNS';          Severity='High';     MitreAttack='T1207';     Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-041'; Category='Persistence & Backdoor'; Name='RODC Present';                       Severity='Informational'; MitreAttack='';   Enabled=$true }
)

#endregion

#region Functions

function Get-RuleCatalog {
    <#
    .SYNOPSIS
        Returns the complete rule catalog.
    .PARAMETER Category
        Optional filter by category.
    .PARAMETER Severity
        Optional filter by severity.
    .EXAMPLE
        Get-RuleCatalog
        Get-RuleCatalog -Category 'Exploit & Vulnerability' -Severity 'Critical'
    #>
    [CmdletBinding()]
    param(
        [string]$Category,
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity
    )

    $rules = $Script:RuleCatalog

    if ($PSBoundParameters.ContainsKey('Category')) {
        $rules = $rules | Where-Object { $_.Category -like "*$Category*" }
    }
    if ($PSBoundParameters.ContainsKey('Severity')) {
        $rules = $rules | Where-Object { $_.Severity -eq $Severity }
    }

    return $rules
}

function Test-Rule {
    <#
    .SYNOPSIS
        Checks whether a specific rule ID is enabled in the catalog.
    .PARAMETER RuleId
        Rule identifier to look up.
    #>
    [CmdletBinding()]
    param([string]$RuleId)

    $rule = $Script:RuleCatalog | Where-Object { $_.RuleId -eq $RuleId }
    if ($null -eq $rule) { return $false }
    return $rule.Enabled
}

function Invoke-AllChecks {
    <#
    .SYNOPSIS
        Runs all enabled security checks and returns aggregated findings.
    .DESCRIPTION
        Orchestrates all four module categories (Identity, Config, Exploit, Persistence),
        deduplicates findings, enriches with rule catalog metadata, and returns a
        unified findings collection.
    .PARAMETER CollectedData
        Hashtable containing all collector outputs:
        - Users, Groups, Computers, OUs, Trusts, GPOs, ACLs, DomainControllers
        - PasswordPolicies, FinePWPolicies
        - SmbSigning, LdapSigning, SmbV1, NtlmSettings
        - CertificateAuthorities, CertificateTemplates, EnrollmentPermissions
    .PARAMETER Modules
        Array of module names to run. Default: all.
    .PARAMETER DomainName
        Domain DNS name.
    .EXAMPLE
        $findings = Invoke-AllChecks -CollectedData $data -DomainName 'corp.local'
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CollectedData,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Identity','Config','Exploit','Persistence')]
        [string[]]$Modules = @('Identity','Config','Exploit','Persistence'),

        [string]$DomainName = $env:USERDNSDOMAIN
    )

    $allFindings = [System.Collections.Generic.List[object]]::new()

    # Safely extract collections with defaults
    $users       = @(if ($CollectedData.ContainsKey('Users'))       { $CollectedData.Users }       else { @() })
    $groups      = @(if ($CollectedData.ContainsKey('Groups'))      { $CollectedData.Groups }      else { @() })
    $computers   = @(if ($CollectedData.ContainsKey('Computers'))   { $CollectedData.Computers }   else { @() })
    $trusts      = @(if ($CollectedData.ContainsKey('Trusts'))      { $CollectedData.Trusts }      else { @() })
    $gpos        = @(if ($CollectedData.ContainsKey('GPOs'))        { $CollectedData.GPOs }        else { @() })
    $acls        = @(if ($CollectedData.ContainsKey('ACLs'))        { $CollectedData.ACLs }        else { @() })
    $dcs         = @(if ($CollectedData.ContainsKey('DomainControllers')) { $CollectedData.DomainControllers } else { @() })
    $pwPolicies  = @(if ($CollectedData.ContainsKey('PasswordPolicies'))  { $CollectedData.PasswordPolicies }  else { @() })
    $smbSigning  = @(if ($CollectedData.ContainsKey('SmbSigning'))  { $CollectedData.SmbSigning }  else { @() })
    $ldapSigning = @(if ($CollectedData.ContainsKey('LdapSigning')) { $CollectedData.LdapSigning } else { @() })
    $smbV1       = @(if ($CollectedData.ContainsKey('SmbV1'))       { $CollectedData.SmbV1 }       else { @() })
    $ntlm        = @(if ($CollectedData.ContainsKey('NtlmSettings'){ $CollectedData.NtlmSettings } else { @() }))
    $cas         = @(if ($CollectedData.ContainsKey('CertificateAuthorities'))  { $CollectedData.CertificateAuthorities }  else { @() })
    $templates   = @(if ($CollectedData.ContainsKey('CertificateTemplates'))    { $CollectedData.CertificateTemplates }    else { @() })
    $aclsEnroll  = @(if ($CollectedData.ContainsKey('EnrollmentPermissions'))   { $CollectedData.EnrollmentPermissions }   else { @() })

    # Load modules (dot-source from relative paths)
    $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

    # Identity & Privilege
    if ('Identity' -in $Modules) {
        Write-Verbose "=== Running Identity & Privilege checks ==="
        try {
            $ipFindings = @()
            if ($users.Count -gt 0 -and $groups.Count -gt 0) {
                $ipFindings += Invoke-PrivilegedGroupCheck -Users $users -Groups $groups
            }
            if ($users.Count -gt 0) {
                $ipFindings += Invoke-PasswordPolicyCheck -Users $users -PasswordPolicies $pwPolicies
                $ipFindings += Invoke-StaleAccountCheck   -Users $users -Computers $computers
                $ipFindings += Invoke-DelegationCheck     -Users $users -Computers $computers -DomainControllers $dcs
                $ipFindings += Invoke-KerberoastableCheck -Users $users
            }
            $ipFindings | ForEach-Object { $allFindings.Add($_) }
        }
        catch { Write-Warning "Identity module error: $_" }
    }

    # Configuration & GPO
    if ('Config' -in $Modules) {
        Write-Verbose "=== Running Configuration & GPO checks ==="
        try {
            $cgFindings  = @()
            $cgFindings += Invoke-WeakProtocolCheck -DomainControllers $dcs `
                -SmbSigningData $smbSigning -LdapSigningData $ldapSigning `
                -SmbV1Data $smbV1 -NtlmData $ntlm
            $cgFindings += Invoke-GPOSecurityCheck  -GPOs $gpos -DomainName $DomainName
            if ($trusts.Count -gt 0) {
                $cgFindings += Invoke-TrustCheck -Trusts $trusts
            }
            $cgFindings | ForEach-Object { $allFindings.Add($_) }
        }
        catch { Write-Warning "Config module error: $_" }
    }

    # Exploit & Vulnerability
    if ('Exploit' -in $Modules) {
        Write-Verbose "=== Running Exploit & Vulnerability checks ==="
        try {
            $evFindings  = @()
            if ($users.Count -gt 0) {
                $evFindings += Invoke-KerberoastingCheck -Users $users
            }
            if ($dcs.Count -gt 0) {
                $evFindings += Invoke-ZerologonCheck    -DomainControllers $dcs
                $evFindings += Invoke-PrintNightmareCheck -DomainControllers $dcs
            }
            $evFindings += Invoke-PetitPotamCheck -DomainControllers $dcs `
                -LdapSigningData $ldapSigning -SmbSigningData $smbSigning
            $evFindings += Invoke-ADCSVulnerabilityCheck -Templates $templates `
                -CertificateAuthorities $cas -EnrollmentPermissions $aclsEnroll
            $evFindings | ForEach-Object { $allFindings.Add($_) }
        }
        catch { Write-Warning "Exploit module error: $_" }
    }

    # Persistence & Backdoor
    if ('Persistence' -in $Modules) {
        Write-Verbose "=== Running Persistence & Backdoor checks ==="
        try {
            $pbFindings  = @()
            if ($users.Count -gt 0) {
                $pbFindings += Invoke-AdminSDHolderCheck -ACLs $acls -Users $users -Groups $groups
                $pbFindings += Invoke-SIDHistoryCheck    -Users $users
            }
            if ($acls.Count -gt 0) {
                $pbFindings += Invoke-DCSyncRightsCheck  -ACLs $acls
            }
            if ($dcs.Count -gt 0) {
                $pbFindings += Invoke-SkeletonKeyCheck   -DomainControllers $dcs
                $pbFindings += Invoke-RogueDCCheck       -DomainControllers $dcs -DomainName $DomainName
            }
            $pbFindings | ForEach-Object { $allFindings.Add($_) }
        }
        catch { Write-Warning "Persistence module error: $_" }
    }

    # Enrich with rule metadata and deduplicate
    $enriched = Invoke-FindingEnrichment -Findings $allFindings.ToArray()
    $deduped  = Invoke-FindingDeduplication -Findings $enriched

    Write-Verbose "Total findings after dedup: $($deduped.Count)"
    return $deduped
}

function Invoke-FindingEnrichment {
    <#
    .SYNOPSIS
        Enriches findings with matching rule catalog metadata.
    #>
    param([object[]]$Findings)

    $ruleIndex = @{}
    foreach ($rule in $Script:RuleCatalog) {
        $ruleIndex[$rule.RuleId] = $rule
    }

    foreach ($finding in $Findings) {
        if ($null -ne $finding.RuleId -and $ruleIndex.ContainsKey($finding.RuleId)) {
            $rule = $ruleIndex[$finding.RuleId]
            $finding | Add-Member -NotePropertyName 'RuleName'       -NotePropertyValue $rule.Name        -Force
            $finding | Add-Member -NotePropertyName 'RuleEnabled'    -NotePropertyValue $rule.Enabled     -Force
            $finding | Add-Member -NotePropertyName 'MitreReference' -NotePropertyValue $rule.MitreAttack -Force
        }
    }

    return $Findings
}

function Invoke-FindingDeduplication {
    <#
    .SYNOPSIS
        Deduplicates findings by RuleId, keeping the most recent occurrence.
    #>
    param([object[]]$Findings)

    $seen     = [System.Collections.Generic.HashSet[string]]::new()
    $deduped  = [System.Collections.Generic.List[object]]::new()

    foreach ($finding in ($Findings | Sort-Object { $_.DetectedAt } -Descending)) {
        $key = "$($finding.RuleId):$($finding.Title)"
        if ($seen.Add($key)) {
            $deduped.Add($finding)
        }
    }

    return $deduped.ToArray()
}

function Get-FindingsByCategory {
    <#
    .SYNOPSIS
        Groups findings by category.
    .PARAMETER Findings
        Array of finding objects.
    .EXAMPLE
        $byCategory = Get-FindingsByCategory -Findings $allFindings
    #>
    [CmdletBinding()]
    param([object[]]$Findings)

    return $Findings | Group-Object -Property Category | ForEach-Object {
        [PSCustomObject]@{
            Category = $_.Name
            Count    = $_.Count
            Findings = $_.Group
        }
    }
}

function Get-FindingsBySeverity {
    <#
    .SYNOPSIS
        Groups and counts findings by severity.
    .PARAMETER Findings
        Array of finding objects.
    .EXAMPLE
        $bySeverity = Get-FindingsBySeverity -Findings $allFindings
    #>
    [CmdletBinding()]
    param([object[]]$Findings)

    $order = @('Critical','High','Medium','Low','Informational')

    $grouped = $Findings | Group-Object -Property Severity

    return $order | ForEach-Object {
        $sev   = $_
        $group = $grouped | Where-Object { $_.Name -eq $sev }
        [PSCustomObject]@{
            Severity = $sev
            Count    = if ($group) { $group.Count } else { 0 }
            Findings = if ($group) { $group.Group  } else { @() }
        }
    }
}

#endregion

Export-ModuleMember -Function Invoke-AllChecks, Get-RuleCatalog, Test-Rule,
                               Get-FindingsByCategory, Get-FindingsBySeverity,
                               Invoke-FindingEnrichment, Invoke-FindingDeduplication
