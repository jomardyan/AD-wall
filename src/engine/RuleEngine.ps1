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
    [PSCustomObject]@{ RuleId='PB-050'; Category='Persistence & Backdoor'; Name='Suspicious Logon/Startup Script Content';  Severity='Critical'; MitreAttack='T1037.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-051'; Category='Persistence & Backdoor'; Name='Logon/Startup Script Writable by Non-Admins'; Severity='High'; MitreAttack='T1037.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='PB-060'; Category='Persistence & Backdoor'; Name='Rogue Scheduled Task on DC';         Severity='Critical'; MitreAttack='T1053.005'; Enabled=$true }
    # Identity & Privilege (new)
    [PSCustomObject]@{ RuleId='IP-050'; Category='Identity & Privilege'; Name='Nested Privileged Group Membership';   Severity='High';     MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-060'; Category='Identity & Privilege'; Name='UseDESKeyOnly (Kerberos DES)';         Severity='Critical'; MitreAttack='T1558.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-061'; Category='Identity & Privilege'; Name='No AES Kerberos Encryption (Users)';   Severity='Medium';   MitreAttack='T1558.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='IP-062'; Category='Identity & Privilege'; Name='No AES Kerberos Encryption (Computers)'; Severity='Medium'; MitreAttack='T1558';     Enabled=$true }
    # Configuration & GPO (new)
    [PSCustomObject]@{ RuleId='CG-030'; Category='Configuration & GPO'; Name='Dangerous ACEs on Sensitive AD Objects'; Severity='Critical'; MitreAttack='T1222.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='CG-040'; Category='Configuration & GPO'; Name='Dangerous User Rights in GPO';          Severity='High';     MitreAttack='T1078.003'; Enabled=$true }
    # Detection Engineering
    [PSCustomObject]@{ RuleId='DE-001'; Category='Detection Engineering'; Name='Missing Windows Audit Policies';      Severity='High';     MitreAttack='T1562.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='DE-002'; Category='Detection Engineering'; Name='Insufficient SIEM Log Coverage';      Severity='High';     MitreAttack='T1562.002'; Enabled=$true }
    # Compliance (CIS/NIST)
    [PSCustomObject]@{ RuleId='COMP-001'; Category='Compliance'; Name='Password Min Length < 14 (CIS 1.1.1)';          Severity='High';     MitreAttack='T1110';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-002'; Category='Compliance'; Name='Password Complexity Disabled (CIS 1.1.2)';       Severity='High';     MitreAttack='T1110';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-003'; Category='Compliance'; Name='Lockout Threshold Too High (CIS 1.1.3)';         Severity='Medium';   MitreAttack='T1110.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-004'; Category='Compliance'; Name='Password History Count < 24 (CIS 1.1.4)';        Severity='Low';      MitreAttack='T1078';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-005'; Category='Compliance'; Name='Max Password Age > 365 Days (CIS 1.1.5)';        Severity='Low';      MitreAttack='T1078';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-010'; Category='Compliance'; Name='Domain Admins > 5 Members (CIS 1.2.1)';          Severity='High';     MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-011'; Category='Compliance'; Name='Schema Admins Not Empty (CIS 1.2.2)';            Severity='Medium';   MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-012'; Category='Compliance'; Name='Guest Account Enabled (CIS 1.2.3)';              Severity='Medium';   MitreAttack='T1078.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-013'; Category='Compliance'; Name='Privileged Accounts Password Never Expires';     Severity='High';     MitreAttack='T1078';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-020'; Category='Compliance'; Name='NTLMv1 Allowed on DCs (CIS 1.3.1)';             Severity='High';     MitreAttack='T1557.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-030'; Category='Compliance'; Name='Trust Without SID Filtering (CIS 1.4.1)';        Severity='High';     MitreAttack='T1134.005'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-040'; Category='Compliance'; Name='LAPS Not Deployed (CIS 4.1)';                   Severity='High';     MitreAttack='T1550.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-041'; Category='Compliance'; Name='LAPS Coverage Below 80%';                        Severity='Medium';   MitreAttack='T1550.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-042'; Category='Compliance'; Name='LAPS Coverage Not 100%';                         Severity='Low';      MitreAttack='T1550.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-050'; Category='Compliance'; Name='Protected Users Group Missing';                  Severity='Medium';   MitreAttack='T1003';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-051'; Category='Compliance'; Name='Privileged Accounts Not in Protected Users';     Severity='High';     MitreAttack='T1003';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-060'; Category='Compliance'; Name='Classic Service Accounts Should Use gMSA';       Severity='Medium';   MitreAttack='T1558.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-061'; Category='Compliance'; Name='No gMSA Accounts Found';                         Severity='Informational'; MitreAttack='T1558.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-070'; Category='Compliance'; Name='DA Accounts With Email (Mixed-Use)';             Severity='High';     MitreAttack='T1566';     Enabled=$true }
    [PSCustomObject]@{ RuleId='COMP-071'; Category='Compliance'; Name='DA Accounts Without Admin Naming Convention';    Severity='Medium';   MitreAttack='T1078.002'; Enabled=$true }
    # Attack Techniques (Joint Govt Guidance — 20 AD Attack Types)
    [PSCustomObject]@{ RuleId='ATK-001'; Category='Attack Techniques'; Name='Password Spraying Surface';                       Severity='Critical'; MitreAttack='T1110.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-002'; Category='Attack Techniques'; Name='MachineAccountQuota > 0';                         Severity='High';     MitreAttack='T1136.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-003'; Category='Attack Techniques'; Name='KRBTGT Password Not Rotated (> 180 days)';        Severity='Critical'; MitreAttack='T1558.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-004'; Category='Attack Techniques'; Name='KRBTGT Password Stale (90-180 days)';             Severity='High';     MitreAttack='T1558.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-005'; Category='Attack Techniques'; Name='Silver Ticket Surface (RC4-only service accts)';  Severity='High';     MitreAttack='T1558.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-006'; Category='Attack Techniques'; Name='Golden Certificate Risk (long-lived CA / no HSM)'; Severity='High';    MitreAttack='T1649';     Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-007'; Category='Attack Techniques'; Name='NTDS.dit Access Rights Overpermissioned';         Severity='Critical'; MitreAttack='T1003.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-008'; Category='Attack Techniques'; Name='AD FS Token Signing Cert Exposure';               Severity='Critical'; MitreAttack='T1606.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-009'; Category='Attack Techniques'; Name='Entra Connect Sync Account Exposure';             Severity='Critical'; MitreAttack='T1098.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-010'; Category='Attack Techniques'; Name='Pass-the-Hash Surface (NTLMv1/No LAPS)';          Severity='High';     MitreAttack='T1550.002'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-011'; Category='Attack Techniques'; Name='Pass-the-Ticket Surface (Forwardable/Unconstrained)'; Severity='Medium'; MitreAttack='T1550.003'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-012'; Category='Attack Techniques'; Name='DCShadow Risk (Replication Rights Misconfiguration)'; Severity='Critical'; MitreAttack='T1207'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-013'; Category='Attack Techniques'; Name='NTLM Relay Surface (Multiple Vectors)';           Severity='Critical'; MitreAttack='T1557.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-014'; Category='Attack Techniques'; Name='MachineAccountQuota Abuse Path';                  Severity='Medium';   MitreAttack='T1136.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-015'; Category='Attack Techniques'; Name='Credential Dumping Surface (LSASS/NTDS/WDigest)';  Severity='Critical'; MitreAttack='T1003';     Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-016'; Category='Attack Techniques'; Name='Lateral Movement Path Abuse (AdminCount/Delegation)'; Severity='Critical'; MitreAttack='T1021';  Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-017'; Category='Attack Techniques'; Name='Shadow Credentials (Key Credential Link Abuse)';      Severity='Critical'; MitreAttack='T1556';     Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-018'; Category='Attack Techniques'; Name='ACL Object Control Chaining';                         Severity='Critical'; MitreAttack='T1222.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-019'; Category='Attack Techniques'; Name='AdminSDHolder / SDProp Persistence';                  Severity='Critical'; MitreAttack='T1098';     Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-020'; Category='Attack Techniques'; Name='GPO Object Write Abuse';                              Severity='Critical'; MitreAttack='T1484.001'; Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-021'; Category='Attack Techniques'; Name='Cross-Forest / Domain Trust Exploitation';            Severity='Critical'; MitreAttack='T1199';     Enabled=$true }
    [PSCustomObject]@{ RuleId='ATK-022'; Category='Attack Techniques'; Name='RBCD (Resource-Based Constrained Delegation) Abuse';  Severity='High';     MitreAttack='T1134.001'; Enabled=$true }
)

# Pre-build a hashtable index for O(1) rule lookups instead of linear Where-Object scans
$Script:RuleIndex = @{}
foreach ($rule in $Script:RuleCatalog) {
    $Script:RuleIndex[$rule.RuleId] = $rule
}

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

    if ($Script:RuleIndex.ContainsKey($RuleId)) {
        return $Script:RuleIndex[$RuleId].Enabled
    }
    return $false
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
        [ValidateSet('Identity','Config','Exploit','Persistence','Detection','Compliance')]
        [string[]]$Modules = @('Identity','Config','Exploit','Persistence','Detection','Compliance'),

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
    $ntlm        = @(if ($CollectedData.ContainsKey('NtlmSettings')) { $CollectedData.NtlmSettings } else { @() })
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
                $ipFindings += Invoke-PrivilegedGroupCheck      -Users $users -Groups $groups
                $ipFindings += Invoke-NestedPrivilegedGroupCheck -Groups $groups -Users $users
            }
            if ($users.Count -gt 0) {
                $ipFindings += Invoke-PasswordPolicyCheck       -Users $users -PasswordPolicies $pwPolicies
                $ipFindings += Invoke-StaleAccountCheck         -Users $users -Computers $computers
                $ipFindings += Invoke-DelegationCheck           -Users $users -Computers $computers -DomainControllers $dcs
                $ipFindings += Invoke-KerberoastableCheck       -Users $users
                $ipFindings += Invoke-WeakEncryptionTypeCheck   -Users $users -Computers $computers
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
            if ($acls.Count -gt 0) {
                $cgFindings += Invoke-DangerousACLCheck -ACLs $acls
            }
            $cgFindings += Invoke-GPOUserRightsCheck -DomainName $DomainName
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
                $pbFindings += Invoke-SkeletonKeyCheck         -DomainControllers $dcs
                $pbFindings += Invoke-RogueDCCheck             -DomainControllers $dcs -DomainName $DomainName
                $pbFindings += Invoke-RogueScheduledTaskCheck  -DomainControllers $dcs
            }
            $pbFindings += Invoke-StartupScriptCheck -DomainName $DomainName -GPOs $gpos
            $pbFindings | ForEach-Object { $allFindings.Add($_) }
        }
        catch { Write-Warning "Persistence module error: $_" }
    }

    # Detection Engineering
    if ('Detection' -in $Modules) {
        Write-Verbose "=== Running Detection Engineering checks ==="
        try {
            $deFindings  = @()
            if ($dcs.Count -gt 0) {
                $deFindings += Invoke-AuditPolicyCheck   -DomainControllers $dcs
                $deFindings += Invoke-SIEMCoverageCheck  -DomainControllers $dcs
            }
            $deFindings | ForEach-Object { $allFindings.Add($_) }
        }
        catch { Write-Warning "Detection Engineering module error: $_" }
    }

    # Compliance (CIS / NIST / MS Baseline)
    if ('Compliance' -in $Modules) {
        Write-Verbose "=== Running Compliance checks ==="
        try {
            $compFindings = Invoke-AllComplianceChecks -CollectedData $CollectedData
            $compFindings | ForEach-Object { $allFindings.Add($_) }
        }
        catch { Write-Warning "Compliance module error: $_" }
    }

    # Attack Techniques (20 attack types — blue team detection)
    if ('OffensiveTechniques' -in $Modules -or 'Exploit' -in $Modules) {
        Write-Verbose "=== Running Attack Techniques checks ==="
        try {
            if (Get-Command Invoke-AllOffensiveTechniqueChecks -ErrorAction SilentlyContinue) {
                $atkFindings = Invoke-AllOffensiveTechniqueChecks -CollectedData $CollectedData -DomainName $DomainName
                $atkFindings | ForEach-Object { $allFindings.Add($_) }
            }
        }
        catch { Write-Warning "Attack Techniques module error: $_" }
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
        Enriches findings with matching rule catalog metadata and verification commands.
    #>
    param([object[]]$Findings)

    $ruleIndex = $Script:RuleIndex

    # Verification command lookup (PowerShell to run after remediation to confirm the fix)
    $verificationCommands = @{
        'IP-001' = 'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object SamAccountName, objectClass'
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
        'IP-061' = 'Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { $_."msDS-SupportedEncryptionTypes" -gt 0 -and -not ($_."msDS-SupportedEncryptionTypes" -band 24) } | Select-Object SamAccountName, "msDS-SupportedEncryptionTypes"'
        'CG-001' = 'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature'
        'CG-002' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity"'
        'CG-004' = 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State'
        'CG-005' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"'
        'CG-010' = 'Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Filter "*.xml" | Select-String "cpassword"'
        'CG-020' = 'Get-ADTrust -Filter * | Select-Object Name, TrustAttributes, SIDFilteringForestAware'
        'CG-030' = '(Get-ACL "AD:DC=corp,DC=local").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl" } | Select-Object IdentityReference, ActiveDirectoryRights'
        'CG-040' = 'Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Filter "GptTmpl.inf" | Select-String "SeDebugPrivilege|SeTcbPrivilege"'
        'EV-001' = 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null"} | Select-Object SamAccountName, ServicePrincipalNames, PasswordLastSet'
        'EV-010' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "FullSecureChannelProtection"'
        'EV-020' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding"'
        'EV-030' = 'Get-Service -ComputerName (Get-ADDomainController -Filter *).HostName -Name "Spooler" | Select-Object MachineName, Status'
        'PB-001' = '(Get-ACL "AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl" } | Select-Object IdentityReference'
        'PB-010' = 'Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory } | Select-Object SamAccountName, SIDHistory'
        'PB-020' = '(Get-ACL "AD:DC=corp,DC=local").Access | Where-Object { $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" } | Select-Object IdentityReference'
        'PB-050' = 'Get-ChildItem "\\$env:USERDNSDOMAIN\NETLOGON" | Select-Object Name, LastWriteTime, Attributes'
        'PB-060' = 'Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\*" -and $_.Principal.UserId -match "SYSTEM" } | Select-Object TaskName, TaskPath, @{N="RunAs";E={$_.Principal.UserId}}'
        'DE-001' = 'auditpol /get /category:"Account Logon","Logon/Logoff","DS Access","Account Management","Privilege Use","Policy Change","Detailed Tracking"'
        'DE-002' = 'Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, RecordCount'
        'COMP-001' = 'Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength'
        'COMP-002' = 'Get-ADDefaultDomainPasswordPolicy | Select-Object PasswordComplexityEnabled'
        'COMP-003' = 'Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow'
        'COMP-010' = 'Get-ADGroupMember -Identity "Domain Admins" | Measure-Object | Select-Object Count'
        'COMP-011' = 'Get-ADGroupMember -Identity "Schema Admins" | Select-Object SamAccountName, objectClass'
        'COMP-012' = 'Get-ADUser -Identity Guest | Select-Object SamAccountName, Enabled'
        'COMP-013' = 'Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true -and AdminCount -eq 1} | Select-Object SamAccountName'
        'COMP-020' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" | Select-Object LmCompatibilityLevel'
        'COMP-030' = 'Get-ADTrust -Filter * | Select-Object Name, TrustAttributes, SIDFilteringForestAware, SIDFilteringQuarantined'
        'COMP-040' = 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,msLAPS-Password | Where-Object { -not $_."ms-Mcs-AdmPwd" -and -not $_."msLAPS-Password" } | Measure-Object | Select-Object Count'
        'COMP-041' = 'Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { -not $_."ms-Mcs-AdmPwd" } | Select-Object SamAccountName | Measure-Object | Select-Object Count'
        'COMP-050' = 'Get-ADGroup -Identity "Protected Users" | Get-ADGroupMember | Select-Object SamAccountName'
        'COMP-051' = 'Get-ADGroupMember -Identity "Domain Admins" | Where-Object { (Get-ADGroupMember -Identity "Protected Users" | Select-Object -ExpandProperty SamAccountName) -notcontains $_.SamAccountName } | Select-Object SamAccountName'
        'COMP-060' = 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null" -and Enabled -eq $true} | Select-Object SamAccountName, ServicePrincipalNames'
        'COMP-061' = 'Get-ADServiceAccount -Filter * | Select-Object SamAccountName, objectClass'
        'COMP-070' = 'Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties EmailAddress | Where-Object {$_.EmailAddress} | Select-Object SamAccountName, EmailAddress'
        'COMP-071' = 'Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties EmailAddress | Select-Object SamAccountName, EmailAddress'
        # Attack Techniques
        'ATK-001' = 'Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow'
        'ATK-002' = 'Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota" | Select-Object "ms-DS-MachineAccountQuota"'
        'ATK-003' = 'Get-ADUser -Identity krbtgt -Properties PasswordLastSet | Select-Object SamAccountName, PasswordLastSet'
        'ATK-004' = 'Get-ADUser -Identity krbtgt -Properties PasswordLastSet | Select-Object SamAccountName, PasswordLastSet'
        'ATK-005' = 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null" -and Enabled -eq $true} -Properties ServicePrincipalNames,"msDS-SupportedEncryptionTypes" | Where-Object { -not ($_."msDS-SupportedEncryptionTypes" -band 24) } | Select-Object SamAccountName,"msDS-SupportedEncryptionTypes"'
        'ATK-006' = 'certutil -dump | Select-String "NotAfter|Provider"'
        'ATK-007' = '(Get-ACL "AD:DC=$((Get-ADDomain).DistinguishedName)").Access | Where-Object { $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -and $_.IdentityReference -notmatch "Domain Controllers" } | Select-Object IdentityReference'
        'ATK-008' = 'Get-ADUser -Filter {SamAccountName -like "adfssvc*" -or SamAccountName -like "adfs*"} | Select-Object SamAccountName, Enabled'
        'ATK-009' = 'Get-ADUser -Filter {SamAccountName -like "MSOL_*" -or SamAccountName -like "AAD_*"} -Properties PasswordLastSet | Select-Object SamAccountName, PasswordLastSet, Enabled'
        'ATK-010' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel","NoLMHash" -ErrorAction SilentlyContinue'
        'ATK-011' = 'Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties maxTicketAge,maxRenewAge | Select-Object maxTicketAge,maxRenewAge'
        'ATK-012' = 'Get-ADObject -SearchBase "CN=Sites,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -Filter {objectClass -eq "nTDSDSA"} | Select-Object DistinguishedName, Created | Sort-Object Created -Descending'
        'ATK-013' = 'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue'
        'ATK-014' = 'Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota" | Select-Object "ms-DS-MachineAccountQuota"'
        'ATK-015' = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue'
        'ATK-016' = 'Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Select-Object SamAccountName,MemberOf; Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo | Select-Object Name,"msDS-AllowedToDelegateTo"'
    }

    foreach ($finding in $Findings) {
        if ($null -ne $finding.RuleId -and $ruleIndex.ContainsKey($finding.RuleId)) {
            $rule = $ruleIndex[$finding.RuleId]
            $finding | Add-Member -NotePropertyName 'RuleName'       -NotePropertyValue $rule.Name        -Force
            $finding | Add-Member -NotePropertyName 'RuleEnabled'    -NotePropertyValue $rule.Enabled     -Force
            $finding | Add-Member -NotePropertyName 'MitreReference' -NotePropertyValue $rule.MitreAttack -Force

            # Overwrite Category from the rule catalog so that the canonical value is
            # always used regardless of what the module's New-Finding call supplied.
            # This also fixes the implicit scope bug where modules loaded earlier could
            # have their findings categorised as 'Compliance' (the last-loaded module's
            # default) when running under dot-source module loading.
            if (-not [string]::IsNullOrEmpty($rule.Category)) {
                $finding | Add-Member -NotePropertyName 'Category' -NotePropertyValue $rule.Category -Force
            }
        }

        # Add verification command if available
        $verCmd = if ($null -ne $finding.RuleId -and $verificationCommands.ContainsKey($finding.RuleId)) {
            $verificationCommands[$finding.RuleId]
        } else { '' }
        $finding | Add-Member -NotePropertyName 'VerificationCommand' -NotePropertyValue $verCmd -Force
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
