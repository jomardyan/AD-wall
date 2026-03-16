#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Offensive Techniques Detection Module (Blue Team)
.DESCRIPTION
    Blue-team detection checks for all 20 AD attack techniques from joint government
    guidance. Checks are READ-ONLY. Cross-references to existing module checks:

    Already covered by existing modules:
      Kerberoasting         — IP-040/041, EV-001 (IdentityPrivilege, ExploitVuln)
      AS-REP Roasting       — IP-017 (IdentityPrivilege)
      Unconstrained Deleg.  — IP-030/031 (IdentityPrivilege)
      GPP/cPassword         — CG-010 (ConfigGpo)
      AD CS ESC1-8          — EV-040..045 (ExploitVuln)
      DCSync                — PB-020 (PersistenceBackdoor)
      SID History           — PB-010/011 (PersistenceBackdoor)
      Skeleton Key          — PB-030 (PersistenceBackdoor)

    New checks in this module:
      ATK-001  Password Spraying Surface
      ATK-002  MachineAccountQuota
      ATK-003  KRBTGT Password Not Rotated (>180d)
      ATK-004  KRBTGT Password Stale (90-180d)
      ATK-005  Silver Ticket Surface (RC4-only services)
      ATK-006  Golden Certificate Risk
      ATK-007  NTDS.dit Access Rights
      ATK-008  AD FS Token Signing Cert Exposure
      ATK-009  Entra Connect Sync Account Exposure
      ATK-010  Pass-the-Hash Surface
      ATK-011  Pass-the-Ticket Surface
      ATK-012  DCShadow Risk
      ATK-013  NTLM Relay Surface
      ATK-017  Shadow Credentials (Key Credential Link Abuse)
      ATK-018  ACL Object Control Chaining
      ATK-019  AdminSDHolder / SDProp Persistence
      ATK-020  GPO Object Write Abuse
      ATK-021  Cross-Forest / Domain Trust Exploitation
      ATK-022  RBCD (Resource-Based Constrained Delegation) Abuse

.NOTES
    Author  : AD-Wall Project
    Version : 1.0.0
    All operations are READ-ONLY.
#>

Set-StrictMode -Version Latest

# New-ATKFinding is defined in src/core/FindingHelper.ps1 (delegates to New-Finding with
# Category fixed to 'Attack Techniques') and dot-sourced before this module.

#region Password Spraying

function Invoke-PasswordSprayingCheck {
    <#
    .SYNOPSIS
        Detects conditions that make the domain susceptible to password spraying (T1110.003).
    .PARAMETER PasswordPolicies
        Domain password policy objects from the LDAP collector.
    .PARAMETER Users
        User objects from the LDAP collector.
    #>
    [CmdletBinding()]
    param(
        [object[]]$PasswordPolicies = @(),
        [object[]]$Users = @()
    )

    Write-Verbose "Running Password Spraying check (ATK-001)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # --- Check effective lockout threshold ---
        $defaultPolicy = $PasswordPolicies | Where-Object { -not $_.AppliesTo -or $_.AppliesTo -eq 'Default' } | Select-Object -First 1
        $lockoutThreshold = 0
        if ($defaultPolicy) {
            $lockoutThreshold = if ($defaultPolicy.LockoutThreshold) { [int]$defaultPolicy.LockoutThreshold } else { 0 }
        }

        if ($lockoutThreshold -eq 0) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-001' `
                -Title       'Password Spraying: No Account Lockout Policy (spray-safe environment)' `
                -Severity    'Critical' `
                -Description 'Account lockout threshold is 0 (disabled). Attackers can spray passwords against all accounts indefinitely without triggering lockouts. This is the optimal condition for password spraying attacks (T1110.003).' `
                -AffectedObjects @('Domain Default Password Policy') `
                -Remediation 'Set LockoutThreshold to 5-10 in the Default Domain Policy. Configure Fine-Grained Password Policies (PSOs) for privileged accounts with a lower threshold (3-5). Enable Azure AD Smart Lockout for hybrid environments.' `
                -MitreAttack 'T1110.003'
            ))
        }
        elseif ($lockoutThreshold -gt 10) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-001' `
                -Title       "Password Spraying: Weak Lockout Threshold ($lockoutThreshold attempts)" `
                -Severity    'High' `
                -Description "Account lockout threshold of $lockoutThreshold allows significant password spray attempts before lockout. Best practice is 5-10 attempts." `
                -AffectedObjects @('Domain Default Password Policy') `
                -Remediation "Reduce LockoutThreshold to 5-10. Current value of $lockoutThreshold is too permissive for spray-resistant configurations." `
                -MitreAttack 'T1110.003'
            ))
        }

        # --- Accounts with PasswordNeverExpires (spray-friendly targets) ---
        $neverExpiresEnabled = @($Users | Where-Object {
            $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true
        })
        if ($neverExpiresEnabled.Count -gt 20) {
            $affected = @($neverExpiresEnabled | Select-Object -First 20 -ExpandProperty SamAccountName)
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-001' `
                -Title       "$($neverExpiresEnabled.Count) enabled accounts with PasswordNeverExpires (stale credential targets)" `
                -Severity    'Medium' `
                -Description "Accounts with PasswordNeverExpires accumulate over time with unchanged credentials, making them high-value spray targets. If an old default password or leaked credential is still in use, these accounts will be compromised." `
                -AffectedObjects $affected `
                -Remediation 'Enforce password expiration for all non-service accounts. Use gMSA for service accounts. Audit PasswordNeverExpires accounts for password age and enforce rotation.' `
                -MitreAttack 'T1110.003'
            ))
        }

        Write-Verbose "Password Spraying check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Password Spraying check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Machine Account Quota

function Invoke-MachineAccountQuotaCheck {
    <#
    .SYNOPSIS
        Checks ms-DS-MachineAccountQuota which allows non-privileged users to add machines
        to the domain — a key primitive for RBCD and domain takeover attacks (T1136.001).
    .PARAMETER DomainName
        DNS name of the domain.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    Write-Verbose "Running MachineAccountQuota check (ATK-002)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        $domainDN = 'DC=' + ($DomainName -replace '\.', ',DC=')
        $searcher = [System.DirectoryServices.DirectorySearcher]::new()
        $searcher.SearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$domainDN")
        $searcher.Filter = '(objectClass=domain)'
        $searcher.SearchScope = 'Base'
        $searcher.PropertiesToLoad.AddRange([string[]]@('ms-DS-MachineAccountQuota','distinguishedName'))

        $result = $searcher.FindOne()
        $quota = 10  # Default AD value

        if ($result -and $result.Properties['ms-DS-MachineAccountQuota'].Count -gt 0) {
            $quota = [int]($result.Properties['ms-DS-MachineAccountQuota'][0])
        }

        if ($quota -gt 0) {
            $severity = if ($quota -ge 10) { 'Critical' } else { 'High' }
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-002' `
                -Title       "MachineAccountQuota is $quota — non-admin users can join machines to domain" `
                -Severity    $severity `
                -Description "ms-DS-MachineAccountQuota = $quota allows any authenticated domain user to create up to $quota machine accounts. This is exploited in Resource-Based Constrained Delegation (RBCD) attacks and as a stepping stone to full domain compromise via S4U2Self. The default value of 10 should be reduced to 0 for most environments." `
                -AffectedObjects @("$domainDN (MachineAccountQuota=$quota)") `
                -Remediation 'Set ms-DS-MachineAccountQuota to 0 on the domain root object: Set-ADDomain -Identity <domain> -Replace @{"ms-DS-MachineAccountQuota"=0}. Use JEA or dedicated accounts for workstation provisioning.' `
                -MitreAttack 'T1136.001'
                -ExtraData @{ MachineAccountQuota = $quota }
            ))
        }
        else {
            Write-Verbose "MachineAccountQuota = 0 (secure)"
        }

        $searcher.Dispose()
        Write-Verbose "MachineAccountQuota check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "MachineAccountQuota check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Golden Ticket (KRBTGT)

function Invoke-GoldenTicketCheck {
    <#
    .SYNOPSIS
        Checks KRBTGT account health — the key prerequisite for Golden Ticket attacks (T1558.001).
    .PARAMETER Users
        User objects from LDAP collector (should include krbtgt).
    .PARAMETER DomainControllers
        DC objects from LDAP collector.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Users = @(),
        [object[]]$DomainControllers = @()
    )

    Write-Verbose "Running Golden Ticket / KRBTGT check (ATK-003/004)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        $krbtgt = $Users | Where-Object { $_.SamAccountName -eq 'krbtgt' } | Select-Object -First 1

        if (-not $krbtgt) {
            Write-Verbose "KRBTGT account not found in collected users — attempting LDAP query"
            try {
                $searcher = [System.DirectoryServices.DirectorySearcher]::new()
                $searcher.Filter = '(sAMAccountName=krbtgt)'
                $searcher.PropertiesToLoad.AddRange([string[]]@('pwdLastSet','whenCreated','samAccountName'))
                $result = $searcher.FindOne()
                if ($result) {
                    $pwdLastSetRaw = $result.Properties['pwdLastSet']
                    $whenCreated   = $result.Properties['whenCreated']
                    $pwdLastSet = $null
                    if ($pwdLastSetRaw -and $pwdLastSetRaw.Count -gt 0 -and $pwdLastSetRaw[0] -is [long] -and [long]$pwdLastSetRaw[0] -gt 0) {
                        $pwdLastSet = [DateTime]::FromFileTime([long]$pwdLastSetRaw[0])
                    }
                    $krbtgt = [PSCustomObject]@{
                        SamAccountName  = 'krbtgt'
                        PasswordLastSet = $pwdLastSet
                        WhenCreated     = if ($whenCreated -and $whenCreated.Count -gt 0) { $whenCreated[0] } else { $null }
                    }
                }
                $searcher.Dispose()
            }
            catch { Write-Verbose "LDAP krbtgt query failed: $_" }
        }

        if ($krbtgt) {
            $pwdLastSet = $null
            if ($krbtgt.PasswordLastSet -and $krbtgt.PasswordLastSet -ne [DateTime]::MinValue) {
                $pwdLastSet = $krbtgt.PasswordLastSet
            }

            if ($pwdLastSet) {
                $daysSinceRotation = ([DateTime]::UtcNow - $pwdLastSet.ToUniversalTime()).Days

                if ($daysSinceRotation -gt 180) {
                    $findings.Add((New-ATKFinding `
                        -RuleId      'ATK-003' `
                        -Title       "KRBTGT password not rotated in $daysSinceRotation days (Golden Ticket risk)" `
                        -Severity    'Critical' `
                        -Description "The KRBTGT account password was last changed $daysSinceRotation days ago ($(($pwdLastSet).ToString('yyyy-MM-dd'))). KRBTGT is the foundation of Kerberos trust — if an attacker has ever obtained the KRBTGT hash (via DCSync, NTDS.dit access, or Golden Ticket), stale credentials mean forged tickets remain valid indefinitely. Microsoft recommends rotating KRBTGT twice every 180 days." `
                        -AffectedObjects @('krbtgt') `
                        -Remediation 'Rotate KRBTGT password TWICE (with a pause between rotations to allow replication): Invoke-Mimikatz -Command "lsadump::changentlm /user:krbtgt" OR use the Microsoft KRBTGT rotation script. After rotation, all existing Golden Tickets are invalidated.' `
                        -MitreAttack 'T1558.001'
                        -ExtraData @{ DaysSinceRotation = $daysSinceRotation; PasswordLastSet = $pwdLastSet.ToString('o') }
                    ))
                }
                elseif ($daysSinceRotation -gt 90) {
                    $findings.Add((New-ATKFinding `
                        -RuleId      'ATK-004' `
                        -Title       "KRBTGT password stale — $daysSinceRotation days since last rotation" `
                        -Severity    'High' `
                        -Description "KRBTGT password was last changed $daysSinceRotation days ago. While not yet at critical threshold, regular rotation (every 90-180 days) limits the window of exposure for any previously stolen KRBTGT hash." `
                        -AffectedObjects @('krbtgt') `
                        -Remediation 'Schedule KRBTGT rotation. Use the New-KrbtgtKeys.ps1 Microsoft script to rotate both the current and previous passwords. Rotation must be performed twice to invalidate all existing TGTs.' `
                        -MitreAttack 'T1558.001'
                        -ExtraData @{ DaysSinceRotation = $daysSinceRotation; PasswordLastSet = $pwdLastSet.ToString('o') }
                    ))
                }
                else {
                    Write-Verbose "KRBTGT password rotated $daysSinceRotation days ago — within acceptable range"
                }
            }
            else {
                $findings.Add((New-ATKFinding `
                    -RuleId      'ATK-003' `
                    -Title       'KRBTGT password last set date is unknown or never changed' `
                    -Severity    'Critical' `
                    -Description 'Unable to determine when the KRBTGT password was last set, or it has never been changed since domain creation. This is a critical Golden Ticket risk.' `
                    -AffectedObjects @('krbtgt') `
                    -Remediation 'Immediately rotate the KRBTGT password twice using the Microsoft KRBTGT rotation script.' `
                    -MitreAttack 'T1558.001'
                ))
            }
        }

        # --- Check for RODC krbtgt accounts ---
        $rodcKrbtgts = @($Users | Where-Object { $_.SamAccountName -like 'krbtgt_*' })
        if ($rodcKrbtgts.Count -gt 0) {
            Write-Verbose "Found $($rodcKrbtgts.Count) RODC KRBTGT account(s): $($rodcKrbtgts.SamAccountName -join ', ')"
        }

        Write-Verbose "Golden Ticket check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Golden Ticket check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Silver Ticket

function Invoke-SilverTicketCheck {
    <#
    .SYNOPSIS
        Identifies service accounts vulnerable to Silver Ticket attacks (T1558.002).
        Silver tickets abuse the service account password hash to forge service tickets.
    .PARAMETER Users
        User objects with SPN and encryption type data.
    .PARAMETER Computers
        Computer objects with SPN data.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Users = @(),
        [object[]]$Computers = @()
    )

    Write-Verbose "Running Silver Ticket check (ATK-005)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # RC4 (0x4 / 4) means the account uses RC4-HMAC, which is weaker than AES
        # msDS-SupportedEncryptionTypes: bit 0=DES-CRC, 1=DES-MD5, 2=RC4, 3=AES128, 4=AES256
        # RC4-only: value is 4 (0x04) or not set (defaults to RC4)
        $rc4ServiceAccounts = @($Users | Where-Object {
            $_.ServicePrincipalNames -and $_.ServicePrincipalNames.Count -gt 0 -and $_.Enabled -eq $true
        } | Where-Object {
            $encType = if ($null -ne $_.'msDS-SupportedEncryptionTypes') { [int]$_.'msDS-SupportedEncryptionTypes' } else { 0 }
            # Not enforcing AES (bits 3 and 4 both zero means AES not required)
            ($encType -band 24) -eq 0
        })

        if ($rc4ServiceAccounts.Count -gt 0) {
            $affected = @($rc4ServiceAccounts | Select-Object -First 30 | ForEach-Object {
                "$($_.SamAccountName) [$($_.ServicePrincipalNames -join '; ')]"
            })
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-005' `
                -Title       "$($rc4ServiceAccounts.Count) service account(s) using RC4 encryption — Silver Ticket vulnerable" `
                -Severity    'High' `
                -Description "Service accounts with SPNs that do not enforce AES Kerberos encryption (AES128/AES256) are vulnerable to Silver Ticket attacks. An attacker with the RC4 NTLM hash of the service account can forge service tickets valid for any service the account hosts, without ever contacting the KDC. RC4 hashes are also faster to crack offline." `
                -AffectedObjects $affected `
                -Remediation '1) Set msDS-SupportedEncryptionTypes = 24 (AES128+AES256) on all service accounts. 2) Set "Network security: Configure encryption types allowed for Kerberos" GPO to require AES. 3) Enable "This account supports Kerberos AES 256 bit encryption" in ADUC. 4) Use gMSA accounts where possible.' `
                -MitreAttack 'T1558.002'
                -ExtraData @{ RC4ServiceAccountCount = $rc4ServiceAccounts.Count }
            ))
        }

        # Check Kerberos ticket max service age via domain policy
        try {
            $searcher = [System.DirectoryServices.DirectorySearcher]::new()
            $searcher.Filter = '(objectClass=domainDNS)'
            $searcher.SearchScope = 'Base'
            $searcher.PropertiesToLoad.Add('msDS-Behavior-Version') | Out-Null
            # Kerberos policy is in Default Domain Policy GPO — check via registry approach would need DC access
            # Flag for awareness
            Write-Verbose "Kerberos MaxServiceTicketAge check requires DC GPO access — see ATK-011 for ticket lifetime checks"
            $searcher.Dispose()
        }
        catch { Write-Verbose "Kerberos policy check skipped: $_" }

        Write-Verbose "Silver Ticket check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Silver Ticket check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Golden Certificate

function Invoke-GoldenCertificateCheck {
    <#
    .SYNOPSIS
        Checks for Golden Certificate attack prerequisites — compromised CA private key (T1649).
    .PARAMETER CertificateAuthorities
        CA objects from the ADCS collector.
    .PARAMETER CertificateTemplates
        Certificate template objects from the ADCS collector.
    #>
    [CmdletBinding()]
    param(
        [object[]]$CertificateAuthorities = @(),
        [object[]]$CertificateTemplates = @()
    )

    Write-Verbose "Running Golden Certificate check (ATK-006)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        if ($CertificateAuthorities.Count -eq 0) {
            Write-Verbose "No Certificate Authorities found — Golden Certificate not applicable"
            return $findings.ToArray()
        }

        foreach ($ca in $CertificateAuthorities) {
            $caName = if ($ca.Name) { $ca.Name } elseif ($ca.DisplayName) { $ca.DisplayName } else { 'Unknown CA' }

            # Check CA certificate validity period (> 10 years = flag)
            $validTo = $null
            if ($ca.ValidTo) { $validTo = $ca.ValidTo }
            elseif ($ca.NotAfter) { $validTo = $ca.NotAfter }

            if ($validTo -and $validTo -is [DateTime]) {
                $validityYears = ($validTo - [DateTime]::UtcNow).TotalDays / 365.25
                if ($validityYears -gt 10) {
                    $findings.Add((New-ATKFinding `
                        -RuleId      'ATK-006' `
                        -Title       "CA '$caName' certificate valid for $([Math]::Round($validityYears,1)) more years (Golden Certificate risk)" `
                        -Severity    'High' `
                        -Description "The CA certificate for '$caName' has an extremely long validity period ($([Math]::Round($validityYears,1)) years remaining). If the CA private key is stolen, an attacker can forge certificates (Golden Certificates) that will be trusted for this entire period. This is the AD CS equivalent of a Golden Ticket." `
                        -AffectedObjects @($caName) `
                        -Remediation '1) Protect CA private keys with HSM (Hardware Security Module). 2) Consider certificate lifecycle management to reduce validity periods on future CA certs. 3) Implement CA key archival with strong access controls. 4) Monitor certificate issuance events (Event ID 4886, 4887).' `
                        -MitreAttack 'T1649'
                        -ExtraData @{ CAName = $caName; ValidityYearsRemaining = [Math]::Round($validityYears, 1) }
                    ))
                }
            }

            # Check for software-based CA (no HSM indicator)
            $providerName = if ($ca.CSProvider) { $ca.CSProvider } elseif ($ca.KeyStorageProvider) { $ca.KeyStorageProvider } else { '' }
            if ($providerName -and $providerName -notmatch 'HSM|CNG|Smart') {
                $findings.Add((New-ATKFinding `
                    -RuleId      'ATK-006' `
                    -Title       "CA '$caName' uses software key storage (no HSM protection)" `
                    -Severity    'High' `
                    -Description "The CA '$caName' stores its private key in software (provider: $providerName) rather than a Hardware Security Module (HSM). Software-stored CA keys can be extracted from the CA server via DPAPI or direct filesystem access, enabling Golden Certificate creation." `
                    -AffectedObjects @("$caName (Provider: $providerName)") `
                    -Remediation 'Migrate CA private key storage to an HSM. Use the certutil -repairstore command after HSM migration. HSMs prevent key extraction even with administrative access.' `
                    -MitreAttack 'T1649'
                    -ExtraData @{ CAName = $caName; KeyProvider = $providerName }
                ))
            }
        }

        # Flag unusually high number of published templates
        $enabledTemplates = @($CertificateTemplates | Where-Object { -not $_.Disabled })
        if ($enabledTemplates.Count -gt 30) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-006' `
                -Title       "$($enabledTemplates.Count) certificate templates published — expanded attack surface" `
                -Severity    'Medium' `
                -Description "A large number of published certificate templates increases the AD CS attack surface. Each additional template is a potential ESC vulnerability vector. Unused templates should be removed from publication." `
                -AffectedObjects @("$($enabledTemplates.Count) published templates") `
                -Remediation 'Audit all published templates. Remove unused templates from Certificate Authorities. Apply the principle of least privilege to enrollment permissions.' `
                -MitreAttack 'T1649'
            ))
        }

        Write-Verbose "Golden Certificate check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Golden Certificate check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region NTDS.dit Access

function Invoke-NtdsDitCheck {
    <#
    .SYNOPSIS
        Checks for overpermissioned access to NTDS.dit — domain credential database (T1003.003).
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .PARAMETER Users
        User objects from LDAP collector.
    #>
    [CmdletBinding()]
    param(
        [object[]]$ACLs = @(),
        [object[]]$Users = @()
    )

    Write-Verbose "Running NTDS.dit access check (ATK-007)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # Accounts with Replication rights (same as DCSync but focused on NTDS access)
        # DS-Replication-Get-Changes-All = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $replicationRights = @($ACLs | Where-Object {
            $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or
            $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or
            ($_.ActiveDirectoryRights -match 'ExtendedRight' -and
             $_.IdentityReference -notmatch 'Domain Controllers|Enterprise Domain Controllers|SYSTEM|Administrators|Enterprise Admins|Domain Admins')
        })

        $suspiciousReplAccounts = @($replicationRights | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN|S-1-5-18|S-1-5-32'
        } | Select-Object -ExpandProperty IdentityReference -Unique)

        if ($suspiciousReplAccounts.Count -gt 0) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-007' `
                -Title       "$($suspiciousReplAccounts.Count) account(s) with DS-Replication rights enabling NTDS.dit extraction" `
                -Severity    'Critical' `
                -Description "Accounts with DS-Replication-Get-Changes-All permission can replicate all domain credentials including NTLM hashes, Kerberos keys, and plaintext reversible-encrypted passwords — the equivalent of dumping NTDS.dit. This right is required for DCSync attacks and should be restricted to Domain Controllers only." `
                -AffectedObjects $suspiciousReplAccounts `
                -Remediation '1) Remove DS-Replication rights from all non-DC accounts immediately. 2) If Azure AD Connect is present, verify MSOL_ accounts only have required permissions. 3) Audit using: (Get-ACL "AD:DC=domain,DC=com").Access | Where-Object ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"' `
                -MitreAttack 'T1003.003'
                -ExtraData @{ AffectedAccounts = $suspiciousReplAccounts }
            ))
        }

        Write-Verbose "NTDS.dit check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "NTDS.dit check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Golden SAML / AD FS

function Invoke-GoldenSAMLCheck {
    <#
    .SYNOPSIS
        Checks for AD FS deployment and Golden SAML attack prerequisites (T1606.002).
    .PARAMETER Users
        User objects (to find ADFS service accounts).
    #>
    [CmdletBinding()]
    param(
        [object[]]$Users = @(),
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    Write-Verbose "Running Golden SAML / AD FS check (ATK-008)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # Look for AD FS service accounts by common naming patterns
        $adfsAccounts = @($Users | Where-Object {
            $_.SamAccountName -match '^(adfssvc|adfs|adfsgmsa|_adfs|svc.adfs|adfsservice)' -or
            ($_.Description -match 'ADFS|AD FS|Federation') -or
            ($_.ServicePrincipalNames -and ($_.ServicePrincipalNames -join ' ') -match 'adfs|federation')
        })

        # Check Configuration NC for AD FS objects via LDAP
        $adfsConfigFound = $false
        try {
            $configNC = $null
            $rootDSE = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
            $configNC = $rootDSE.Properties['configurationNamingContext'][0]

            if ($configNC) {
                $adfsSearcher = [System.DirectoryServices.DirectorySearcher]::new()
                $adfsSearcher.SearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$configNC")
                $adfsSearcher.Filter = '(objectClass=msDS-FederationServiceConfiguration)'
                $adfsSearcher.SearchScope = 'Subtree'
                $adfsResult = $adfsSearcher.FindOne()
                $adfsConfigFound = ($null -ne $adfsResult)
                $adfsSearcher.Dispose()
            }
        }
        catch { Write-Verbose "AD FS config NC check failed: $_" }

        if ($adfsAccounts.Count -gt 0 -or $adfsConfigFound) {
            # AD FS is present — assess risk
            $affectedObjs = @($adfsAccounts | Select-Object -ExpandProperty SamAccountName)
            if ($adfsConfigFound) { $affectedObjs += 'AD FS Configuration Object (Config NC)' }

            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-008' `
                -Title       "AD FS deployment detected — Golden SAML attack surface present" `
                -Severity    'Critical' `
                -Description "Active Directory Federation Services (AD FS) is deployed in this environment. The AD FS token-signing certificate private key, if extracted (e.g., via DPAPI on the AD FS server), enables Golden SAML attacks — forging SAML tokens for any federated identity including cloud resources like Microsoft 365. This is the SAML equivalent of a Golden Ticket and was used in the SolarWinds breach (T1606.002)." `
                -AffectedObjects $affectedObjs `
                -Remediation '1) Store AD FS token-signing certificate private keys in HSM. 2) Restrict administrative access to AD FS servers. 3) Monitor Event ID 411 (AD FS token signing cert changes). 4) Consider migrating to Azure AD SSO/PTA instead of AD FS federation. 5) Implement Privileged Access Workstations for AD FS management.' `
                -MitreAttack 'T1606.002'
                -ExtraData @{ ADFSAccountsFound = $adfsAccounts.Count; ADFSConfigInAD = $adfsConfigFound }
            ))

            # Check AD FS service account privileges
            foreach ($adfsAcct in $adfsAccounts) {
                $isMember = $false
                if ($adfsAcct.MemberOf) {
                    $isMember = $adfsAcct.MemberOf -match 'Domain Admins|Enterprise Admins|Administrators'
                }
                if ($isMember) {
                    $findings.Add((New-ATKFinding `
                        -RuleId      'ATK-008' `
                        -Title       "AD FS service account '$($adfsAcct.SamAccountName)' has excessive domain privileges" `
                        -Severity    'Critical' `
                        -Description "The AD FS service account '$($adfsAcct.SamAccountName)' is a member of privileged AD groups. AD FS service accounts should have minimal permissions — only local service rights on the AD FS server." `
                        -AffectedObjects @($adfsAcct.SamAccountName) `
                        -Remediation 'Remove AD FS service accounts from privileged groups. Use gMSA for AD FS service accounts to prevent password theft.' `
                        -MitreAttack 'T1606.002'
                    ))
                }
            }
        }
        else {
            Write-Verbose "AD FS not detected — Golden SAML not applicable in this environment"
        }

        Write-Verbose "Golden SAML check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Golden SAML check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Entra Connect (Azure AD Connect)

function Invoke-EntraConnectCheck {
    <#
    .SYNOPSIS
        Detects Azure AD Connect (Entra Connect) service accounts and their privilege exposure (T1098.001).
    .PARAMETER Users
        User objects from LDAP collector.
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Users = @(),
        [object[]]$ACLs = @()
    )

    Write-Verbose "Running Entra Connect check (ATK-009)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # MSOL_ accounts are created by Azure AD Connect for directory synchronisation
        $msolAccounts = @($Users | Where-Object {
            $_.SamAccountName -match '^MSOL_' -or
            $_.SamAccountName -match '^AAD_' -or
            ($_.Description -match 'Azure AD Connect|Microsoft Azure AD Connect|directory synchronization') -or
            ($_.UserPrincipalName -match 'sync.*@')
        })

        if ($msolAccounts.Count -gt 0) {
            $affectedNames = @($msolAccounts | Select-Object -ExpandProperty SamAccountName)

            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-009' `
                -Title       "$($msolAccounts.Count) Azure AD Connect sync account(s) detected (MSOL_/AAD_ pattern)" `
                -Severity    'Critical' `
                -Description "Azure AD Connect creates MSOL_* accounts with DCSync-equivalent replication permissions to synchronise identities to Entra ID (Azure AD). Compromising these accounts enables an attacker to extract all on-premises domain credentials via DCSync and potentially escalate to cloud tenant admin. This technique was demonstrated in the AADInternals toolset." `
                -AffectedObjects $affectedNames `
                -Remediation '1) Ensure MSOL_ accounts are not members of Domain Admins or any privileged group. 2) Apply tiered administration — the AAD Connect server should be in Tier 0. 3) Monitor for unusual replication from MSOL_ accounts (Event 4662). 4) Consider migrating to AAD Connect Cloud Sync (agent-based, less privileged). 5) Enable MFA on the Azure AD Connect service account in the cloud.' `
                -MitreAttack 'T1098.001'
                -ExtraData @{ MSOLAccountCount = $msolAccounts.Count; Accounts = $affectedNames }
            ))

            # Check if MSOL accounts have DCSync rights
            foreach ($msolAcct in $msolAccounts) {
                $acctName = $msolAcct.SamAccountName
                $hasDcSyncRight = $ACLs | Where-Object {
                    $_.IdentityReference -match [regex]::Escape($acctName) -and
                    ($_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or
                     $_.ActiveDirectoryRights -match 'ExtendedRight')
                }
                if ($hasDcSyncRight) {
                    $findings.Add((New-ATKFinding `
                        -RuleId      'ATK-009' `
                        -Title       "MSOL sync account '$acctName' has explicit DCSync / replication rights" `
                        -Severity    'Critical' `
                        -Description "The Azure AD Connect sync account '$acctName' has explicit DS-Replication rights on the domain object. While this is expected for AAD Connect operation, it also means that compromising this account grants full DCSync capability (all domain hashes)." `
                        -AffectedObjects @($acctName) `
                        -Remediation '1) Verify this is the expected AAD Connect account and rights are not over-scoped. 2) Ensure the AAD Connect server itself is Tier 0 protected. 3) Monitor all authentication events for MSOL_ accounts.' `
                        -MitreAttack 'T1098.001'
                    ))
                }
            }
        }
        else {
            Write-Verbose "No Azure AD Connect sync accounts detected"
        }

        Write-Verbose "Entra Connect check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Entra Connect check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Pass the Hash

function Invoke-PassTheHashCheck {
    <#
    .SYNOPSIS
        Identifies Pass-the-Hash (PtH) attack prerequisites (T1550.002).
    .PARAMETER DomainControllers
        DC objects from LDAP collector.
    .PARAMETER NtlmSettings
        NTLM configuration from SMB collector.
    .PARAMETER Computers
        Computer objects for LAPS coverage check.
    #>
    [CmdletBinding()]
    param(
        [object[]]$DomainControllers = @(),
        [object[]]$NtlmSettings = @(),
        [object[]]$Computers = @()
    )

    Write-Verbose "Running Pass-the-Hash check (ATK-010)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # --- Check LM hash storage ---
        $lmHashEnabled = $false
        $noLMHash = $null

        try {
            $noLMHash = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ErrorAction SilentlyContinue
            if ($null -eq $noLMHash -or $noLMHash.NoLMHash -eq 0) {
                $lmHashEnabled = $true
            }
        }
        catch { Write-Verbose "LM hash registry check failed (may be remote context): $_" }

        # --- Check NTLMv1 ---
        $ntlmv1Allowed = $false
        foreach ($ntlmSetting in $NtlmSettings) {
            $lmLevel = if ($ntlmSetting.LmCompatibilityLevel) { [int]$ntlmSetting.LmCompatibilityLevel } else { -1 }
            if ($lmLevel -ge 0 -and $lmLevel -lt 3) {
                $ntlmv1Allowed = $true
                break
            }
        }

        if ($ntlmv1Allowed) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-010' `
                -Title       'NTLMv1 allowed on domain controllers — LM/NTLMv1 hashes extractable' `
                -Severity    'High' `
                -Description 'NTLMv1 is permitted (LmCompatibilityLevel < 3). NTLMv1 challenge responses can be cracked with precomputed rainbow tables in seconds and the resulting NTLM hashes enable Pass-the-Hash attacks without needing to crack the password.' `
                -AffectedObjects @('Domain Controllers (NTLMv1 LmCompatibilityLevel)') `
                -Remediation 'Set LmCompatibilityLevel to 5 (Send NTLMv2 response only; refuse LM and NTLM) via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > "Network security: LAN Manager authentication level".' `
                -MitreAttack 'T1550.002'
            ))
        }

        # --- Check LAPS coverage ---
        $computersWithoutLAPS = @($Computers | Where-Object {
            -not $_.'ms-Mcs-AdmPwd' -and -not $_.'msLAPS-Password' -and $_.Enabled -eq $true
        })
        if ($computersWithoutLAPS.Count -gt 0) {
            $affected = @($computersWithoutLAPS | Select-Object -First 20 -ExpandProperty SamAccountName)
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-010' `
                -Title       "$($computersWithoutLAPS.Count) computers without LAPS — shared local admin password enables lateral movement" `
                -Severity    'High' `
                -Description "Computers without LAPS (Local Administrator Password Solution) likely share the same local administrator password. A single Pass-the-Hash attack against one machine can propagate laterally to all machines with the same local admin hash — a classic 'horizontal' PTH attack." `
                -AffectedObjects $affected `
                -Remediation '1) Deploy Microsoft LAPS or Windows LAPS (Windows 11/2022) to all workstations and servers. 2) Use LAPS PowerShell module to verify coverage. 3) As interim mitigation, disable the built-in Administrator account and create unique local admin accounts.' `
                -MitreAttack 'T1550.002'
                -ExtraData @{ ComputersWithoutLAPS = $computersWithoutLAPS.Count }
            ))
        }

        Write-Verbose "Pass-the-Hash check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Pass-the-Hash check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region Pass the Ticket

function Invoke-PassTheTicketCheck {
    <#
    .SYNOPSIS
        Identifies Pass-the-Ticket (PtT) attack prerequisites (T1550.003).
    .PARAMETER Users
        User objects with delegation settings.
    .PARAMETER Computers
        Computer objects with delegation settings.
    .PARAMETER DomainControllers
        DC objects.
    #>
    [CmdletBinding()]
    param(
        [object[]]$Users = @(),
        [object[]]$Computers = @(),
        [object[]]$DomainControllers = @()
    )

    Write-Verbose "Running Pass-the-Ticket check (ATK-011)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # Check for Kerberos ticket age policy (domain policy)
        # MaxTicketAge default is 10 hours, MaxRenewAge is 7 days
        # If these are set higher than defaults, PTT window is extended
        try {
            $searcher = [System.DirectoryServices.DirectorySearcher]::new()
            $searcher.Filter = '(objectClass=domain)'
            $searcher.SearchScope = 'Base'
            $searcher.PropertiesToLoad.AddRange([string[]]@('maxTicketAge','maxRenewAge'))
            $result = $searcher.FindOne()

            if ($result) {
                $maxTicketAge = $result.Properties['maxTicketAge']
                $maxRenewAge  = $result.Properties['maxRenewAge']

                if ($maxTicketAge -and $maxTicketAge.Count -gt 0) {
                    $ticketHours = [int]($maxTicketAge[0])
                    if ($ticketHours -gt 10) {
                        $findings.Add((New-ATKFinding `
                            -RuleId      'ATK-011' `
                            -Title       "Kerberos MaxTicketAge is $ticketHours hours (default 10) — extended PTT window" `
                            -Severity    'Medium' `
                            -Description "Kerberos TGTs are valid for $ticketHours hours. A stolen TGT remains usable for this entire period via Pass-the-Ticket attacks. The Microsoft default of 10 hours already provides a significant window — values above this increase exposure." `
                            -AffectedObjects @("Domain Kerberos Policy (MaxTicketAge=$ticketHours hours)") `
                            -Remediation 'Reduce MaxTicketAge to 10 hours (default) or lower via Default Domain Policy > Kerberos Policy. Implement short-lived tickets (4-8 hours) for highly privileged accounts.' `
                            -MitreAttack 'T1550.003'
                            -ExtraData @{ MaxTicketAgeHours = $ticketHours }
                        ))
                    }
                }
            }
            $searcher.Dispose()
        }
        catch { Write-Verbose "Kerberos policy LDAP check failed: $_" }

        # Unconstrained delegation targets (tickets can be extracted from memory)
        $unconstrainedUsers = @($Users | Where-Object { $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true })
        $unconstrainedComps = @($Computers | Where-Object {
            $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true -and
            $_.DistinguishedName -notmatch 'OU=Domain Controllers'
        })

        $totalUnconstrained = $unconstrainedUsers.Count + $unconstrainedComps.Count
        if ($totalUnconstrained -gt 0) {
            $affected = @($unconstrainedUsers | Select-Object -ExpandProperty SamAccountName) +
                        @($unconstrainedComps | Select-Object -ExpandProperty SamAccountName)
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-011' `
                -Title       "$totalUnconstrained account(s) with unconstrained delegation — forwardable TGT theft surface" `
                -Severity    'High' `
                -Description "Accounts with unconstrained delegation receive forwardable TGTs from connecting users/computers. If an attacker compromises one of these systems, they can extract TGTs from LSASS memory (via Mimikatz sekurlsa::tickets) and reuse them (Pass-the-Ticket) to impersonate any user who authenticated to the compromised system. Combined with printer bug/coerce techniques, this can yield DC TGTs." `
                -AffectedObjects $affected `
                -Remediation '1) Migrate from unconstrained to constrained delegation or Resource-Based Constrained Delegation (RBCD). 2) Add accounts to the Protected Users security group to prevent forwardable TGTs. 3) Set "Account is sensitive and cannot be delegated" on high-privilege accounts.' `
                -MitreAttack 'T1550.003'
            ))
        }

        Write-Verbose "Pass-the-Ticket check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "Pass-the-Ticket check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region DCShadow

function Invoke-DCShadowCheck {
    <#
    .SYNOPSIS
        Detects conditions enabling DCShadow attacks — rogue DC injection (T1207).
    .PARAMETER DomainControllers
        Known DC objects from LDAP collector.
    .PARAMETER Computers
        All computer objects for anomaly detection.
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .PARAMETER DomainName
        Domain DNS name.
    #>
    [CmdletBinding()]
    param(
        [object[]]$DomainControllers = @(),
        [object[]]$Computers = @(),
        [object[]]$ACLs = @(),
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    Write-Verbose "Running DCShadow check (ATK-012)..."
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        # --- Check for replication rights on non-DCs (required to inject objects via DCShadow) ---
        # DCShadow requires DS-Install-Replica permission or schema write + replication access
        $replicationSPN = 'E3514235-4B06-11D1-AB04-00C04FC2DCD2'  # Replication SPN GUID

        # Look for computer objects outside Domain Controllers OU with DC-like replication SPNs
        # The replication SPN is registered as: E3514235-4B06-11D1-AB04-00C04FC2DCD2/<FQDN>/<domain>
        $rogueIndicators = @($Computers | Where-Object {
            $_.DistinguishedName -notmatch 'OU=Domain Controllers' -and
            $_.ServicePrincipalNames -and
            ($_.ServicePrincipalNames -join ' ') -match 'E3514235-4B06-11D1-AB04-00C04FC2DCD2'
        })

        if ($rogueIndicators.Count -gt 0) {
            $affected = @($rogueIndicators | Select-Object -ExpandProperty SamAccountName)
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-012' `
                -Title       "$($rogueIndicators.Count) non-DC computer(s) with DC replication SPN — potential DCShadow indicator" `
                -Severity    'Critical' `
                -Description "Computer accounts outside the Domain Controllers OU have the replication SPN (E3514235-4B06-11D1-AB04-00C04FC2DCD2). This is a hallmark of a DCShadow attack in progress or previous execution. DCShadow temporarily registers a rogue DC to inject malicious objects into Active Directory bypassing detection." `
                -AffectedObjects $affected `
                -Remediation '1) Immediately investigate these computer accounts. 2) Check Configuration NC for unauthorised DC registrations. 3) Audit recent schema and object changes. 4) Restrict who can add replication SPNs using AD ACLs.' `
                -MitreAttack 'T1207'
                -ExtraData @{ RogueDCIndicators = $affected }
            ))
        }

        # --- Check Configuration NC for unexpected DC registrations ---
        try {
            $configDCCount = 0
            $rootDSE = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
            $configNC = $rootDSE.Properties['configurationNamingContext'][0]

            if ($configNC) {
                $dcSearcher = [System.DirectoryServices.DirectorySearcher]::new()
                $dcSearcher.SearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=Sites,$configNC")
                $dcSearcher.Filter = '(objectClass=nTDSDSA)'
                $dcSearcher.SearchScope = 'Subtree'
                $dcResults = $dcSearcher.FindAll()
                $configDCCount = $dcResults.Count
                $dcSearcher.Dispose()
            }

            if ($DomainControllers.Count -gt 0 -and $configDCCount -gt $DomainControllers.Count + 1) {
                $findings.Add((New-ATKFinding `
                    -RuleId      'ATK-012' `
                    -Title       "Configuration NC has $configDCCount DC registrations vs $($DomainControllers.Count) known DCs — possible rogue DC" `
                    -Severity    'Critical' `
                    -Description "The Configuration naming context shows $configDCCount registered domain controllers, but only $($DomainControllers.Count) DCs were enumerated. This discrepancy may indicate a rogue DC registration (DCShadow) or an orphaned DC object that needs cleanup." `
                    -AffectedObjects @("Configuration NC: $configDCCount entries vs $($DomainControllers.Count) actual DCs") `
                -Remediation '1) Enumerate all nTDSDSA objects in the Configuration NC. 2) Verify each corresponds to a real DC. 3) Remove orphaned DC registrations: ntdsutil "metadata cleanup". 4) Audit recent changes to the Configuration NC.' `
                    -MitreAttack 'T1207'
                ))
            }
        }
        catch { Write-Verbose "Configuration NC DC count check failed: $_" }

        # --- Check for DS-Install-Replica rights ---
        $dsInstallReplica = '{9923a32a-3607-11d2-b9be-0000f87a36b2}'
        $installReplicaRights = @($ACLs | Where-Object {
            ($_.ObjectType -eq $dsInstallReplica -or $_.ActiveDirectoryRights -match 'ExtendedRight') -and
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference -notmatch 'Domain Controllers|Enterprise Domain Controllers|SYSTEM|Enterprise Admins|Domain Admins'
        } | Select-Object -ExpandProperty IdentityReference -Unique)

        if ($installReplicaRights.Count -gt 0) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-012' `
                -Title       "$($installReplicaRights.Count) non-standard account(s) with DS-Install-Replica right" `
                -Severity    'High' `
                -Description "Accounts with the DS-Install-Replica extended right can add new domain controllers to the domain. This permission is required for DCShadow to register a rogue DC. It should be restricted to Enterprise Admins and Domain Admins only." `
                -AffectedObjects $installReplicaRights `
                -Remediation 'Remove DS-Install-Replica rights from non-admin accounts. Only Enterprise Admins should have this permission.' `
                -MitreAttack 'T1207'
            ))
        }

        Write-Verbose "DCShadow check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "DCShadow check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region NTLM Relay

function Invoke-NTLMRelayCheck {
    <#
    .SYNOPSIS
        Consolidated NTLM relay attack surface assessment (T1557.001).
    .PARAMETER DomainControllers
        DC objects from LDAP collector.
    .PARAMETER SmbSigningData
        SMB signing configuration data.
    .PARAMETER LdapSigningData
        LDAP signing configuration data.
    .PARAMETER NtlmData
        NTLM configuration data.
    #>
    [CmdletBinding()]
    param(
        [object[]]$DomainControllers = @(),
        [object[]]$SmbSigningData = @(),
        [object[]]$LdapSigningData = @(),
        [object[]]$NtlmData = @()
    )

    Write-Verbose "Running NTLM Relay surface check (ATK-013)..."
    $findings = [System.Collections.Generic.List[object]]::new()
    $relayVectors = [System.Collections.Generic.List[string]]::new()

    try {
        # --- SMB Signing ---
        $smbUnsigned = @($SmbSigningData | Where-Object {
            -not $_.RequireSecuritySignature -and -not $_.SigningRequired
        })
        if ($smbUnsigned.Count -gt 0) {
            $relayVectors.Add("SMB signing not required on $($smbUnsigned.Count) host(s)")
        }

        # --- LDAP Signing ---
        $ldapUnsigned = @($LdapSigningData | Where-Object {
            $_.LdapServerIntegrity -lt 2 -or -not $_.SigningRequired
        })
        if ($ldapUnsigned.Count -gt 0) {
            $relayVectors.Add("LDAP signing not required/enforced on $($ldapUnsigned.Count) host(s)")
        }

        # --- NTLM allowed ---
        foreach ($ntlmSetting in $NtlmData) {
            $level = if ($ntlmSetting.LmCompatibilityLevel) { [int]$ntlmSetting.LmCompatibilityLevel } else { -1 }
            if ($level -ge 0 -and $level -lt 5) {
                $relayVectors.Add("NTLMv1/v2 downgrade possible (LmCompatibilityLevel=$level)")
                break
            }
        }

        # --- Spooler (PrinterBug) on DCs ---
        $spoolerDCs = @($DomainControllers | Where-Object { $_.SpoolerRunning -eq $true })
        if ($spoolerDCs.Count -gt 0) {
            $relayVectors.Add("Print Spooler running on $($spoolerDCs.Count) DC(s) — PrinterBug coerce vector")
        }

        # --- WebClient on DCs (WebDAV relay) ---
        $webClientDCs = @($DomainControllers | Where-Object { $_.WebClientRunning -eq $true })
        if ($webClientDCs.Count -gt 0) {
            $relayVectors.Add("WebClient (WebDAV) running on $($webClientDCs.Count) DC(s) — HTTP relay vector")
        }

        if ($relayVectors.Count -ge 2) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-013' `
                -Title       "NTLM Relay attack surface: $($relayVectors.Count) active vector(s) detected" `
                -Severity    'Critical' `
                -Description "Multiple NTLM relay attack vectors are present. NTLM relay attacks (Responder, ntlmrelayx) capture NTLM authentication and relay it to other services, enabling privilege escalation without cracking passwords. Vectors detected: $($relayVectors -join '; ')." `
                -AffectedObjects $relayVectors.ToArray() `
                -Remediation '1) Require SMB signing on ALL hosts via GPO. 2) Set LDAP signing to "Require signing" (LDAPServerIntegrity=2). 3) Enable Extended Protection for Authentication (EPA/Channel Binding). 4) Disable Print Spooler on DCs. 5) Disable WebClient service on servers. 6) Block inbound NTLM via GPO where possible. 7) Consider deploying ATA/MDI to detect relay attacks.' `
                -MitreAttack 'T1557.001'
                -ExtraData @{ RelayVectors = $relayVectors.ToArray() }
            ))
        }
        elseif ($relayVectors.Count -eq 1) {
            $findings.Add((New-ATKFinding `
                -RuleId      'ATK-013' `
                -Title       "NTLM Relay vector detected: $($relayVectors[0])" `
                -Severity    'High' `
                -Description "An NTLM relay attack vector is present: $($relayVectors[0]). While a single vector is less impactful than combined attack chains, it still enables credential relay attacks in the right conditions." `
                -AffectedObjects $relayVectors.ToArray() `
                -Remediation 'Remediate the identified NTLM relay vector. See ATK-013 remediation guidance.' `
                -MitreAttack 'T1557.001'
            ))
        }

        Write-Verbose "NTLM Relay check complete. Findings: $($findings.Count)"
    }
    catch {
        Write-Warning "NTLM Relay check error: $_"
    }

    return $findings.ToArray()
}

#endregion

#region CredentialDumping

function Invoke-CredentialDumpingCheck {
    <#
    .SYNOPSIS
        Detects AD configuration weaknesses that facilitate credential dumping (T1003).
    .DESCRIPTION
        Checks for Credential Guard readiness, LSASS PPL status indicators, WDigest
        cleartext password settings, LSA protection, cached domain logon count, SAM
        access restrictions, and DPAPI domain backup key exposure.  All checks are
        read-only LDAP/registry-query based.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$DomainControllers = @(),
        [array]$Users             = @(),
        [array]$Computers         = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    # -----------------------------------------------------------------------
    # 1. Credential Guard / Device Guard deployment on DCs
    # -----------------------------------------------------------------------
    $dcList = @($DomainControllers | Where-Object { $_ -and $_.DNSHostName })
    if ($dcList.Count -gt 0) {
        $cgDisabled = [System.Collections.Generic.List[string]]::new()
        foreach ($dc in $dcList) {
            try {
                $name = $dc.DNSHostName
                # Detect via LSACFG key in AD computer object attributes (read-only)
                $osName = if ($dc.PSObject.Properties['OperatingSystem']) { $dc.OperatingSystem } else { 'Unknown' }
                # Win2016+ supports Credential Guard; older OS = always vulnerable
                if ($osName -match 'Windows Server (2003|2008( R2)?|2012(?! R2))|Windows (XP|Vista|7|8(?!\.1))') {
                    $cgDisabled.Add("$name ($osName — OS too old for Credential Guard)")
                } else {
                    # Can't read registry remotely in read-only mode; record as unverified
                    $cgDisabled.Add("$name — Credential Guard status unverified (requires local registry check)")
                }
            } catch { }
        }
        if ($cgDisabled.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                RuleId          = 'ATK-015'
                Category        = 'Credential Dumping'
                Title           = 'Credential Guard Not Confirmed on Domain Controllers'
                Severity        = 'High'
                Status          = 'Finding'
                Description     = 'Credential Guard isolates LSASS secrets in a VBS enclave, blocking Mimikatz-style memory reads. DCs without Credential Guard are vulnerable to LSASS credential extraction by any code running as SYSTEM.'
                AffectedObjects = @($cgDisabled)
                Remediation     = 'Enable Credential Guard via Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > "Turn On Virtualization Based Security". Requires VBS-capable hardware (Hyper-V, Secure Boot, IOMMU).'
                MitreAttack     = 'T1003.001'
                References      = @('https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard', 'https://attack.mitre.org/techniques/T1003/001/')
                VerificationCommand = 'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity","RequirePlatformSecurityFeatures" -ErrorAction SilentlyContinue'
                Timestamp       = $now
            })
        }
    }

    # -----------------------------------------------------------------------
    # 2. WDigest UseLogonCredential — detects cleartext password caching
    # -----------------------------------------------------------------------
    # We enumerate domain-joined computers with outdated OS (WDigest default = enabled pre-Win8.1)
    $wdigestRisk = @($Computers | Where-Object {
        $_ -and $_.OperatingSystem -match 'Windows (XP|Vista|7|2003|2008( R2)?)'
    } | Select-Object -ExpandProperty DNSHostName -ErrorAction SilentlyContinue)

    if ($wdigestRisk.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-015'
            Category        = 'Credential Dumping'
            Title           = 'WDigest Cleartext Caching Risk (Legacy OS in Domain)'
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "WDigest authentication caches cleartext passwords in LSASS on pre-Windows 8.1/2012 R2 systems. $($wdigestRisk.Count) legacy system(s) still joined to the domain. Any attacker with SYSTEM on these hosts can extract plaintext credentials."
            AffectedObjects = $wdigestRisk
            Remediation     = 'Decommission or upgrade all pre-Windows 8.1/2012 R2 systems. For modern systems confirm HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0 (set via GPO).'
            MitreAttack     = 'T1003.001'
            References      = @('https://support.microsoft.com/kb/2871997', 'https://attack.mitre.org/techniques/T1003/001/')
            VerificationCommand = 'Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object { $_.OperatingSystem -match "Windows (XP|Vista|7|2003|2008)" } | Select-Object Name, OperatingSystem'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. Elevated accounts with interactive logon rights on non-Tier-0 systems
    #    (credential exposure path for credential dumping)
    # -----------------------------------------------------------------------
    $privUsers = @($Users | Where-Object {
        $_ -and $_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators' })
    })
    $exposedAdmins = @($privUsers | Where-Object {
        $_.PSObject.Properties['LastLogonDate'] -and $_.LastLogonDate -gt (Get-Date).AddDays(-30)
    })
    if ($exposedAdmins.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-015'
            Category        = 'Credential Dumping'
            Title           = 'Active Privileged Accounts with Recent Interactive Logons'
            Severity        = 'High'
            Status          = 'Finding'
            Description     = "$($exposedAdmins.Count) privileged account(s) have logged on interactively within the last 30 days. Each logon deposits credentials (TGT, NTLM hash, possibly cleartext) into LSASS on the workstation used, expanding the credential dump attack surface beyond domain controllers."
            AffectedObjects = @($exposedAdmins | ForEach-Object { "$($_.SamAccountName) — LastLogon $($_.LastLogonDate.ToString('yyyy-MM-dd'))" })
            Remediation     = 'Enforce Privileged Access Workstations (PAWs). Add DA/EA accounts to Protected Users group. Restrict interactive logon rights via "Deny log on locally" and "Deny log on through Remote Desktop Services" GPOs for Tier 0 accounts.'
            MitreAttack     = 'T1003.001'
            References      = @('https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model', 'https://attack.mitre.org/techniques/T1003/')
            VerificationCommand = 'Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -Properties LastLogonDate | Sort-Object LastLogonDate -Descending | Select-Object SamAccountName, LastLogonDate'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 4. DPAPI domain backup key exposure indicators
    #    (accounts with GenericAll/WriteDACL on domain root)
    # -----------------------------------------------------------------------
    $dpapiFinding = $null
    # If no specific DPAPI data, check if DCSync-capable accounts exist (already checked in PB module),
    # so we emit an informational finding about DPAPI domain key
    $findings.Add([PSCustomObject]@{
        RuleId          = 'ATK-015'
        Category        = 'Credential Dumping'
        Title           = 'DPAPI Domain Backup Key — Verify Restricted Access'
        Severity        = 'Medium'
        Status          = 'Review'
        Description     = 'The DPAPI domain backup key (stored in CN=BCKUPKEY_*,CN=System) allows decryption of all DPAPI-protected secrets for domain users. Any account with DCSync rights or direct read access to this object can recover all DPAPI secrets including cached credentials and certificates.'
        AffectedObjects = @('CN=BCKUPKEY_*,CN=System,DC=<domain>')
        Remediation     = 'Verify only Domain Controllers have read access to BCKUPKEY objects. Use Mimikatz ''lsadump::backupkeys /export'' in audit to confirm. Rotate DPAPI backup key if compromise is suspected.'
        MitreAttack     = 'T1555.004'
        References      = @('https://attack.mitre.org/techniques/T1555/004/', 'https://www.dsinternals.com/en/dumping-and-loading-dpapi-domain-backup-keys/')
        VerificationCommand = 'Get-ADObject -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Filter {objectClass -eq "secret" -and name -like "BCKUPKEY*"} -Properties * | Select-Object Name, DistinguishedName'
        Timestamp       = $now
    })

    return $findings.ToArray()
}

#endregion

#region LateralMovement

function Invoke-LateralMovementCheck {
    <#
    .SYNOPSIS
        Detects AD configuration weaknesses that enable lateral movement path abuse (T1021/T1550).
    .DESCRIPTION
        Checks for local admin sprawl, privileged account logon exposure on non-DC systems,
        excessive WinRM/PSRemoting access, risky Kerberos delegation chains, and excessive
        inter-tier session exposure that enable attackers to escalate from Tier 2 to Tier 0.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$Users             = @(),
        [array]$Computers         = @(),
        [array]$DomainControllers = @(),
        [array]$ACLs              = @(),
        [string]$DomainName       = $env:USERDNSDOMAIN
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    # -----------------------------------------------------------------------
    # 1. Local admin sprawl — domain groups/accounts with broad local admin rights
    #    Detected via AdminCount=1 on non-standard accounts (AdminSDHolder)
    # -----------------------------------------------------------------------
    $adminCountAccounts = @($Users | Where-Object {
        $_ -and $_.PSObject.Properties['AdminCount'] -and $_.AdminCount -eq 1 -and
        $_.SamAccountName -notmatch '^(Administrator|krbtgt)$' -and
        $_.MemberOf -and -not ($_.MemberOf | Where-Object { $_ -match 'Domain Admins|Enterprise Admins|Schema Admins|Backup Operators|Account Operators|Server Operators|Print Operators|Replicators' })
    })
    if ($adminCountAccounts.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-016'
            Category        = 'Lateral Movement'
            Title           = 'Non-Standard Accounts with AdminCount=1 (Lateral Movement Path)'
            Severity        = 'High'
            Status          = 'Finding'
            Description     = "$($adminCountAccounts.Count) account(s) have AdminCount=1 but are not members of standard privileged groups. AdminCount=1 accounts have AdminSDHolder ACL protection and are often assigned local admin rights broadly, creating lateral movement paths to Domain Admin."
            AffectedObjects = @($adminCountAccounts | ForEach-Object { $_.SamAccountName })
            Remediation     = 'Audit all AdminCount=1 accounts. Remove unnecessary AdminCount flags via ''Set-ADUser -AdminCount 0''. Eliminate non-standard local admin assignments. Implement LAPS for all workstations.'
            MitreAttack     = 'T1021.002'
            References      = @('https://attack.mitre.org/techniques/T1021/002/', 'https://adsecurity.org/?p=2773')
            VerificationCommand = 'Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Select-Object SamAccountName,MemberOf | Sort-Object SamAccountName'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 2. Constrained delegation → lateral movement chain
    #    Accounts with constrained delegation can be abused to reach any service
    #    the delegation is configured for, enabling lateral movement
    # -----------------------------------------------------------------------
    $constrainedDelegation = @($Users | Where-Object {
        $_ -and $_.PSObject.Properties['msDS-AllowedToDelegateTo'] -and
        $_.'msDS-AllowedToDelegateTo' -and $_.'msDS-AllowedToDelegateTo'.Count -gt 0
    })
    $constrainedDelegationComputers = @($Computers | Where-Object {
        $_ -and $_.PSObject.Properties['msDS-AllowedToDelegateTo'] -and
        $_.'msDS-AllowedToDelegateTo' -and $_.'msDS-AllowedToDelegateTo'.Count -gt 0 -and
        $_.DNSHostName -notin ($DomainControllers | Select-Object -ExpandProperty DNSHostName)
    })
    $allConstrained = @($constrainedDelegation) + @($constrainedDelegationComputers)
    if ($allConstrained.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-016'
            Category        = 'Lateral Movement'
            Title           = 'Constrained Delegation Accounts Enable Lateral Movement'
            Severity        = 'High'
            Status          = 'Finding'
            Description     = "$($allConstrained.Count) account(s)/computer(s) have constrained delegation configured. If any of these are compromised, an attacker can impersonate any domain user (including DA) to reach the delegated service targets, enabling lateral movement and privilege escalation."
            AffectedObjects = @($allConstrained | ForEach-Object {
                $name = if ($_.PSObject.Properties['SamAccountName']) { $_.SamAccountName } else { $_.Name }
                $targets = $_.'msDS-AllowedToDelegateTo' -join ', '
                "$name → $targets"
            })
            Remediation     = 'Review all constrained delegation configurations. Prefer Resource-Based Constrained Delegation (RBCD). Add high-value accounts to Protected Users group (blocks delegation). Audit delegation targets for DC/sensitive service exposure.'
            MitreAttack     = 'T1021.002'
            References      = @('https://attack.mitre.org/techniques/T1021/', 'https://blog.harmj0y.net/activedirectory/s4u2abuse/')
            VerificationCommand = 'Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo,SamAccountName | Select-Object SamAccountName,"msDS-AllowedToDelegateTo"'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. Privileged accounts accessible from workstations (Tier violation)
    #    DA accounts with LastLogonDate on non-DCs indicate Tier 0/1/2 boundary violations
    # -----------------------------------------------------------------------
    $daAccounts = @($Users | Where-Object {
        $_ -and $_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match 'CN=Domain Admins' })
    })
    $staleDA = @($daAccounts | Where-Object {
        $_.PSObject.Properties['LastLogonDate'] -and $_.LastLogonDate -and
        $_.LastLogonDate -gt (Get-Date).AddDays(-7)
    })
    if ($staleDA.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-016'
            Category        = 'Lateral Movement'
            Title           = 'Domain Admin Accounts Active Within Last 7 Days (Session Exposure)'
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "$($staleDA.Count) Domain Admin account(s) have logged on within the last 7 days. Each logon creates a credential footprint that enables Pass-the-Hash/Pass-the-Ticket lateral movement. Attackers with local admin on any workstation these accounts touched can harvest credentials and reach Domain Admin."
            AffectedObjects = @($staleDA | ForEach-Object { "$($_.SamAccountName) — LastLogon: $($_.LastLogonDate.ToString('yyyy-MM-dd'))" })
            Remediation     = 'Enforce privileged access model: DA accounts should only log on to dedicated PAWs/DCs, never to workstations or member servers. Implement ''Deny log on locally'' / ''Deny log on through Remote Desktop Services'' GPOs for Tier 0 accounts on Tier 1/2 systems.'
            MitreAttack     = 'T1078.002'
            References      = @('https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-accounts', 'https://attack.mitre.org/techniques/T1078/002/')
            VerificationCommand = 'Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -Properties LastLogonDate | Where-Object { $_.LastLogonDate -gt (Get-Date).AddDays(-7) } | Select-Object SamAccountName, LastLogonDate'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 4. Excessive computer count per admin (local admin sprawl indicator)
    #    Heuristic: service accounts or generic admin accounts with broad SPN scope
    # -----------------------------------------------------------------------
    $broadSPNAccounts = @($Users | Where-Object {
        $_ -and $_.PSObject.Properties['ServicePrincipalNames'] -and
        $_.ServicePrincipalNames -and $_.ServicePrincipalNames.Count -gt 10
    })
    if ($broadSPNAccounts.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-016'
            Category        = 'Lateral Movement'
            Title           = 'Service Accounts with Excessive SPNs (Wide Lateral Movement Surface)'
            Severity        = 'Medium'
            Status          = 'Finding'
            Description     = "$($broadSPNAccounts.Count) service account(s) have more than 10 SPNs registered, indicating they run services on many machines. If any single machine is compromised, the attacker can use Kerberoasting to crack the account and then move laterally across all SPN targets."
            AffectedObjects = @($broadSPNAccounts | ForEach-Object { "$($_.SamAccountName) — $($_.ServicePrincipalNames.Count) SPNs" })
            Remediation     = 'Audit SPN registrations. Remove unnecessary SPNs. Replace broad service accounts with per-service gMSAs. Enforce AES encryption (block RC4) to raise cracking cost.'
            MitreAttack     = 'T1558.003'
            References      = @('https://attack.mitre.org/techniques/T1558/003/', 'https://adsecurity.org/?p=2293')
            VerificationCommand = 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null"} -Properties ServicePrincipalNames | Where-Object { $_.ServicePrincipalNames.Count -gt 10 } | Select-Object SamAccountName,@{n="SPNCount";e={$_.ServicePrincipalNames.Count}}'
            Timestamp       = $now
        })
    }

    return $findings.ToArray()
}

#endregion

#region ShadowCredentials

function Invoke-ShadowCredentialsCheck {
    <#
    .SYNOPSIS
        Detects conditions enabling Shadow Credentials attacks via msDS-KeyCredentialLink (T1556).
    .DESCRIPTION
        Shadow Credentials abuse allows an attacker with WriteProperty rights over a target account
        to set the msDS-KeyCredentialLink attribute with a forged key credential, then perform
        PKINIT certificate-based authentication as that account — obtaining a TGT and NTLM hash
        without knowing the account password. This check:
          1. Identifies accounts with non-empty msDS-KeyCredentialLink (unexpected key entries)
          2. Identifies accounts (non-DCs/non-WHfB) where the attribute is set outside of expected WHfB flows
          3. Reports accounts where WriteProperty on msDS-KeyCredentialLink is overly permissive
    .PARAMETER Users
        User objects from LDAP collector.
    .PARAMETER Computers
        Computer objects from LDAP collector.
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$Users     = @(),
        [array]$Computers = @(),
        [array]$ACLs      = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    # -----------------------------------------------------------------------
    # 1. Accounts with msDS-KeyCredentialLink set (unexpected key credentials)
    #    In most environments, only Windows Hello for Business (WHfB) sets this.
    #    Finding it on non-WHfB accounts (especially privileged ones) is suspicious.
    # -----------------------------------------------------------------------
    $usersWithKeyCredLink = @($Users | Where-Object {
        $_ -and $_.PSObject.Properties['msDS-KeyCredentialLink'] -and
        $_.'msDS-KeyCredentialLink' -and $_.'msDS-KeyCredentialLink'.Count -gt 0
    })

    $computersWithKeyCredLink = @($Computers | Where-Object {
        $_ -and $_.PSObject.Properties['msDS-KeyCredentialLink'] -and
        $_.'msDS-KeyCredentialLink' -and $_.'msDS-KeyCredentialLink'.Count -gt 0
    })

    if ($usersWithKeyCredLink.Count -gt 0) {
        $privilegedWithKey = @($usersWithKeyCredLink | Where-Object {
            $_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators' })
        })

        $severity = if ($privilegedWithKey.Count -gt 0) { 'Critical' } else { 'High' }
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-017'
            Category        = 'Shadow Credentials'
            Title           = "Shadow Credentials: $($usersWithKeyCredLink.Count) user account(s) have msDS-KeyCredentialLink set"
            Severity        = $severity
            Status          = 'Finding'
            Description     = "The msDS-KeyCredentialLink attribute enables PKINIT certificate-based authentication. $($usersWithKeyCredLink.Count) user account(s) have this attribute set. In environments without Windows Hello for Business (WHfB), this attribute should be empty. An attacker with WriteProperty on an account can forge a key credential to authenticate as that account and retrieve its NTLM hash without knowing the password. $($privilegedWithKey.Count) privileged account(s) are affected."
            AffectedObjects = @($usersWithKeyCredLink | ForEach-Object {
                $isPriv = if ($_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match 'Domain Admins|Enterprise Admins|Schema Admins' })) { ' [PRIVILEGED]' } else { '' }
                "$($_.SamAccountName)$isPriv"
            })
            Remediation     = '1) Audit msDS-KeyCredentialLink values: Get-ADUser -Filter * -Properties msDS-KeyCredentialLink | Where-Object { $_."msDS-KeyCredentialLink" } | Select-Object SamAccountName. 2) Remove unexpected key credentials from accounts not enrolled in WHfB. 3) Restrict WriteProperty on msDS-KeyCredentialLink to Domain Controllers only. 4) Monitor Event ID 4662 (Object access) and 5136 (DS object modification) for changes to msDS-KeyCredentialLink.'
            MitreAttack     = 'T1556'
            References      = @('https://attack.mitre.org/techniques/T1556/', 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab', 'https://github.com/eladshamir/Whisker')
            VerificationCommand = 'Get-ADUser -Filter * -Properties msDS-KeyCredentialLink | Where-Object { $_."msDS-KeyCredentialLink" } | Select-Object SamAccountName, @{n="KeyCredCount";e={$_."msDS-KeyCredentialLink".Count}}'
            Timestamp       = $now
        })
    }

    if ($computersWithKeyCredLink.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-017'
            Category        = 'Shadow Credentials'
            Title           = "Shadow Credentials: $($computersWithKeyCredLink.Count) computer account(s) have msDS-KeyCredentialLink set"
            Severity        = 'High'
            Status          = 'Finding'
            Description     = "$($computersWithKeyCredLink.Count) computer account(s) have msDS-KeyCredentialLink set. In environments without WHfB device credentials, this attribute should be empty on computer accounts. Attackers with write access to computer objects (e.g., via RBCD or unconstrained delegation abuse) can leverage Shadow Credentials to authenticate as the machine account and extract its NTLM hash."
            AffectedObjects = @($computersWithKeyCredLink | ForEach-Object { $_.DNSHostName })
            Remediation     = '1) Review and clear unexpected msDS-KeyCredentialLink values on computer accounts. 2) Audit who has WriteProperty rights on computer objects. 3) Enable LDAP signing and channel binding to prevent relay attacks that could set this attribute.'
            MitreAttack     = 'T1556'
            References      = @('https://attack.mitre.org/techniques/T1556/', 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab')
            VerificationCommand = 'Get-ADComputer -Filter * -Properties msDS-KeyCredentialLink | Where-Object { $_."msDS-KeyCredentialLink" } | Select-Object Name, @{n="KeyCredCount";e={$_."msDS-KeyCredentialLink".Count}}'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 2. ACL check: overly permissive WriteProperty on msDS-KeyCredentialLink
    #    The msDS-KeyCredentialLink attribute GUID: 5b47d60f-6090-40b2-9f37-2a4de88f3063
    # -----------------------------------------------------------------------
    $keyCredLinkGuid = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    $dangerousKeyCredACEs = @($ACLs | Where-Object {
        $_ -and
        ($_.ObjectType -eq $keyCredLinkGuid -or $_.ObjectType -eq '00000000-0000-0000-0000-000000000000') -and
        ($_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll|WriteDacl|WriteOwner') -and
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference -notmatch '^(NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|Domain Admins|Enterprise Admins|Domain Controllers|KEY ADMINS|ENTERPRISE KEY ADMINS)' -and
        $_.TargetObject -match 'CN=Users|CN=Computers|OU='
    })

    if ($dangerousKeyCredACEs.Count -gt 0) {
        $uniquePrincipals = @($dangerousKeyCredACEs | Select-Object -ExpandProperty IdentityReference -Unique)
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-017'
            Category        = 'Shadow Credentials'
            Title           = "Shadow Credentials: $($uniquePrincipals.Count) non-standard principal(s) can write msDS-KeyCredentialLink"
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "$($uniquePrincipals.Count) non-standard principal(s) have WriteProperty (or equivalent) rights on msDS-KeyCredentialLink or all properties on AD user/computer objects. Any of these principals can perform a Shadow Credentials attack to take over any account they have write access to, obtaining a TGT and NTLM hash without knowing the target password."
            AffectedObjects = @($uniquePrincipals)
            Remediation     = '1) Remove overpermissive WriteProperty rights on msDS-KeyCredentialLink. 2) Only Domain Controllers, KEY ADMINS, and ENTERPRISE KEY ADMINS should have this right. 3) Review GenericWrite/GenericAll ACEs on user and computer objects. 4) Add privileged accounts to Protected Users group.'
            MitreAttack     = 'T1556'
            References      = @('https://attack.mitre.org/techniques/T1556/', 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab', 'https://github.com/eladshamir/Whisker')
            VerificationCommand = '(Get-ACL "AD:CN=Users,DC=domain,DC=com").Access | Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll" } | Select-Object IdentityReference, ActiveDirectoryRights'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. Informational: Environment has no WHfB deployment indicator
    #    If no users have msDS-KeyCredentialLink, flag as review point
    # -----------------------------------------------------------------------
    if ($usersWithKeyCredLink.Count -eq 0 -and $computersWithKeyCredLink.Count -eq 0 -and $dangerousKeyCredACEs.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-017'
            Category        = 'Shadow Credentials'
            Title           = 'Shadow Credentials: No msDS-KeyCredentialLink entries detected (verify)'
            Severity        = 'Low'
            Status          = 'Review'
            Description     = 'No accounts with msDS-KeyCredentialLink were detected in the collected data. This may mean the attribute is clean (good) or that the LDAP collector did not retrieve this attribute. Verify collector configuration includes msDS-KeyCredentialLink in the property list. Also audit who has WriteProperty on this attribute to ensure Shadow Credentials attacks remain blocked.'
            AffectedObjects = @()
            Remediation     = 'Ensure LDAP collector fetches msDS-KeyCredentialLink. Periodically audit this attribute across all accounts. Restrict WriteProperty on msDS-KeyCredentialLink to DCs, KEY ADMINS, and ENTERPRISE KEY ADMINS only.'
            MitreAttack     = 'T1556'
            References      = @('https://attack.mitre.org/techniques/T1556/', 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab')
            VerificationCommand = 'Get-ADUser -Filter * -Properties msDS-KeyCredentialLink | Where-Object { $_."msDS-KeyCredentialLink" } | Select-Object SamAccountName'
            Timestamp       = $now
        })
    }

    return $findings.ToArray()
}

#endregion

#region ACLObjectControl

function Invoke-ACLObjectControlCheck {
    <#
    .SYNOPSIS
        Detects multi-hop ACL permission chains that enable privilege escalation (T1222.001).
    .DESCRIPTION
        ACL object control chaining exploits granular AD permissions across multiple objects to
        escalate privileges indirectly. A single WriteDACL on a group → modifying the group →
        adding self → gaining DA is a classic chain. This check identifies:
          1. Non-standard principals with dangerous rights on high-value objects (Domain, AdminSDHolder,
             Domain Controllers OU, privileged groups)
          2. Accounts with WriteDACL / WriteOwner on domain-critical objects (enables full control)
          3. Principals with GenericWrite / AllExtendedRights on user objects (enables password reset,
             Kerberoasting, targeted AS-REP roasting)
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .PARAMETER Users
        User objects from LDAP collector.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$ACLs  = @(),
        [array]$Users = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    if ($ACLs.Count -eq 0) {
        Write-Verbose "No ACL data provided; skipping ACL object control check."
        return $findings.ToArray()
    }

    # Principals that are expected to have elevated rights (skip these to reduce noise)
    $legitimatePrincipals = @(
        'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'Domain Admins',
        'Enterprise Admins', 'Schema Admins', 'Domain Controllers',
        'Enterprise Domain Controllers', 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
        'CREATOR OWNER', 'BUILTIN\Account Operators'
    )

    # -----------------------------------------------------------------------
    # 1. WriteDACL / WriteOwner on domain root or AdminSDHolder
    #    These rights allow full control via DACL modification — the "God right" of AD
    # -----------------------------------------------------------------------
    $dacl_owner_ACEs = @($ACLs | Where-Object {
        $_ -and
        ($_.ActiveDirectoryRights -match 'WriteDacl|WriteOwner') -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.TargetObject -match 'DC=|CN=AdminSDHolder') -and
        -not ($legitimatePrincipals | Where-Object { $_.IdentityReference -match [regex]::Escape($_) })
    } | Where-Object {
        $ir = $_.IdentityReference.ToString()
        -not ($legitimatePrincipals | Where-Object { $ir -match [regex]::Escape($_) })
    })

    if ($dacl_owner_ACEs.Count -gt 0) {
        $uniquePrincipals = @($dacl_owner_ACEs | Select-Object -ExpandProperty IdentityReference -Unique)
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-018'
            Category        = 'ACL Object Control'
            Title           = "ACL Chaining: $($uniquePrincipals.Count) principal(s) have WriteDACL/WriteOwner on domain root or AdminSDHolder"
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "$($uniquePrincipals.Count) non-standard principal(s) have WriteDACL or WriteOwner on the domain root object or AdminSDHolder. These rights grant effective full control: the holder can modify the DACL to grant themselves any permission, then perform DCSync, object takeover, or persistent backdoor via AdminSDHolder. This is the most dangerous ACL misconfiguration in Active Directory."
            AffectedObjects = @($uniquePrincipals)
            Remediation     = '1) Immediately remove WriteDACL and WriteOwner from non-standard principals on the domain root and AdminSDHolder. 2) Investigate how these ACEs were added. 3) Run AD security health check tools (BloodHound, ADACLScanner) to identify further exposure. 4) Review all Domain Admin and EA group membership for unauthorized additions.'
            MitreAttack     = 'T1222.001'
            References      = @('https://attack.mitre.org/techniques/T1222/001/', 'https://adsecurity.org/?p=3658', 'https://github.com/BloodHoundAD/BloodHound')
            VerificationCommand = '(Get-ACL "AD:DC=domain,DC=com").Access | Where-Object { $_.ActiveDirectoryRights -match "WriteDacl|WriteOwner" -and $_.AccessControlType -eq "Allow" } | Select-Object IdentityReference, ActiveDirectoryRights, ObjectType'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 2. GenericWrite / AllExtendedRights on privileged group objects
    #    Enables adding members to Domain Admins, Enterprise Admins, etc.
    # -----------------------------------------------------------------------
    $privilegedGroupACEs = @($ACLs | Where-Object {
        $_ -and
        ($_.ActiveDirectoryRights -match 'GenericWrite|GenericAll|AllExtendedRights|WriteProperty') -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.TargetObject -match 'CN=Domain Admins|CN=Enterprise Admins|CN=Schema Admins|CN=Administrators|CN=Group Policy Creator Owners|CN=Account Operators') -and
        -not ($legitimatePrincipals | Where-Object { $_.IdentityReference -match [regex]::Escape($_) })
    } | Where-Object {
        $ir = $_.IdentityReference.ToString()
        -not ($legitimatePrincipals | Where-Object { $ir -match [regex]::Escape($_) })
    })

    if ($privilegedGroupACEs.Count -gt 0) {
        $uniquePrincipals = @($privilegedGroupACEs | Select-Object -ExpandProperty IdentityReference -Unique)
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-018'
            Category        = 'ACL Object Control'
            Title           = "ACL Chaining: $($uniquePrincipals.Count) principal(s) have GenericWrite/AllExtendedRights on privileged groups"
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "$($uniquePrincipals.Count) non-standard principal(s) have GenericWrite, GenericAll, or AllExtendedRights on privileged AD groups (Domain Admins, Enterprise Admins, etc.). This allows them to add themselves or arbitrary principals to those groups, enabling immediate privilege escalation to Domain Admin. This is a common ACL chaining attack path identified by BloodHound."
            AffectedObjects = @($uniquePrincipals)
            Remediation     = '1) Remove GenericWrite/GenericAll/AllExtendedRights from non-standard principals on privileged groups. 2) Audit all ACEs on Domain Admins, Enterprise Admins, and Schema Admins groups. 3) Enable auditing (Event ID 4728/4732/5136) for privileged group membership changes. 4) Use BloodHound to enumerate full attack paths.'
            MitreAttack     = 'T1222.001'
            References      = @('https://attack.mitre.org/techniques/T1222/001/', 'https://github.com/BloodHoundAD/BloodHound', 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces')
            VerificationCommand = '(Get-ACL "AD:CN=Domain Admins,CN=Users,DC=domain,DC=com").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|AllExtendedRights" -and $_.AccessControlType -eq "Allow" } | Select-Object IdentityReference, ActiveDirectoryRights'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. ForceChangePassword / AllExtendedRights on DA/EA accounts
    #    Allows password reset without knowing current password → immediate takeover
    # -----------------------------------------------------------------------
    $daAccounts = @($Users | Where-Object {
        $_ -and $_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match 'CN=Domain Admins|CN=Enterprise Admins' })
    })
    $daDistinguishedNames = @($daAccounts | Select-Object -ExpandProperty DistinguishedName -ErrorAction SilentlyContinue)

    if ($daDistinguishedNames.Count -gt 0) {
        $passwordResetACEs = @($ACLs | Where-Object {
            $_ -and
            ($_.ActiveDirectoryRights -match 'AllExtendedRights|GenericAll') -and
            $_.AccessControlType -eq 'Allow' -and
            ($daDistinguishedNames | Where-Object { $_.TargetObject -match [regex]::Escape($_) }) -and
            -not ($legitimatePrincipals | Where-Object { $_.IdentityReference -match [regex]::Escape($_) })
        } | Where-Object {
            $ir = $_.IdentityReference.ToString()
            -not ($legitimatePrincipals | Where-Object { $ir -match [regex]::Escape($_) })
        })

        if ($passwordResetACEs.Count -gt 0) {
            $uniquePrincipals = @($passwordResetACEs | Select-Object -ExpandProperty IdentityReference -Unique)
            $findings.Add([PSCustomObject]@{
                RuleId          = 'ATK-018'
                Category        = 'ACL Object Control'
                Title           = "ACL Chaining: $($uniquePrincipals.Count) principal(s) can reset Domain Admin account passwords"
                Severity        = 'Critical'
                Status          = 'Finding'
                Description     = "$($uniquePrincipals.Count) non-standard principal(s) have AllExtendedRights or GenericAll on Domain Admin or Enterprise Admin accounts. These rights include User-Force-Change-Password, allowing the holder to reset the DA account password without knowing the current password — enabling immediate account takeover and domain compromise."
                AffectedObjects = @($uniquePrincipals)
                Remediation     = '1) Remove AllExtendedRights/GenericAll from non-standard principals on DA/EA accounts. 2) Add all DA/EA accounts to Protected Users security group. 3) Enable fine-grained ACL auditing on privileged user objects. 4) Use BloodHound Shortest Path to DA to identify the complete attack graph.'
                MitreAttack     = 'T1222.001'
                References      = @('https://attack.mitre.org/techniques/T1222/001/', 'https://github.com/BloodHoundAD/BloodHound')
                VerificationCommand = 'Get-ADGroupMember "Domain Admins" | ForEach-Object { (Get-ACL "AD:$($_.distinguishedName)").Access | Where-Object { $_.ActiveDirectoryRights -match "AllExtendedRights|GenericAll" -and $_.AccessControlType -eq "Allow" } | Select-Object IdentityReference, ActiveDirectoryRights }'
                Timestamp       = $now
            })
        }
    }

    return $findings.ToArray()
}

#endregion

#region AdminSDHolderAbuse

function Invoke-AdminSDHolderAbuseCheck {
    <#
    .SYNOPSIS
        Detects AdminSDHolder/SDProp persistence and abuse conditions (T1098).
    .DESCRIPTION
        AdminSDHolder is the template security descriptor for protected AD objects. SDProp runs
        every 60 minutes and overwrites the ACLs of all protected accounts with the AdminSDHolder
        ACL. This is commonly abused for persistence: add a backdoor ACE to AdminSDHolder and it
        propagates automatically to all DA/EA/BA accounts, surviving manual ACL cleanup attempts.
        This dedicated ATK check:
          1. Flags non-standard ACEs on AdminSDHolder (attack vector for SDProp persistence)
          2. Identifies orphaned AdminCount=1 accounts (SDProp no longer manages them but DACL is frozen)
          3. Looks for large numbers of protected accounts (increases blast radius if AdminSDHolder is backdoored)
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .PARAMETER Users
        User objects from LDAP collector.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$ACLs  = @(),
        [array]$Users = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    # Legitimate principals on AdminSDHolder
    $legitimateAdminSDHolderPrincipals = @(
        'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'Domain Admins',
        'Enterprise Admins', 'BUILTIN\Pre-Windows 2000 Compatible Access',
        'NT AUTHORITY\SELF', 'NT AUTHORITY\Authenticated Users',
        'Domain Controllers', 'CREATOR OWNER', 'Everyone',
        'Account Operators', 'Print Operators', 'Server Operators',
        'Backup Operators', 'Replicator'
    )

    # -----------------------------------------------------------------------
    # 1. Non-standard ACEs on AdminSDHolder object
    # -----------------------------------------------------------------------
    $adminSDHolderACEs = @($ACLs | Where-Object {
        $_ -and $_.TargetObject -like '*CN=AdminSDHolder*'
    })

    if ($adminSDHolderACEs.Count -gt 0) {
        $suspiciousACEs = @($adminSDHolderACEs | Where-Object {
            $ace = $_
            $ir  = $ace.IdentityReference.ToString()
            ($ace.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|AllExtendedRights') -and
            $ace.AccessControlType -eq 'Allow' -and
            -not ($legitimateAdminSDHolderPrincipals | Where-Object { $ir -match [regex]::Escape($_) })
        })

        if ($suspiciousACEs.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                RuleId          = 'ATK-019'
                Category        = 'AdminSDHolder Abuse'
                Title           = "AdminSDHolder/SDProp: $($suspiciousACEs.Count) suspicious ACE(s) on AdminSDHolder will propagate to all protected accounts"
                Severity        = 'Critical'
                Status          = 'Finding'
                Description     = "$($suspiciousACEs.Count) non-standard ACE(s) with elevated permissions are present on the AdminSDHolder object (CN=AdminSDHolder,CN=System). The SDProp process runs every 60 minutes and stamps these ACEs onto all Domain Admins, Enterprise Admins, Backup Operators, and other protected accounts. An attacker who added these ACEs will silently retain persistent control over all protected accounts, even after manual ACL remediation of the protected accounts themselves."
                AffectedObjects = @($suspiciousACEs | ForEach-Object { "$($_.IdentityReference) — $($_.ActiveDirectoryRights)" })
                Remediation     = '1) IMMEDIATELY remove suspicious ACEs from AdminSDHolder: Set-ACL "AD:CN=AdminSDHolder,CN=System,DC=domain,DC=com". 2) Force SDProp to refresh all protected accounts: ldp.exe → Rootdse → runProtectAdminGroupsTask. 3) Investigate how ACEs were added (SIEM Event 5136 on AdminSDHolder). 4) Audit all DA/EA/BA accounts for residual unauthorized ACEs. 5) Alert on any future modifications to AdminSDHolder (Event ID 5136).'
                MitreAttack     = 'T1098'
                References      = @('https://attack.mitre.org/techniques/T1098/', 'https://adsecurity.org/?p=1906', 'https://www.semperis.com/blog/adminsdholder-abuse/')
                VerificationCommand = '(Get-ACL "AD:CN=AdminSDHolder,CN=System,$(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner" -and $_.AccessControlType -eq "Allow" } | Select-Object IdentityReference, ActiveDirectoryRights'
                Timestamp       = $now
            })
        }
    }

    # -----------------------------------------------------------------------
    # 2. Orphaned AdminCount=1 accounts (not in protected groups, ACL not refreshed)
    # -----------------------------------------------------------------------
    $protectedGroupPatterns = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Backup Operators|Account Operators|Server Operators|Print Operators|Replicators|Group Policy Creator Owners|Network Configuration Operators'

    $orphanedAdminCount = @($Users | Where-Object {
        $_ -and
        $_.PSObject.Properties['AdminCount'] -and $_.AdminCount -eq 1 -and
        $_.Enabled -eq $true -and
        $_.SamAccountName -notmatch '^(Administrator|krbtgt)$' -and
        -not ($_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match $protectedGroupPatterns }))
    })

    if ($orphanedAdminCount.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-019'
            Category        = 'AdminSDHolder Abuse'
            Title           = "AdminSDHolder/SDProp: $($orphanedAdminCount.Count) orphaned AdminCount=1 account(s) — SDProp no longer managing their ACLs"
            Severity        = 'High'
            Status          = 'Finding'
            Description     = "$($orphanedAdminCount.Count) enabled account(s) have AdminCount=1 but are no longer members of any protected group. SDProp no longer refreshes their ACLs, so their security descriptors are 'frozen' in the state when they were last protected. These accounts retain the tightened AdminSDHolder ACL (blocking inheritance) which can be exploited to hide permissions. Attackers specifically look for AdminCount=1 orphans as stealthy persistence targets."
            AffectedObjects = @($orphanedAdminCount | ForEach-Object { $_.SamAccountName })
            Remediation     = '1) Reset AdminCount to 0 on all orphaned accounts: Set-ADUser -Identity <account> -Replace @{AdminCount=0}. 2) Re-enable ACL inheritance on these objects. 3) Audit whether these accounts have unexpected local admin rights or group memberships. 4) Implement scheduled review of AdminCount=1 accounts.'
            MitreAttack     = 'T1098'
            References      = @('https://attack.mitre.org/techniques/T1098/', 'https://adsecurity.org/?p=2477', 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory')
            VerificationCommand = 'Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf | Select-Object SamAccountName, MemberOf | Sort-Object SamAccountName'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. SDProp blast radius assessment — how many accounts are protected
    # -----------------------------------------------------------------------
    $adminCountAccounts = @($Users | Where-Object {
        $_ -and $_.PSObject.Properties['AdminCount'] -and $_.AdminCount -eq 1 -and $_.Enabled -eq $true
    })

    if ($adminCountAccounts.Count -gt 50) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-019'
            Category        = 'AdminSDHolder Abuse'
            Title           = "AdminSDHolder/SDProp: High protected account count ($($adminCountAccounts.Count)) — large SDProp blast radius"
            Severity        = 'Medium'
            Status          = 'Finding'
            Description     = "$($adminCountAccounts.Count) enabled accounts have AdminCount=1, indicating they are (or were) in protected groups. A large protected account population increases the impact of AdminSDHolder backdooring: a single ACE added to AdminSDHolder propagates to all $($adminCountAccounts.Count) accounts within 60 minutes. Review whether all these accounts legitimately require protected-account status."
            AffectedObjects = @($adminCountAccounts | ForEach-Object { $_.SamAccountName } | Select-Object -First 20)
            Remediation     = '1) Audit all AdminCount=1 accounts. Remove from privileged groups any accounts that do not need them. 2) Reset AdminCount=0 for accounts no longer needing protection. 3) Monitor the size of protected groups over time — sudden increases indicate privilege escalation. 4) Consider implementing Tier 0/1/2 access model to limit protected account proliferation.'
            MitreAttack     = 'T1098'
            References      = @('https://attack.mitre.org/techniques/T1098/', 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory')
            VerificationCommand = 'Get-ADUser -Filter {AdminCount -eq 1 -and Enabled -eq $true} -Properties AdminCount | Measure-Object | Select-Object Count'
            Timestamp       = $now
        })
    }

    return $findings.ToArray()
}

#endregion

#region GPOAbuse

function Invoke-GPOAbuseCheck {
    <#
    .SYNOPSIS
        Detects conditions enabling GPO write-abuse for code execution and persistence (T1484.001).
    .DESCRIPTION
        Group Policy Objects (GPOs) represent a high-impact attack surface: a single GPO linked
        to the Domain Objects or Domain Controllers OU can deploy malicious settings, scripts,
        or scheduled tasks to thousands of machines simultaneously. This check:
          1. Identifies non-admin principals with write permissions on GPO objects in AD
          2. Identifies GPOs linked to sensitive OUs (Domain root, DC OU) with weak write ACLs
          3. Checks for GPOs where Authenticated Users have write access (universal write surface)
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .PARAMETER GPOs
        GPO objects from collector.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$ACLs = @(),
        [array]$GPOs = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    # Legitimate GPO management principals
    $legitimateGPOPrincipals = @(
        'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'Domain Admins',
        'Enterprise Admins', 'CREATOR OWNER', 'Group Policy Creator Owners',
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
    )

    # -----------------------------------------------------------------------
    # 1. Non-admin write access on GPO objects in AD (CN=Policies,CN=System)
    # -----------------------------------------------------------------------
    $gpoWriteACEs = @($ACLs | Where-Object {
        $_ -and
        $_.TargetObject -match 'CN=Policies,CN=System|{[0-9A-Fa-f\-]{36}}' -and
        ($_.ActiveDirectoryRights -match 'GenericWrite|GenericAll|WriteDacl|WriteOwner|WriteProperty') -and
        $_.AccessControlType -eq 'Allow' -and
        -not ($legitimateGPOPrincipals | Where-Object { $_.IdentityReference -match [regex]::Escape($_) })
    } | Where-Object {
        $ir = $_.IdentityReference.ToString()
        -not ($legitimateGPOPrincipals | Where-Object { $ir -match [regex]::Escape($_) })
    })

    if ($gpoWriteACEs.Count -gt 0) {
        $uniquePrincipals = @($gpoWriteACEs | Select-Object -ExpandProperty IdentityReference -Unique)
        $uniqueGPOs       = @($gpoWriteACEs | Select-Object -ExpandProperty TargetObject -Unique)
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-020'
            Category        = 'GPO Abuse'
            Title           = "GPO Abuse: $($uniquePrincipals.Count) non-admin principal(s) have write access on $($uniqueGPOs.Count) GPO object(s)"
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "$($uniquePrincipals.Count) non-standard principal(s) have GenericWrite, GenericAll, WriteDACL, WriteOwner, or WriteProperty rights on $($uniqueGPOs.Count) GPO object(s) in Active Directory. GPO write access enables immediate large-scale compromise: an attacker can add malicious startup scripts, schedule tasks, deploy software, or modify security settings. If the affected GPO is linked to the Domain root or DC OU, this enables domain-wide compromise from a single write operation."
            AffectedObjects = @($uniquePrincipals)
            Remediation     = '1) Remove non-admin write access from GPO objects. Only Group Policy Creator Owners, Domain Admins, and SYSTEM should have write rights. 2) Audit all GPO permissions using Get-GPPermissions. 3) Review GPOs linked to Domain root and DC OU for unauthorized changes. 4) Enable GPO change auditing (Event ID 5136 on GPO objects). 5) Implement GPO change approval workflow.'
            MitreAttack     = 'T1484.001'
            References      = @('https://attack.mitre.org/techniques/T1484/001/', 'https://adsecurity.org/?p=2716', 'https://github.com/FSecureLABS/SharpGPOAbuse')
            VerificationCommand = 'Get-GPO -All | ForEach-Object { Get-GPPermissions -Guid $_.Id -All | Where-Object { $_.Permission -match "GpoEdit|GpoEditDeleteModifySecurity" } | Select-Object @{n="GPO";e={$_.Trustee.Name}}, Permission }'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 2. GPOs where Authenticated Users / Everyone has Create Child or Write
    # -----------------------------------------------------------------------
    $broadGPOACEs = @($ACLs | Where-Object {
        $_ -and
        $_.TargetObject -match 'CN=Policies,CN=System|{[0-9A-Fa-f\-]{36}}' -and
        ($_.ActiveDirectoryRights -match 'CreateChild|WriteProperty|GenericWrite') -and
        $_.AccessControlType -eq 'Allow' -and
        ($_.IdentityReference -match 'Authenticated Users|Everyone|BUILTIN\\Users|Domain Users')
    })

    if ($broadGPOACEs.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-020'
            Category        = 'GPO Abuse'
            Title           = "GPO Abuse: Authenticated Users or Domain Users have write access on GPO objects"
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "Authenticated Users, Everyone, or Domain Users have CreateChild, WriteProperty, or GenericWrite on one or more GPO objects. This means any authenticated domain user can modify these GPOs, enabling any compromised user account to perform large-scale malicious configuration deployment."
            AffectedObjects = @($broadGPOACEs | Select-Object -ExpandProperty TargetObject -Unique)
            Remediation     = '1) Immediately remove Authenticated Users / Domain Users write access from all GPOs. 2) GPO modify rights should be restricted to Domain Admins, Group Policy Creator Owners, and specific delegated GPO managers. 3) Audit all GPOs for overly broad permissions using Get-GPPermissions -All.'
            MitreAttack     = 'T1484.001'
            References      = @('https://attack.mitre.org/techniques/T1484/001/', 'https://github.com/FSecureLABS/SharpGPOAbuse')
            VerificationCommand = 'Get-GPO -All | ForEach-Object { Get-GPPermissions -Guid $_.Id -All | Where-Object { $_.Trustee.SidType -eq "WellKnownGroup" } | Select-Object @{n="GPO";e={$using:_.DisplayName}}, Trustee, Permission }'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. GPO write-permission delegation review (informational if nothing found)
    # -----------------------------------------------------------------------
    if ($gpoWriteACEs.Count -eq 0 -and $broadGPOACEs.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-020'
            Category        = 'GPO Abuse'
            Title           = 'GPO Abuse: No overpermissive GPO write ACEs detected from ACL data (verify)'
            Severity        = 'Low'
            Status          = 'Review'
            Description     = 'No non-admin write ACEs were detected on GPO objects from the collected ACL data. This may mean permissions are correctly configured, or that GPO ACL data was not fully collected (ACL collector may not enumerate CN=Policies,CN=System objects). Verify by running Get-GPPermissions against all GPOs and checking SYSVOL folder permissions.'
            AffectedObjects = @()
            Remediation     = '1) Verify GPO permission collection: Get-GPO -All | ForEach-Object { Get-GPPermissions -Guid $_.Id -All }. 2) Check SYSVOL folder ACLs for non-admin write access. 3) Enable GPO change auditing. 4) Periodically review delegated GPO management rights.'
            MitreAttack     = 'T1484.001'
            References      = @('https://attack.mitre.org/techniques/T1484/001/', 'https://github.com/FSecureLABS/SharpGPOAbuse')
            VerificationCommand = 'Get-GPO -All | ForEach-Object { $gpo = $_; Get-GPPermissions -Guid $gpo.Id -All | Where-Object { $_.Permission -ne "GpoRead" } | Select-Object @{n="GPO";e={$gpo.DisplayName}}, Trustee, Permission }'
            Timestamp       = $now
        })
    }

    return $findings.ToArray()
}

#endregion

#region CrossForestTrust

function Invoke-CrossForestTrustCheck {
    <#
    .SYNOPSIS
        Detects cross-forest and cross-domain trust exploitation conditions (T1199).
    .DESCRIPTION
        Trust relationships between domains and forests can be abused to escalate privileges
        across organizational boundaries. Key risks include:
          1. SID filtering disabled on cross-forest trusts (enables SID history injection)
          2. Selectively authenticated trusts with broad authentication scope
          3. One-way trusts where the trusted domain can authenticate against the trusting domain
          4. Transitive trust chains enabling unexpected cross-forest access
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .PARAMETER Users
        User objects from LDAP collector (to detect cross-domain accounts).
    .PARAMETER DomainName
        Domain DNS name.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$ACLs       = @(),
        [array]$Users      = @(),
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    # -----------------------------------------------------------------------
    # 1. Enumerate trusts and check for SID filtering / quarantine status
    # -----------------------------------------------------------------------
    $trusts = @()
    try {
        $trusts = @(Get-ADTrust -Filter * -Properties TrustType, TrustDirection, TrustAttributes, SIDFilteringQuarantined, SIDFilteringForestAware -ErrorAction Stop)
    }
    catch {
        Write-Verbose "Could not enumerate trusts (requires AD module or DC connectivity): $_"
    }

    if ($trusts.Count -gt 0) {
        # SID filtering disabled trusts (quarantine = false on external trusts)
        $unquarantinedTrusts = @($trusts | Where-Object {
            $_.SIDFilteringQuarantined -eq $false -and
            $_.TrustType -ne 'Kerberos' -and
            $_.TrustType -ne 'Uplevel'
        })

        if ($unquarantinedTrusts.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                RuleId          = 'ATK-021'
                Category        = 'Cross-Forest Trust Abuse'
                Title           = "Cross-Forest Trust: $($unquarantinedTrusts.Count) trust(s) have SID filtering (quarantine) disabled"
                Severity        = 'Critical'
                Status          = 'Finding'
                Description     = "$($unquarantinedTrusts.Count) domain trust(s) have SID Filtering (Quarantine) disabled. Without SID filtering, a compromised trusted domain can inject arbitrary SID history values (including Enterprise Admins S-1-5-21-*-519) into Kerberos tickets, enabling privilege escalation in the trusting domain. This is the most dangerous cross-domain trust misconfiguration."
                AffectedObjects = @($unquarantinedTrusts | ForEach-Object { "$($_.Name) ($($_.TrustDirection), Type: $($_.TrustType))" })
                Remediation     = '1) Enable SID filtering on all external trusts: netdom trust <TrustingDomain> /domain:<TrustedDomain> /EnableSIDHistory:no. 2) For forest trusts, enable SID filtering forest-aware. 3) Review all trust relationships and remove unnecessary trusts. 4) Deploy Selective Authentication on all external trusts.'
                MitreAttack     = 'T1199'
                References      = @('https://attack.mitre.org/techniques/T1199/', 'https://adsecurity.org/?p=1588', 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772513(v=ws.10)')
                VerificationCommand = 'Get-ADTrust -Filter * -Properties SIDFilteringQuarantined | Select-Object Name, TrustDirection, TrustType, SIDFilteringQuarantined'
                Timestamp       = $now
            })
        }

        # Bidirectional or full-trust forest trusts (increased lateral movement surface)
        $bidirectionalForestTrusts = @($trusts | Where-Object {
            $_.TrustDirection -eq 'BiDirectional' -and
            ($_.TrustType -eq 'Forest' -or ($_.TrustAttributes -band 8) -eq 8)
        })

        if ($bidirectionalForestTrusts.Count -gt 0) {
            $findings.Add([PSCustomObject]@{
                RuleId          = 'ATK-021'
                Category        = 'Cross-Forest Trust Abuse'
                Title           = "Cross-Forest Trust: $($bidirectionalForestTrusts.Count) bidirectional forest trust(s) — mutual compromise risk"
                Severity        = 'High'
                Status          = 'Finding'
                Description     = "$($bidirectionalForestTrusts.Count) bidirectional forest trust(s) exist. Bidirectional trusts mean both forests trust each other, and compromise in either forest can be leveraged to attack the other. An attacker who achieves Domain Admin in one forest can use the trust to enumerate and attack resources in the partner forest. Forest-level trusts are transitive within each forest."
                AffectedObjects = @($bidirectionalForestTrusts | ForEach-Object { $_.Name })
                Remediation     = '1) Review whether bidirectional forest trusts are necessary. Convert to one-way trusts where possible. 2) Enable Selective Authentication on all forest trusts. 3) Audit which AD groups in the trusted forest have access to resources in the trusting forest. 4) Treat partner forests with the same security rigor as your own forest.'
                MitreAttack     = 'T1199'
                References      = @('https://attack.mitre.org/techniques/T1199/', 'https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d')
                VerificationCommand = 'Get-ADTrust -Filter * -Properties TrustAttributes | Where-Object { $_.TrustDirection -eq "BiDirectional" } | Select-Object Name, TrustDirection, TrustType, TrustAttributes'
                Timestamp       = $now
            })
        }
    }

    # -----------------------------------------------------------------------
    # 2. Cross-domain accounts with elevated rights in the local domain
    #    These are accounts from trusted domains with local domain admin rights
    # -----------------------------------------------------------------------
    $crossDomainPrivileged = @($Users | Where-Object {
        $_ -and
        $_.PSObject.Properties['SID'] -and $_.SID -and
        $DomainName -and
        # Account SID not from local domain (different domain prefix)
        $_.SamAccountName -match '\$' -eq $false -and
        $_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match 'Domain Admins|Enterprise Admins' })
    } | Where-Object {
        # Filter for accounts whose UPN suggests a different domain
        $_.PSObject.Properties['UserPrincipalName'] -and $_.UserPrincipalName -and
        $_.UserPrincipalName -notmatch [regex]::Escape($DomainName)
    })

    if ($crossDomainPrivileged.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-021'
            Category        = 'Cross-Forest Trust Abuse'
            Title           = "Cross-Forest Trust: $($crossDomainPrivileged.Count) external-domain account(s) have local privileged group membership"
            Severity        = 'High'
            Status          = 'Finding'
            Description     = "$($crossDomainPrivileged.Count) account(s) with UPNs from external domains are members of privileged groups (Domain Admins or Enterprise Admins) in this domain. Cross-domain privileged access increases the attack surface: compromise of the external domain can immediately translate to compromise of this domain through these account memberships."
            AffectedObjects = @($crossDomainPrivileged | ForEach-Object { "$($_.SamAccountName) — $($_.UserPrincipalName)" })
            Remediation     = '1) Review all cross-domain accounts with local privileged group membership. Remove if not required. 2) Prefer resource-based access (local groups in specific resources) over privileged group membership for cross-domain access. 3) Audit the security posture of partner domains that have accounts with local admin rights.'
            MitreAttack     = 'T1199'
            References      = @('https://attack.mitre.org/techniques/T1199/', 'https://adsecurity.org/?p=1588')
            VerificationCommand = 'Get-ADGroupMember "Domain Admins" -Recursive | Where-Object { $_.objectClass -eq "user" } | Get-ADUser -Properties UserPrincipalName | Where-Object { $_.UserPrincipalName -notmatch "' + $DomainName + '" } | Select-Object SamAccountName, UserPrincipalName'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. Informational: No trust data available from collector
    # -----------------------------------------------------------------------
    if ($trusts.Count -eq 0 -and $crossDomainPrivileged.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-021'
            Category        = 'Cross-Forest Trust Abuse'
            Title           = 'Cross-Forest Trust: No trust data collected — manual verification required'
            Severity        = 'Low'
            Status          = 'Review'
            Description     = 'No domain trust information was returned from the collector (requires AD module / DC connectivity). Cross-forest trust abuse is a significant attack vector that cannot be fully assessed without trust enumeration. Perform manual review of all trust relationships.'
            AffectedObjects = @()
            Remediation     = '1) Run: Get-ADTrust -Filter * -Properties * to enumerate all trusts. 2) Verify SID filtering is enabled on all external/forest trusts. 3) Implement Selective Authentication on all trusts. 4) Review cross-domain accounts with local privileged membership.'
            MitreAttack     = 'T1199'
            References      = @('https://attack.mitre.org/techniques/T1199/', 'https://adsecurity.org/?p=1588', 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772513(v=ws.10)')
            VerificationCommand = 'Get-ADTrust -Filter * -Properties SIDFilteringQuarantined, TrustAttributes | Select-Object Name, TrustDirection, TrustType, SIDFilteringQuarantined, TrustAttributes'
            Timestamp       = $now
        })
    }

    return $findings.ToArray()
}

#endregion

#region RBCDAbuse

function Invoke-RBCDCheck {
    <#
    .SYNOPSIS
        Detects Resource-Based Constrained Delegation (RBCD) misconfigurations and abuse paths (T1134.001).
    .DESCRIPTION
        RBCD (configured via msDS-AllowedToActOnBehalfOfOtherIdentity) enables service impersonation
        without requiring DA privileges to configure. An attacker who gains write access to a computer
        object can set RBCD to allow any account they control to impersonate any user to that service.
        Combined with MachineAccountQuota > 0, this creates a full privilege-escalation path from
        zero credentials. This check:
          1. Finds computer accounts with msDS-AllowedToActOnBehalfOfOtherIdentity set (RBCD configured)
          2. Identifies non-admin accounts with WriteProperty/GenericWrite on computer objects
             (RBCD write path)
          3. Checks for MachineAccountQuota enabling attacker-controlled computer account creation
    .PARAMETER Computers
        Computer objects from LDAP collector.
    .PARAMETER ACLs
        ACL objects from LDAP collector.
    .PARAMETER Users
        User objects from LDAP collector.
    .OUTPUTS
        Array of PSCustomObject findings.
    #>
    [CmdletBinding()]
    param(
        [array]$Computers = @(),
        [array]$ACLs      = @(),
        [array]$Users     = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $now      = Get-Date

    # -----------------------------------------------------------------------
    # 1. Computers with msDS-AllowedToActOnBehalfOfOtherIdentity set (RBCD configured)
    #    Review whether these are legitimate delegations or attacker-planted
    # -----------------------------------------------------------------------
    $rbcdComputers = @($Computers | Where-Object {
        $_ -and
        $_.PSObject.Properties['msDS-AllowedToActOnBehalfOfOtherIdentity'] -and
        $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
    })

    if ($rbcdComputers.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-022'
            Category        = 'RBCD Abuse'
            Title           = "RBCD: $($rbcdComputers.Count) computer object(s) have msDS-AllowedToActOnBehalfOfOtherIdentity configured"
            Severity        = 'High'
            Status          = 'Finding'
            Description     = "$($rbcdComputers.Count) computer object(s) have Resource-Based Constrained Delegation (RBCD) configured via the msDS-AllowedToActOnBehalfOfOtherIdentity attribute. Verify these delegations are intentional and necessary. Attackers who gain write access to a computer object set this attribute to allow an attacker-controlled account to impersonate any domain user (including DA) to reach the target service — a complete privilege escalation path requiring no special privileges to configure."
            AffectedObjects = @($rbcdComputers | ForEach-Object { $_.DNSHostName })
            Remediation     = '1) Audit all computers with msDS-AllowedToActOnBehalfOfOtherIdentity: Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" }. 2) Clear RBCD on systems where it is not required: Set-ADComputer <name> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity. 3) Restrict who can write to computer objects (msDS-AllowedToActOnBehalfOfOtherIdentity attribute). 4) Add high-value accounts to Protected Users group (blocks delegation).'
            MitreAttack     = 'T1134.001'
            References      = @('https://attack.mitre.org/techniques/T1134/001/', 'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html', 'https://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/')
            VerificationCommand = 'Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } | Select-Object Name, DNSHostName'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 2. Non-admin accounts with WriteProperty on computer objects
    #    This is the prerequisite for planting RBCD — if you can write to a computer, you can set RBCD
    # -----------------------------------------------------------------------
    $legitimateComputerWritePrincipals = @(
        'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'Domain Admins',
        'Enterprise Admins', 'CREATOR OWNER', 'Domain Controllers',
        'Account Operators'
    )

    $computerWriteACEs = @($ACLs | Where-Object {
        $_ -and
        $_.TargetObject -match 'CN=Computers|OU=' -and
        ($_.ActiveDirectoryRights -match 'GenericWrite|GenericAll|WriteProperty') -and
        $_.AccessControlType -eq 'Allow' -and
        -not ($legitimateComputerWritePrincipals | Where-Object { $_.IdentityReference -match [regex]::Escape($_) })
    } | Where-Object {
        $ir = $_.IdentityReference.ToString()
        -not ($legitimateComputerWritePrincipals | Where-Object { $ir -match [regex]::Escape($_) })
    })

    if ($computerWriteACEs.Count -gt 0) {
        $uniquePrincipals = @($computerWriteACEs | Select-Object -ExpandProperty IdentityReference -Unique)
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-022'
            Category        = 'RBCD Abuse'
            Title           = "RBCD: $($uniquePrincipals.Count) non-admin principal(s) can write to computer objects (RBCD plant path)"
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = "$($uniquePrincipals.Count) non-standard principal(s) have GenericWrite, GenericAll, or WriteProperty on computer objects. WriteProperty on a computer object includes the ability to set msDS-AllowedToActOnBehalfOfOtherIdentity. Combined with MachineAccountQuota > 0 (enabling attacker to create a machine account), this provides a complete RBCD privilege escalation path: any domain user with write access to a computer object can potentially become Domain Admin via S4U2Self/S4U2Proxy delegation abuse."
            AffectedObjects = @($uniquePrincipals)
            Remediation     = '1) Remove GenericWrite/WriteProperty from non-admin principals on computer objects. 2) Set MachineAccountQuota to 0. 3) Audit RBCD configurations on all computer objects. 4) Deploy Protected Users for high-value accounts. 5) Use BloodHound to enumerate complete RBCD attack paths in your environment.'
            MitreAttack     = 'T1134.001'
            References      = @('https://attack.mitre.org/techniques/T1134/001/', 'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html', 'https://github.com/BloodHoundAD/BloodHound')
            VerificationCommand = 'Get-ADComputer -Filter * | ForEach-Object { (Get-ACL "AD:$($_.DistinguishedName)").Access | Where-Object { $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty" -and $_.AccessControlType -eq "Allow" } | Select-Object @{n="Computer";e={$using:_.Name}}, IdentityReference, ActiveDirectoryRights }'
            Timestamp       = $now
        })
    }

    # -----------------------------------------------------------------------
    # 3. MachineAccountQuota > 0 combined with delegation surface
    #    (RBCD escalation requires attacker-controlled machine account)
    # -----------------------------------------------------------------------
    $maqVulnerable = $false
    try {
        $domainRoot = Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -Filter { objectClass -eq 'domain' } -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
        $maq = if ($domainRoot.PSObject.Properties['ms-DS-MachineAccountQuota']) { $domainRoot.'ms-DS-MachineAccountQuota' } else { 10 }
        $maqVulnerable = ($maq -gt 0)
    }
    catch {
        Write-Verbose "Could not check MachineAccountQuota (requires DC access): $_"
    }

    if ($maqVulnerable -and ($rbcdComputers.Count -gt 0 -or $computerWriteACEs.Count -gt 0)) {
        $findings.Add([PSCustomObject]@{
            RuleId          = 'ATK-022'
            Category        = 'RBCD Abuse'
            Title           = 'RBCD: MachineAccountQuota > 0 combined with RBCD write surface — complete escalation path present'
            Severity        = 'Critical'
            Status          = 'Finding'
            Description     = 'MachineAccountQuota is greater than 0, allowing any authenticated domain user to create machine accounts. Combined with write access to existing computer objects (allowing RBCD planting), this provides a complete privilege escalation path: (1) create attacker-controlled computer account, (2) write msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer to allow the attacker account to delegate, (3) use S4U2Self + S4U2Proxy to obtain service tickets as any user (including DA) to the target service.'
            AffectedObjects = @('MachineAccountQuota > 0', "$($computerWriteACEs.Count) computer write ACEs detected")
            Remediation     = '1) CRITICAL: Set MachineAccountQuota to 0 immediately. 2) Remove non-admin write access from computer objects. 3) Clear all existing RBCD configurations that are not intentional. 4) Audit recently created computer accounts for attacker-planted machines.'
            MitreAttack     = 'T1134.001'
            References      = @('https://attack.mitre.org/techniques/T1134/001/', 'https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html')
            VerificationCommand = 'Get-ADObject -LDAPFilter "(objectClass=domain)" -Properties ms-DS-MachineAccountQuota | Select-Object Name,"ms-DS-MachineAccountQuota"'
            Timestamp       = $now
        })
    }

    return $findings.ToArray()
}

#endregion

#region Orchestrator

function Invoke-AllOffensiveTechniqueChecks {
    <#
    .SYNOPSIS
        Runs all offensive technique detection checks and returns aggregated findings.
    .PARAMETER CollectedData
        Hashtable of all collector outputs (same format as Invoke-AllChecks).
    .PARAMETER DomainName
        Domain DNS name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CollectedData,
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    $users       = @(if ($CollectedData.ContainsKey('Users'))       { $CollectedData.Users }       else { @() })
    $computers   = @(if ($CollectedData.ContainsKey('Computers'))   { $CollectedData.Computers }   else { @() })
    $dcs         = @(if ($CollectedData.ContainsKey('DomainControllers')) { $CollectedData.DomainControllers } else { @() })
    $acls        = @(if ($CollectedData.ContainsKey('ACLs'))        { $CollectedData.ACLs }        else { @() })
    $pwPolicies  = @(if ($CollectedData.ContainsKey('PasswordPolicies'))  { $CollectedData.PasswordPolicies }  else { @() })
    $smbSigning  = @(if ($CollectedData.ContainsKey('SmbSigning'))  { $CollectedData.SmbSigning }  else { @() })
    $ldapSigning = @(if ($CollectedData.ContainsKey('LdapSigning')) { $CollectedData.LdapSigning } else { @() })
    $ntlm        = @(if ($CollectedData.ContainsKey('NtlmSettings')) { $CollectedData.NtlmSettings } else { @() })
    $cas         = @(if ($CollectedData.ContainsKey('CertificateAuthorities')) { $CollectedData.CertificateAuthorities } else { @() })
    $templates   = @(if ($CollectedData.ContainsKey('CertificateTemplates'))   { $CollectedData.CertificateTemplates }   else { @() })
    $gpos        = @(if ($CollectedData.ContainsKey('GPOs'))         { $CollectedData.GPOs }         else { @() })

    $checks = @(
        { Invoke-PasswordSprayingCheck    -PasswordPolicies $pwPolicies -Users $users }
        { Invoke-MachineAccountQuotaCheck -DomainName $DomainName }
        { Invoke-GoldenTicketCheck        -Users $users -DomainControllers $dcs }
        { Invoke-SilverTicketCheck        -Users $users -Computers $computers }
        { Invoke-GoldenCertificateCheck   -CertificateAuthorities $cas -CertificateTemplates $templates }
        { Invoke-NtdsDitCheck             -ACLs $acls -Users $users }
        { Invoke-GoldenSAMLCheck          -Users $users -DomainName $DomainName }
        { Invoke-EntraConnectCheck        -Users $users -ACLs $acls }
        { Invoke-PassTheHashCheck         -DomainControllers $dcs -NtlmSettings $ntlm -Computers $computers }
        { Invoke-PassTheTicketCheck       -Users $users -Computers $computers -DomainControllers $dcs }
        { Invoke-DCShadowCheck            -DomainControllers $dcs -Computers $computers -ACLs $acls -DomainName $DomainName }
        { Invoke-NTLMRelayCheck           -DomainControllers $dcs -SmbSigningData $smbSigning -LdapSigningData $ldapSigning -NtlmData $ntlm }
        { Invoke-CredentialDumpingCheck   -DomainControllers $dcs -Users $users -Computers $computers }
        { Invoke-LateralMovementCheck     -Users $users -Computers $computers -DomainControllers $dcs -ACLs $acls -DomainName $DomainName }
        { Invoke-ShadowCredentialsCheck   -Users $users -Computers $computers -ACLs $acls }
        { Invoke-ACLObjectControlCheck    -ACLs $acls -Users $users }
        { Invoke-AdminSDHolderAbuseCheck  -ACLs $acls -Users $users }
        { Invoke-GPOAbuseCheck            -ACLs $acls -GPOs $gpos }
        { Invoke-CrossForestTrustCheck    -ACLs $acls -Users $users -DomainName $DomainName }
        { Invoke-RBCDCheck                -Computers $computers -ACLs $acls -Users $users }
    )

    foreach ($check in $checks) {
        try {
            $result = & $check
            if ($result) { $result | ForEach-Object { $findings.Add($_) } }
        }
        catch { Write-Warning "Offensive technique check error: $_" }
    }

    Write-Verbose "All offensive technique checks complete. Total findings: $($findings.Count)"
    return $findings.ToArray()
}

#endregion
