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

.NOTES
    Author  : AD-Wall Project
    Version : 1.0.0
    All operations are READ-ONLY.
#>

Set-StrictMode -Version Latest

#region Helper

function New-ATKFinding {
    param(
        [string]$RuleId,
        [string]$Title,
        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string]$Severity,
        [string]$Description,
        [object[]]$AffectedObjects,
        [string]$Remediation,
        [string]$MitreAttack = '',
        [hashtable]$ExtraData = @{}
    )
    return [PSCustomObject]@{
        RuleId          = $RuleId
        Title           = $Title
        Severity        = $Severity
        Category        = 'Attack Techniques'
        Description     = $Description
        AffectedObjects = @($AffectedObjects | Where-Object { $_ })
        AffectedCount   = @($AffectedObjects | Where-Object { $_ }).Count
        Remediation     = $Remediation
        MitreAttack     = $MitreAttack
        ExtraData       = $ExtraData
        DetectedAt      = (Get-Date -Format 'o')
    }
}

#endregion

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

    $checks = @(
        { Invoke-PasswordSprayingCheck   -PasswordPolicies $pwPolicies -Users $users }
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
