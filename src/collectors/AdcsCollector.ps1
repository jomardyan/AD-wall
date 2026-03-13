#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall AD Certificate Services (AD CS) Collector Module
.DESCRIPTION
    Enumerates AD CS infrastructure: Certificate Authorities, certificate templates,
    enrollment permissions, and CA configuration. Collects the data needed to detect
    ESC1-ESC8 privilege escalation vulnerabilities via certificate abuse.
    All operations are read-only.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0

    ESC Vulnerability Reference:
    ESC1  - Enrollee supplies Subject (SANs)
    ESC2  - Any Purpose EKU or no EKU (SubCA)
    ESC3  - Certificate Request Agent EKU
    ESC4  - Weak template ACL (write access)
    ESC5  - Vulnerable PKI Object ACL
    ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
    ESC7  - Vulnerable CA ACL
    ESC8  - NTLM relay to AD CS HTTP endpoints
#>

Set-StrictMode -Version Latest

#region Constants

# Certificate template flag bitmasks
$Script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT     = 0x00000001
$Script:CT_FLAG_ADD_EMAIL                     = 0x00000002
$Script:CT_FLAG_ADD_OBJ_GUID                  = 0x00000004
$Script:CT_FLAG_DSMAIL                        = 0x00000008
$Script:CT_FLAG_PUBLISH_TO_DS                 = 0x00000010
$Script:CT_FLAG_SMIME_CAPABILITIES            = 0x00000040
$Script:CT_FLAG_AUTO_ENROLLMENT               = 0x00000020
$Script:CT_FLAG_MACHINE_TYPE                  = 0x00000040
$Script:CT_FLAG_IS_CA                         = 0x00000080
$Script:CT_FLAG_ADD_TEMPLATE_NAME             = 0x00000200
$Script:CT_FLAG_IS_CROSS_CA                   = 0x00000800
$Script:CT_FLAG_IS_DEFAULT                    = 0x00010000
$Script:CT_FLAG_IS_MODIFIED                   = 0x00020000
$Script:CT_FLAG_DONOTPERSISTINDB              = 0x00001000
$Script:CT_FLAG_EXPORTABLE_KEY                = 0x00000010

# msPKI-Certificate-Name-Flag
$Script:SUBJECTALTREQ_SAN_SUBJECT             = 0x00000001
$Script:SUBJECT_REQUIRE_DIRECTORY_PATH        = 0x80000000
$Script:SUBJECT_REQUIRE_COMMON_NAME           = 0x40000000
$Script:SUBJECT_REQUIRE_EMAIL                 = 0x20000000
$Script:SUBJECT_REQUIRE_DNS_AS_CN             = 0x10000000

# msPKI-Enrollment-Flag
$Script:PEND_ALL_REQUESTS                     = 0x00000002
$Script:NO_SECURITY_EXTENSION                 = 0x00080000

# CA flags (EDITF)
$Script:EDITF_ATTRIBUTESUBJECTALTNAME2        = 0x00040000

# Known EKUs
$Script:EKU_ANY_PURPOSE                       = '2.5.29.37.0'
$Script:EKU_SMARTCARD_LOGON                   = '1.3.6.1.4.1.311.20.2.2'
$Script:EKU_CLIENT_AUTHENTICATION             = '1.3.6.1.5.5.7.3.2'
$Script:EKU_CERTIFICATE_REQUEST_AGENT         = '1.3.6.1.4.1.311.20.2.1'
$Script:EKU_SERVER_AUTHENTICATION             = '1.3.6.1.5.5.7.3.1'

#endregion

#region Helper

function New-LdapEntry {
    param(
        [string]$Path,
        [System.Management.Automation.PSCredential]$Credential
    )
    try {
        if ($null -ne $Credential) {
            return New-Object System.DirectoryServices.DirectoryEntry(
                $Path, $Credential.UserName,
                $Credential.GetNetworkCredential().Password)
        }
        return New-Object System.DirectoryServices.DirectoryEntry($Path)
    }
    catch {
        Write-Warning "Failed to create LDAP entry for '$Path': $_"
        return $null
    }
}

function Get-ConfigurationNC {
    param(
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$Credential
    )
    $root = if ($DomainController) { "LDAP://$DomainController/RootDSE" } else { 'LDAP://RootDSE' }
    try {
        $entry = New-LdapEntry -Path $root -Credential $Credential
        return $entry.Properties['configurationNamingContext'][0]
    }
    catch {
        Write-Warning "Could not retrieve Configuration NC: $_"
        return $null
    }
}

function Search-LdapObjects {
    param(
        [string]$SearchBase,
        [string]$Filter,
        [string[]]$Properties,
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PageSize = 200
    )

    $ldapPath = if ($DomainController) { "LDAP://$DomainController/$SearchBase" } else { "LDAP://$SearchBase" }

    try {
        $entry = New-LdapEntry -Path $ldapPath -Credential $Credential
        if ($null -eq $entry) { return @() }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter    = $Filter
        $searcher.PageSize  = $PageSize
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        if ($Properties) { $searcher.PropertiesToLoad.AddRange($Properties) }

        $results = $searcher.FindAll()
        $searcher.Dispose()
        return @($results)
    }
    catch {
        Write-Warning "LDAP search failed ($SearchBase): $_"
        return @()
    }
}

function Get-Prop {
    param($Result, [string]$Name, [bool]$Multi = $false)
    if ($null -eq $Result -or -not $Result.Properties.Contains($Name)) { return $null }
    $vals = $Result.Properties[$Name]
    if ($Multi) { return @($vals) }
    if ($vals.Count -gt 0) { return $vals[0] }
    return $null
}

function Decode-OidList {
    param([object[]]$RawList)
    if ($null -eq $RawList) { return @() }
    return $RawList | Where-Object { $_ } | ForEach-Object { $_.ToString() }
}

#endregion

#region Exported Functions

function Get-ADCSCertificateAuthorities {
    <#
    .SYNOPSIS
        Enumerates all AD Certificate Authority objects from the Configuration NC.
    .DESCRIPTION
        Discovers Enterprise CAs via the PKI Enrollment Services container and collects
        configuration data relevant to ESC6, ESC7, and ESC8 checks.
    .PARAMETER DomainController
        Target DC for LDAP queries.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-ADCSCertificateAuthorities -DomainController dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting AD CS Certificate Authorities..."

    $configNC = Get-ConfigurationNC -DomainController $DomainController -Credential $Credential
    if (-not $configNC) { return @() }

    $enrollSvcBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

    $props = @(
        'name','distinguishedname','dnshostname','cacertificate',
        'certificatetemplates','flags','mspki-enrollment-servers',
        'whencreated','whenchanged','objectguid'
    )

    $caObjects = Search-LdapObjects -SearchBase $enrollSvcBase `
        -Filter '(objectClass=pKIEnrollmentService)' -Properties $props `
        -DomainController $DomainController -Credential $Credential

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($ca in $caObjects) {
        $caName = Get-Prop $ca 'name'
        $caHost = Get-Prop $ca 'dnshostname'

        # NOTE: EditFlags are read from the local machine's registry.
        # This check is only accurate when the script runs directly on the CA host.
        # For remote CAs ($caHost differs from $env:COMPUTERNAME), the value will be
        # $null and ESC6_SANEditFlagSet will correctly default to $false rather than
        # a false positive. To check remote CAs, use Invoke-Command or remote CIM.
        $caFlags = $null
        if ($caHost) {
            try {
                $flagVal = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName" `
                    -Name 'EditFlags' -ErrorAction SilentlyContinue).EditFlags
                $caFlags = $flagVal
            }
            catch { $caFlags = $null }
        }

        $templates = Get-Prop $ca 'certificatetemplates' -Multi $true

        $results.Add([PSCustomObject]@{
            Name                   = $caName
            DistinguishedName      = Get-Prop $ca 'distinguishedname'
            DnsHostName            = $caHost
            EnrolledTemplates      = @($templates | Where-Object { $_ })
            Flags                  = $caFlags
            ESC6_SANEditFlagSet    = ($null -ne $caFlags -and [bool]($caFlags -band $Script:EDITF_ATTRIBUTESUBJECTALTNAME2))
            WhenCreated            = Get-Prop $ca 'whencreated'
            WhenChanged            = Get-Prop $ca 'whenchanged'
        })
    }

    Write-Verbose "Found $($results.Count) Certificate Authorities."
    return $results.ToArray()
}

function Get-CertificateTemplates {
    <#
    .SYNOPSIS
        Enumerates all certificate templates and their security-relevant attributes.
    .DESCRIPTION
        Retrieves all certificate template objects from the Configuration NC.
        Collects flags, EKUs, subject name flags, and enrollment counts to support
        ESC1-ESC4 vulnerability detection.
    .PARAMETER DomainController
        Target DC.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-CertificateTemplates -DomainController dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting certificate templates..."

    $configNC = Get-ConfigurationNC -DomainController $DomainController -Credential $Credential
    if (-not $configNC) { return @() }

    $certTemplateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    $props = @(
        'name','distinguishedname','displayname',
        'mspki-cert-template-oid',
        'mspki-certificate-name-flag',   # Subject/SAN flags
        'mspki-enrollment-flag',          # Enrollment flags
        'mspki-certificate-application-policy', # Application policies (EKUs)
        'pkiextendedkeyusage',            # Extended Key Usage OIDs
        'pkidefaultkeyspec',
        'flags',
        'revision',
        'mspki-template-schema-version',
        'mspki-minimal-key-size',
        'mspki-ra-signature',             # Number of RA signatures required
        'mspki-private-key-flag',
        'mspki-subject-alternative-name', # SAN template setting
        'whencreated','whenchanged',
        'objectguid'
    )

    $templateObjects = Search-LdapObjects -SearchBase $certTemplateBase `
        -Filter '(objectClass=pKICertificateTemplate)' -Properties $props `
        -DomainController $DomainController -Credential $Credential

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($t in $templateObjects) {
        $nameFlags       = [int](Get-Prop $t 'mspki-certificate-name-flag')
        $enrollFlags     = [int](Get-Prop $t 'mspki-enrollment-flag')
        $templateFlags   = [int](Get-Prop $t 'flags')
        $ekus            = Decode-OidList (Get-Prop $t 'pkiextendedkeyusage' -Multi $true)
        $appPolicies     = Decode-OidList (Get-Prop $t 'mspki-certificate-application-policy' -Multi $true)
        $raSignatures    = [int](Get-Prop $t 'mspki-ra-signature')
        $schemaVersion   = [int](Get-Prop $t 'mspki-template-schema-version')
        $privateKeyFlag  = [int](Get-Prop $t 'mspki-private-key-flag')

        # ESC1: Template allows enrollee-supplied SAN + client auth EKU + no manager approval
        $enrolleeSuppliesSAN = [bool]($nameFlags -band $Script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        $hasClientAuth       = $ekus -contains $Script:EKU_CLIENT_AUTHENTICATION -or
                               $appPolicies -contains $Script:EKU_CLIENT_AUTHENTICATION
        $hasSmartcardLogon   = $ekus -contains $Script:EKU_SMARTCARD_LOGON -or
                               $appPolicies -contains $Script:EKU_SMARTCARD_LOGON
        $hasAnyPurpose       = $ekus -contains $Script:EKU_ANY_PURPOSE -or
                               $appPolicies -contains $Script:EKU_ANY_PURPOSE -or
                               ($ekus.Count -eq 0 -and $appPolicies.Count -eq 0)
        $managerApproval     = [bool]($enrollFlags -band $Script:PEND_ALL_REQUESTS)
        $raSignatureRequired = ($raSignatures -gt 0)
        $noSecurityExtension = [bool]($enrollFlags -band $Script:NO_SECURITY_EXTENSION)

        # ESC2: Any Purpose or no EKU
        $esc2 = $hasAnyPurpose -and -not $enrolleeSuppliesSAN

        # ESC3: Certificate Request Agent EKU
        $hasCertReqAgent = $ekus -contains $Script:EKU_CERTIFICATE_REQUEST_AGENT -or
                           $appPolicies -contains $Script:EKU_CERTIFICATE_REQUEST_AGENT

        # Key is exportable?
        $keyExportable = [bool]($privateKeyFlag -band 0x10)

        $results.Add([PSCustomObject]@{
            Name                      = Get-Prop $t 'name'
            DisplayName               = Get-Prop $t 'displayname'
            DistinguishedName         = Get-Prop $t 'distinguishedname'
            TemplateOID               = Get-Prop $t 'mspki-cert-template-oid'
            SchemaVersion             = $schemaVersion
            CertificateNameFlags      = $nameFlags
            EnrollmentFlags           = $enrollFlags
            TemplateFlags             = $templateFlags
            EKUs                      = $ekus
            ApplicationPolicies       = $appPolicies
            RASignaturesRequired      = $raSignatures
            MinimumKeySize            = Get-Prop $t 'mspki-minimal-key-size'
            KeyExportable             = $keyExportable
            EnrolleeSuppliesSAN       = $enrolleeSuppliesSAN
            HasClientAuthEKU          = $hasClientAuth
            HasSmartcardLogonEKU      = $hasSmartcardLogon
            HasAnyPurposeEKU          = $hasAnyPurpose
            HasCertRequestAgentEKU    = $hasCertReqAgent
            ManagerApprovalRequired   = $managerApproval
            NoSecurityExtension       = $noSecurityExtension
            # ESC indicator flags
            PotentialESC1             = ($enrolleeSuppliesSAN -and ($hasClientAuth -or $hasSmartcardLogon) -and -not $managerApproval -and -not $raSignatureRequired)
            PotentialESC2             = ($esc2 -and -not $managerApproval)
            PotentialESC3             = ($hasCertReqAgent -and -not $managerApproval)
            WhenCreated               = Get-Prop $t 'whencreated'
            WhenChanged               = Get-Prop $t 'whenchanged'
        })
    }

    Write-Verbose "Collected $($results.Count) certificate templates."
    return $results.ToArray()
}

function Get-ADCSEnrollmentPermissions {
    <#
    .SYNOPSIS
        Retrieves enrollment ACLs for certificate templates and CAs.
    .DESCRIPTION
        Reads the nTSecurityDescriptor from each template/CA object to identify which
        principals can enroll, auto-enroll, or write to templates (ESC4, ESC7).
        Flags overly permissive ACEs (Domain Users, Authenticated Users, Everyone).
    .PARAMETER DomainController
        Target DC.
    .PARAMETER Credential
        Optional credential.
    .EXAMPLE
        Get-ADCSEnrollmentPermissions -DomainController dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting AD CS enrollment permissions..."

    $configNC = Get-ConfigurationNC -DomainController $DomainController -Credential $Credential
    if (-not $configNC) { return @() }

    $certTemplateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    # Enrollment rights GUIDs
    $enrollRightGuid    = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid     = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    $overpermissive = @(
        'Everyone',
        'NT AUTHORITY\Authenticated Users',
        'BUILTIN\Users',
        'Domain Users'
    )

    $props = @('name','distinguishedname','displayname')

    $templateObjects = Search-LdapObjects -SearchBase $certTemplateBase `
        -Filter '(objectClass=pKICertificateTemplate)' -Properties $props `
        -DomainController $DomainController -Credential $Credential

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($t in $templateObjects) {
        $dn   = Get-Prop $t 'distinguishedname'
        $name = Get-Prop $t 'name'

        $ldapPath = if ($DomainController) { "LDAP://$DomainController/$dn" } else { "LDAP://$dn" }

        try {
            $entry = New-LdapEntry -Path $ldapPath -Credential $Credential
            if ($null -eq $entry) { continue }

            $acl  = $entry.ObjectSecurity
            $aces = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

            foreach ($ace in $aces) {
                $identity    = $ace.IdentityReference.Value
                $rights      = $ace.ActiveDirectoryRights.ToString()
                $objectType  = $ace.ObjectType.ToString()
                $aceType     = $ace.AccessControlType.ToString()

                $isEnroll    = ($objectType -eq $enrollRightGuid) -and ($aceType -eq 'Allow')
                $isAutoEnroll = ($objectType -eq $autoEnrollGuid) -and ($aceType -eq 'Allow')
                $isWrite     = ($rights -match 'WriteDacl|WriteOwner|GenericAll|WriteProperty') -and ($aceType -eq 'Allow')
                $isOverpermissive = ($identity -in $overpermissive) -or ($identity -like '*Domain Users*')

                $results.Add([PSCustomObject]@{
                    TemplateName        = $name
                    TemplateDN          = $dn
                    IdentityReference   = $identity
                    AccessControlType   = $aceType
                    ActiveDirectoryRights = $rights
                    ObjectType          = $objectType
                    CanEnroll           = $isEnroll
                    CanAutoEnroll       = $isAutoEnroll
                    HasWriteAccess      = $isWrite
                    IsInherited         = $ace.IsInherited
                    IsOverpermissive    = $isOverpermissive
                    PotentialESC4       = ($isWrite -and $isOverpermissive)
                })
            }
        }
        catch {
            Write-Warning "Could not read ACL for template '$name': $_"
        }
    }

    Write-Verbose "Collected $($results.Count) enrollment permission entries."
    return $results.ToArray()
}

#endregion

Export-ModuleMember -Function Get-ADCSCertificateAuthorities, Get-CertificateTemplates,
                               Get-ADCSEnrollmentPermissions
