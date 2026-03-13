#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall LDAP/GC Collector Module
.DESCRIPTION
    Collects Active Directory object data using System.DirectoryServices (.NET LDAP).
    All operations are READ-ONLY and use the current user's credentials unless a
    PSCredential is supplied.
.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region Helper Functions

function New-LdapSearcher {
    <#
    .SYNOPSIS
        Creates a configured System.DirectoryServices.DirectorySearcher.
    #>
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [string]$Filter,
        [string[]]$Properties,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PageSize   = 1000,
        [int]$Timeout    = 120,
        [bool]$UseSSL    = $false,
        [bool]$UseGC     = $false
    )

    try {
        $protocol = if ($UseSSL) { 'LDAPS' } elseif ($UseGC) { 'GC' } else { 'LDAP' }
        $port     = if ($UseSSL) { 636 } elseif ($UseGC) { 3268 } else { 389 }

        if (-not [string]::IsNullOrEmpty($DomainController)) {
            $root = "${protocol}://${DomainController}:${port}"
        }
        else {
            $root = "${protocol}:"
        }

        if (-not [string]::IsNullOrEmpty($SearchBase)) {
            $root = "${root}/$SearchBase"
        }

        if ($null -ne $Credential) {
            $dirEntry = New-Object System.DirectoryServices.DirectoryEntry(
                $root,
                $Credential.UserName,
                $Credential.GetNetworkCredential().Password
            )
        }
        else {
            $dirEntry = New-Object System.DirectoryServices.DirectoryEntry($root)
        }

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($dirEntry)
        $searcher.Filter   = $Filter
        $searcher.PageSize = $PageSize
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($Timeout)
        $searcher.SearchScope     = [System.DirectoryServices.SearchScope]::Subtree

        if ($Properties -and $Properties.Count -gt 0) {
            $searcher.PropertiesToLoad.AddRange($Properties)
        }

        return $searcher
    }
    catch {
        Write-Error "Failed to create LDAP searcher: $_"
        return $null
    }
}

function Get-LdapProperty {
    <#
    .SYNOPSIS
        Safely extracts a property value from a DirectoryServices SearchResult.
    #>
    param(
        [System.DirectoryServices.SearchResult]$Result,
        [string]$PropertyName,
        [bool]$Multi = $false
    )

    if ($null -eq $Result -or -not $Result.Properties.Contains($PropertyName)) {
        return $null
    }

    $vals = $Result.Properties[$PropertyName]
    if ($Multi) { return @($vals) }
    if ($vals.Count -gt 0) { return $vals[0] }
    return $null
}

function Get-DomainSearchBase {
    <#
    .SYNOPSIS
        Builds a default search base DN from the configured or discovered domain.
    #>
    param([string]$DomainController, [System.Management.Automation.PSCredential]$Credential)

    try {
        $root = if (-not [string]::IsNullOrEmpty($DomainController)) {
            "LDAP://$DomainController/RootDSE"
        } else { "LDAP://RootDSE" }

        if ($null -ne $Credential) {
            $rootDse = New-Object System.DirectoryServices.DirectoryEntry(
                $root, $Credential.UserName,
                $Credential.GetNetworkCredential().Password)
        }
        else {
            $rootDse = New-Object System.DirectoryServices.DirectoryEntry($root)
        }

        return $rootDse.Properties['defaultNamingContext'][0]
    }
    catch {
        Write-Warning "Could not auto-detect domain search base: $_"
        return $null
    }
}

#endregion

#region Exported Collector Functions

function Get-ADUsers {
    <#
    .SYNOPSIS
        Enumerates all user accounts from Active Directory.
    .DESCRIPTION
        Returns security-relevant attributes for all user objects, including flags
        useful for privilege and password policy analysis.
    .PARAMETER DomainController
        Target domain controller FQDN or IP.
    .PARAMETER SearchBase
        LDAP distinguished name to use as search root.
    .PARAMETER Credential
        Optional PSCredential for alternate authentication.
    .EXAMPLE
        Get-ADUsers -DomainController dc01.corp.local
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PageSize = 1000
    )

    Write-Verbose "Collecting AD Users..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $props = @(
        'samaccountname','distinguishedname','displayname','mail','description',
        'useraccountcontrol','pwdlastset','lastlogontimestamp','whencreated',
        'whenchanged','memberof','serviceprincipalname','admincount','objectsid',
        'msds-supportedencryptiontypes','msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity','sidhistory','enabled',
        'passwordlastset','accountexpires','badpwdcount','logoncount',
        'primarygroupid','userworkstations','homedirectory','scriptpath'
    )

    $filter  = '(&(objectCategory=person)(objectClass=user))'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $SearchBase -Filter $filter -Properties $props `
        -Credential $Credential -PageSize $PageSize

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r   = $_
            $uac = [int](Get-LdapProperty $r 'useraccountcontrol')

            $obj = [PSCustomObject]@{
                SamAccountName          = Get-LdapProperty $r 'samaccountname'
                DistinguishedName       = Get-LdapProperty $r 'distinguishedname'
                DisplayName             = Get-LdapProperty $r 'displayname'
                Mail                    = Get-LdapProperty $r 'mail'
                Description             = Get-LdapProperty $r 'description'
                UserAccountControl      = $uac
                Enabled                 = -not [bool]($uac -band 0x0002)
                PasswordNeverExpires    = [bool]($uac -band 0x10000)
                PasswordNotRequired     = [bool]($uac -band 0x0020)
                DontRequirePreAuth      = [bool]($uac -band 0x400000)  # AS-REP Roasting
                TrustedForDelegation    = [bool]($uac -band 0x80000)   # Unconstrained
                TrustedToAuthForDelegate = [bool]($uac -band 0x1000000) # Constrained
                UseDesKeyOnly           = [bool]($uac -band 0x200000)
                SmartcardRequired       = [bool]($uac -band 0x40000)
                PasswordLastSet         = if ((Get-LdapProperty $r 'pwdlastset') -gt 0) {
                                            [DateTime]::FromFileTimeUtc([long](Get-LdapProperty $r 'pwdlastset'))
                                          } else { $null }
                LastLogonTimestamp      = if ((Get-LdapProperty $r 'lastlogontimestamp') -gt 0) {
                                            [DateTime]::FromFileTimeUtc([long](Get-LdapProperty $r 'lastlogontimestamp'))
                                          } else { $null }
                WhenCreated             = Get-LdapProperty $r 'whencreated'
                WhenChanged             = Get-LdapProperty $r 'whenchanged'
                AdminCount              = [int](Get-LdapProperty $r 'admincount')
                MemberOf                = Get-LdapProperty $r 'memberof' -Multi $true
                ServicePrincipalNames   = Get-LdapProperty $r 'serviceprincipalname' -Multi $true
                AllowedToDelegateTo     = Get-LdapProperty $r 'msDS-AllowedToDelegateTo' -Multi $true
                SidHistory              = Get-LdapProperty $r 'sidhistory' -Multi $true
                ObjectSid               = Get-LdapProperty $r 'objectsid'
                PrimaryGroupId          = Get-LdapProperty $r 'primarygroupid'
                LogonCount              = [int](Get-LdapProperty $r 'logoncount')
                BadPwdCount             = [int](Get-LdapProperty $r 'badpwdcount')
                HomeDirectory           = Get-LdapProperty $r 'homedirectory'
                ScriptPath              = Get-LdapProperty $r 'scriptpath'
                SupportedEncryptionTypes = [int](Get-LdapProperty $r 'msds-supportedencryptiontypes')
            }
            $results.Add($obj)
        }
        Write-Verbose "Collected $($results.Count) user accounts."
    }
    catch {
        Write-Error "Error collecting AD users: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADGroups {
    <#
    .SYNOPSIS
        Enumerates all security groups from Active Directory.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PageSize = 1000
    )

    Write-Verbose "Collecting AD Groups..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $props = @(
        'samaccountname','distinguishedname','description','member',
        'memberof','grouptype','admincount','objectsid','whencreated','whenchanged',
        'managedby','info'
    )

    $filter   = '(objectClass=group)'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $SearchBase -Filter $filter -Properties $props `
        -Credential $Credential -PageSize $PageSize

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r = $_
            $gt = [int](Get-LdapProperty $r 'grouptype')
            $results.Add([PSCustomObject]@{
                SamAccountName    = Get-LdapProperty $r 'samaccountname'
                DistinguishedName = Get-LdapProperty $r 'distinguishedname'
                Description       = Get-LdapProperty $r 'description'
                GroupType         = $gt
                IsSecurity        = [bool]($gt -band 0x80000000)
                IsGlobal          = [bool]($gt -band 0x2)
                IsUniversal       = [bool]($gt -band 0x8)
                IsDomainLocal     = [bool]($gt -band 0x4)
                Members           = Get-LdapProperty $r 'member'    -Multi $true
                MemberOf          = Get-LdapProperty $r 'memberof'  -Multi $true
                AdminCount        = [int](Get-LdapProperty $r 'admincount')
                ManagedBy         = Get-LdapProperty $r 'managedby'
                ObjectSid         = Get-LdapProperty $r 'objectsid'
                WhenCreated       = Get-LdapProperty $r 'whencreated'
                WhenChanged       = Get-LdapProperty $r 'whenchanged'
            })
        }
        Write-Verbose "Collected $($results.Count) groups."
    }
    catch {
        Write-Error "Error collecting AD groups: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADComputers {
    <#
    .SYNOPSIS
        Enumerates all computer accounts from Active Directory.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PageSize = 1000
    )

    Write-Verbose "Collecting AD Computers..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $props = @(
        'samaccountname','distinguishedname','dnshostname','operatingsystem',
        'operatingsystemversion','operatingsystemservicepack','lastlogontimestamp',
        'whencreated','whenchanged','useraccountcontrol','serviceprincipalname',
        'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',
        'objectsid','description','managedby','location','admincount',
        'msds-supportedencryptiontypes'
    )

    $filter   = '(objectClass=computer)'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $SearchBase -Filter $filter -Properties $props `
        -Credential $Credential -PageSize $PageSize

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r   = $_
            $uac = [int](Get-LdapProperty $r 'useraccountcontrol')
            $results.Add([PSCustomObject]@{
                SamAccountName       = Get-LdapProperty $r 'samaccountname'
                DistinguishedName    = Get-LdapProperty $r 'distinguishedname'
                DnsHostName          = Get-LdapProperty $r 'dnshostname'
                OperatingSystem      = Get-LdapProperty $r 'operatingsystem'
                OSVersion            = Get-LdapProperty $r 'operatingsystemversion'
                OSServicePack        = Get-LdapProperty $r 'operatingsystemservicepack'
                UserAccountControl   = $uac
                Enabled              = -not [bool]($uac -band 0x0002)
                TrustedForDelegation = [bool]($uac -band 0x80000)
                TrustedToAuthForDelegate = [bool]($uac -band 0x1000000)
                LastLogonTimestamp   = if ((Get-LdapProperty $r 'lastlogontimestamp') -gt 0) {
                                         [DateTime]::FromFileTimeUtc([long](Get-LdapProperty $r 'lastlogontimestamp'))
                                       } else { $null }
                WhenCreated          = Get-LdapProperty $r 'whencreated'
                ServicePrincipalNames = Get-LdapProperty $r 'serviceprincipalname' -Multi $true
                AllowedToDelegateTo  = Get-LdapProperty $r 'msDS-AllowedToDelegateTo' -Multi $true
                Description          = Get-LdapProperty $r 'description'
                ManagedBy            = Get-LdapProperty $r 'managedby'
                Location             = Get-LdapProperty $r 'location'
                AdminCount           = [int](Get-LdapProperty $r 'admincount')
                SupportedEncryptionTypes = [int](Get-LdapProperty $r 'msds-supportedencryptiontypes')
            })
        }
        Write-Verbose "Collected $($results.Count) computer accounts."
    }
    catch {
        Write-Error "Error collecting AD computers: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADOUs {
    <#
    .SYNOPSIS
        Enumerates Organizational Units.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PageSize = 1000
    )

    Write-Verbose "Collecting AD OUs..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $props = @('name','distinguishedname','description','gplink','gpoptions',
               'whencreated','whenchanged','managedby')

    $filter   = '(objectClass=organizationalUnit)'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $SearchBase -Filter $filter -Properties $props `
        -Credential $Credential -PageSize $PageSize

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r = $_
            $results.Add([PSCustomObject]@{
                Name              = Get-LdapProperty $r 'name'
                DistinguishedName = Get-LdapProperty $r 'distinguishedname'
                Description       = Get-LdapProperty $r 'description'
                GpLink            = Get-LdapProperty $r 'gplink'
                GpOptions         = Get-LdapProperty $r 'gpoptions'
                ManagedBy         = Get-LdapProperty $r 'managedby'
                WhenCreated       = Get-LdapProperty $r 'whencreated'
                WhenChanged       = Get-LdapProperty $r 'whenchanged'
            })
        }
        Write-Verbose "Collected $($results.Count) OUs."
    }
    catch {
        Write-Error "Error collecting AD OUs: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADTrusts {
    <#
    .SYNOPSIS
        Enumerates all domain/forest trust relationships.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting AD Trusts..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $props = @('name','distinguishedname','trustpartner','trusttype','trustattributes',
               'trustdirection','whencreated','whenchanged','flatname','securityidentifier')

    $filter   = '(objectClass=trustedDomain)'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $SearchBase -Filter $filter -Properties $props `
        -Credential $Credential

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r  = $_
            $td = [int](Get-LdapProperty $r 'trustdirection')
            $tt = [int](Get-LdapProperty $r 'trusttype')
            $ta = [int](Get-LdapProperty $r 'trustattributes')

            $directionStr = switch ($td) {
                0 { 'Disabled' }
                1 { 'Inbound' }
                2 { 'Outbound' }
                3 { 'Bidirectional' }
                default { "Unknown($td)" }
            }

            $typeStr = switch ($tt) {
                1 { 'Downlevel (NT)' }
                2 { 'Uplevel (AD)' }
                3 { 'MIT Kerberos' }
                4 { 'DCE' }
                default { "Unknown($tt)" }
            }

            $results.Add([PSCustomObject]@{
                Name              = Get-LdapProperty $r 'name'
                DistinguishedName = Get-LdapProperty $r 'distinguishedname'
                TrustPartner      = Get-LdapProperty $r 'trustpartner'
                FlatName          = Get-LdapProperty $r 'flatname'
                TrustType         = $typeStr
                TrustDirection    = $directionStr
                TrustAttributes   = $ta
                IsTransitive      = [bool]($ta -band 0x8)         # FOREST_TRANSITIVE flag
                IsForestTrust     = [bool]($ta -band 0x8)         # same bit; forest trusts are transitive
                IsSidFilteringEnabled = -not [bool]($ta -band 0x40) # TREAT_AS_EXTERNAL disables SID filtering
                WhenCreated       = Get-LdapProperty $r 'whencreated'
                WhenChanged       = Get-LdapProperty $r 'whenchanged'
            })
        }
        Write-Verbose "Collected $($results.Count) trusts."
    }
    catch {
        Write-Error "Error collecting AD trusts: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADGPOs {
    <#
    .SYNOPSIS
        Enumerates all Group Policy Objects.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PageSize = 1000
    )

    Write-Verbose "Collecting AD GPOs..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $gpoBase  = "CN=Policies,CN=System,$SearchBase"
    $props    = @('displayname','distinguishedname','cn','gpcfilesyspath',
                  'gpcmachineextensionnames','gpcuserextensionnames',
                  'whencreated','whenchanged','flags','versionnumber')

    $filter   = '(objectClass=groupPolicyContainer)'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $gpoBase -Filter $filter -Properties $props `
        -Credential $Credential -PageSize $PageSize

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r     = $_
            $flags = [int](Get-LdapProperty $r 'flags')
            $results.Add([PSCustomObject]@{
                DisplayName       = Get-LdapProperty $r 'displayname'
                DistinguishedName = Get-LdapProperty $r 'distinguishedname'
                GpoId             = Get-LdapProperty $r 'cn'
                FileSysPath       = Get-LdapProperty $r 'gpcfilesyspath'
                MachineExtensions = Get-LdapProperty $r 'gpcmachineextensionnames'
                UserExtensions    = Get-LdapProperty $r 'gpcuserextensionnames'
                Flags             = $flags
                IsEnabled         = ($flags -eq 0)
                IsUserEnabled     = -not [bool]($flags -band 0x1)
                IsComputerEnabled = -not [bool]($flags -band 0x2)
                VersionNumber     = Get-LdapProperty $r 'versionnumber'
                WhenCreated       = Get-LdapProperty $r 'whencreated'
                WhenChanged       = Get-LdapProperty $r 'whenchanged'
            })
        }
        Write-Verbose "Collected $($results.Count) GPOs."
    }
    catch {
        Write-Error "Error collecting AD GPOs: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADACLs {
    <#
    .SYNOPSIS
        Retrieves ACLs for sensitive Active Directory objects.
    .DESCRIPTION
        Reads the nTSecurityDescriptor of high-value targets: domain root, AdminSDHolder,
        built-in admin containers. Uses System.DirectoryServices.ActiveDirectorySecurity.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting sensitive AD ACLs..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $sensitiveTargets = @(
        $SearchBase,                              # Domain root
        "CN=AdminSDHolder,CN=System,$SearchBase", # AdminSDHolder
        "CN=Domain Admins,CN=Users,$SearchBase",  # Domain Admins group
        "CN=Builtin,$SearchBase"                  # Builtin container
    )

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($target in $sensitiveTargets) {
        try {
            $ldapPath = if (-not [string]::IsNullOrEmpty($DomainController)) {
                "LDAP://$DomainController/$target"
            } else { "LDAP://$target" }

            $dirEntry = if ($null -ne $Credential) {
                New-Object System.DirectoryServices.DirectoryEntry(
                    $ldapPath, $Credential.UserName,
                    $Credential.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
            }

            $acl  = $dirEntry.ObjectSecurity
            $aces = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

            foreach ($ace in $aces) {
                $results.Add([PSCustomObject]@{
                    TargetObject       = $target
                    IdentityReference  = $ace.IdentityReference.Value
                    AccessControlType  = $ace.AccessControlType.ToString()
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                    IsInherited        = $ace.IsInherited
                    InheritanceType    = $ace.InheritanceType.ToString()
                    ObjectType         = $ace.ObjectType.ToString()
                    InheritedObjectType = $ace.InheritedObjectType.ToString()
                })
            }
        }
        catch {
            Write-Warning "Could not read ACL for '$target': $_"
        }
    }

    Write-Verbose "Collected $($results.Count) ACE entries."
    return $results.ToArray()
}

function Get-ADDomainControllers {
    <#
    .SYNOPSIS
        Enumerates all domain controllers in the domain.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting Domain Controllers..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $props = @('name','distinguishedname','dnshostname','operatingsystem',
               'operatingsystemversion','useraccountcontrol','lastlogontimestamp',
               'serviceprincipalname','msDS-IsRODC','whencreated','whenchanged',
               'serverreferenceBL','primarygroupid')

    $filter   = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $SearchBase -Filter $filter -Properties $props `
        -Credential $Credential

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r = $_
            $results.Add([PSCustomObject]@{
                Name              = Get-LdapProperty $r 'name'
                DistinguishedName = Get-LdapProperty $r 'distinguishedname'
                DnsHostName       = Get-LdapProperty $r 'dnshostname'
                OperatingSystem   = Get-LdapProperty $r 'operatingsystem'
                OSVersion         = Get-LdapProperty $r 'operatingsystemversion'
                IsRODC            = [bool](Get-LdapProperty $r 'msDS-IsRODC')
                LastLogonTimestamp = if ((Get-LdapProperty $r 'lastlogontimestamp') -gt 0) {
                                      [DateTime]::FromFileTimeUtc([long](Get-LdapProperty $r 'lastlogontimestamp'))
                                    } else { $null }
                ServicePrincipalNames = Get-LdapProperty $r 'serviceprincipalname' -Multi $true
                WhenCreated       = Get-LdapProperty $r 'whencreated'
                WhenChanged       = Get-LdapProperty $r 'whenchanged'
            })
        }
        Write-Verbose "Collected $($results.Count) domain controllers."
    }
    catch {
        Write-Error "Error collecting domain controllers: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADPasswordPolicies {
    <#
    .SYNOPSIS
        Retrieves the default domain password policy.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting domain password policy..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $props = @('distinguishedname','minpwdlength','minpwdage','maxpwdage',
               'lockoutthreshold','lockoutobservationwindow','lockoutduration',
               'pwdproperties','pwdhistorylength','ms-ds-machineaccountquota')

    $filter   = '(objectClass=domainDNS)'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $SearchBase -Filter $filter -Properties $props `
        -Credential $Credential
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r   = $_
            $pp  = [int](Get-LdapProperty $r 'pwdproperties')
            $results.Add([PSCustomObject]@{
                DistinguishedName    = Get-LdapProperty $r 'distinguishedname'
                MinPasswordLength    = [int](Get-LdapProperty $r 'minpwdlength')
                PasswordHistoryCount = [int](Get-LdapProperty $r 'pwdhistorylength')
                ComplexityEnabled    = [bool]($pp -band 0x1)
                ReversibleEncryption = [bool]($pp -band 0x10)
                MaxPasswordAgeDays   = if ((Get-LdapProperty $r 'maxpwdage') -ne 0) {
                                         [Math]::Abs([long](Get-LdapProperty $r 'maxpwdage') / 864000000000)
                                       } else { 0 }
                MinPasswordAgeDays   = if ((Get-LdapProperty $r 'minpwdage') -ne 0) {
                                         [Math]::Abs([long](Get-LdapProperty $r 'minpwdage') / 864000000000)
                                       } else { 0 }
                LockoutThreshold     = [int](Get-LdapProperty $r 'lockoutthreshold')
                LockoutDurationMins  = if ((Get-LdapProperty $r 'lockoutduration') -ne 0) {
                                         [Math]::Abs([long](Get-LdapProperty $r 'lockoutduration') / 600000000)
                                       } else { 0 }
                MachineAccountQuota  = [int](Get-LdapProperty $r 'ms-ds-machineaccountquota')
            })
        }
    }
    catch {
        Write-Error "Error collecting domain password policy: $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

function Get-ADFinePWPolicies {
    <#
    .SYNOPSIS
        Retrieves Fine-Grained Password Policies (PSOs).
    #>
    [CmdletBinding()]
    param(
        [string]$DomainController,
        [string]$SearchBase,
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Verbose "Collecting Fine-Grained Password Policies..."

    if ([string]::IsNullOrEmpty($SearchBase)) {
        $SearchBase = Get-DomainSearchBase -DomainController $DomainController -Credential $Credential
    }

    $psoBase  = "CN=Password Settings Container,CN=System,$SearchBase"
    $props    = @('name','distinguishedname','msds-passwordsettingsprecedence',
                  'msds-minimumpasswordlength','msds-passwordhistorylength',
                  'msds-passwordcomplexityenabled','msds-maximumpasswordage',
                  'msds-minimumpasswordage','msds-lockoutthreshold',
                  'msds-lockoutobservationwindow','msds-lockoutduration',
                  'msds-psoappliesto','msds-passwordreversibleencryptionenabled',
                  'whencreated','whenchanged')

    $filter   = '(objectClass=msDS-PasswordSettings)'
    $searcher = New-LdapSearcher -DomainController $DomainController `
        -SearchBase $psoBase -Filter $filter -Properties $props `
        -Credential $Credential

    if ($null -eq $searcher) { return @() }

    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $searcher.FindAll() | ForEach-Object {
            $r = $_
            $results.Add([PSCustomObject]@{
                Name              = Get-LdapProperty $r 'name'
                DistinguishedName = Get-LdapProperty $r 'distinguishedname'
                Precedence        = [int](Get-LdapProperty $r 'msds-passwordsettingsprecedence')
                MinPasswordLength = [int](Get-LdapProperty $r 'msds-minimumpasswordlength')
                PasswordHistoryCount = [int](Get-LdapProperty $r 'msds-passwordhistorylength')
                ComplexityEnabled = [bool](Get-LdapProperty $r 'msds-passwordcomplexityenabled')
                ReversibleEncryption = [bool](Get-LdapProperty $r 'msds-passwordreversibleencryptionenabled')
                AppliesToDNs      = Get-LdapProperty $r 'msds-psoappliesto' -Multi $true
                LockoutThreshold  = [int](Get-LdapProperty $r 'msds-lockoutthreshold')
                WhenCreated       = Get-LdapProperty $r 'whencreated'
                WhenChanged       = Get-LdapProperty $r 'whenchanged'
            })
        }
        Write-Verbose "Collected $($results.Count) Fine-Grained Password Policies."
    }
    catch {
        Write-Warning "Could not collect Fine-Grained Password Policies (may not exist): $_"
    }
    finally {
        $searcher.Dispose()
    }

    return $results.ToArray()
}

#endregion

Export-ModuleMember -Function Get-ADUsers, Get-ADGroups, Get-ADComputers, Get-ADOUs,
                               Get-ADTrusts, Get-ADGPOs, Get-ADACLs, Get-ADDomainControllers,
                               Get-ADPasswordPolicies, Get-ADFinePWPolicies
