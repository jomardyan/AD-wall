#Requires -Version 5.1
<#
.SYNOPSIS
    Pester tests for src/engine/AttackGraphEngine.ps1
.DESCRIPTION
    Tests Build-AttackGraph and Find-AttackPaths using synthetic AD data objects
    so that no Active Directory connection is required.
#>

BeforeAll {
    # Suppress Export-ModuleMember error (only valid inside .psm1 modules)
    try { . "$PSScriptRoot\..\src\engine\AttackGraphEngine.ps1" } catch [System.InvalidOperationException] { }

    # ---------------------------------------------------------------------------
    # Helpers to build minimal synthetic AD data
    # ---------------------------------------------------------------------------

    function script:_MakeUser {
        param(
            [string]$Sam,
            [string]$DN          = "CN=$Sam,DC=corp,DC=local",
            [bool]  $Enabled     = $true,
            [string[]]$MemberOf  = @(),
            [string[]]$SPNs      = @(),
            [bool]  $UnconsDel   = $false,
            [bool]  $ASREPRoast  = $false
        )
        [PSCustomObject]@{
            SamAccountName              = $Sam
            DistinguishedName           = $DN
            Enabled                     = $Enabled
            MemberOf                    = $MemberOf
            ServicePrincipalNames       = $SPNs
            TrustedForDelegation        = $UnconsDel
            DoesNotRequirePreAuth       = $ASREPRoast
            # Build-AttackGraph uses UserAccountControl bitmask for AS-REP roasting check.
            # Set to 0 (no flags) by default; callers can override for specific tests.
            UserAccountControl          = 0
            SIDHistory                  = @()
            AdminCount                  = 0
            PasswordLastSet             = (Get-Date)
            LastLogonDate               = (Get-Date)
            'msDS-SupportedEncryptionTypes' = 28   # AES128+256
        }
    }

    function script:_MakeGroup {
        param(
            [string]$Name,
            [string]$DN        = "CN=$Name,CN=Users,DC=corp,DC=local",
            [string[]]$Members = @(),
            [string[]]$MemberOf = @()
        )
        [PSCustomObject]@{
            SamAccountName    = $Name
            DistinguishedName = $DN
            Members           = $Members
            MemberOf          = $MemberOf
        }
    }

    function script:_MakeCollectedData {
        param(
            [object[]]$Users       = @(),
            [object[]]$Groups      = @(),
            [object[]]$Computers   = @(),
            [object[]]$ACLs        = @(),
            [object[]]$Trusts      = @(),
            [object[]]$Templates   = @(),
            [object[]]$EnrollPerms = @(),
            [object[]]$DCs         = @()
        )
        @{
            Users                  = $Users
            Groups                 = $Groups
            Computers              = $Computers
            ACLs                   = $ACLs
            Trusts                 = $Trusts
            CertificateTemplates   = $Templates
            EnrollmentPermissions  = $EnrollPerms
            DomainControllers      = $DCs
        }
    }
}
Describe 'Build-AttackGraph' {

    Context 'Empty data' {

        It 'Returns a graph hashtable without throwing' {
            $data  = _MakeCollectedData
            { Build-AttackGraph -CollectedData $data -DomainName 'corp.local' } |
                Should -Not -Throw
        }

        It 'Graph has NodeCount >= 1 (at least the domain root node)' {
            $data  = _MakeCollectedData
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'
            $graph.NodeCount | Should -BeGreaterOrEqual 1
        }
    }

    Context 'User nodes' {

        It 'Creates a user node for each enabled user' {
            $users = @(
                _MakeUser 'alice'
                _MakeUser 'bob'
            )
            $data  = _MakeCollectedData -Users $users
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'
            $graph.Nodes.Keys | Should -Contain 'USER:alice'
            $graph.Nodes.Keys | Should -Contain 'USER:bob'
        }

        It 'Does not create SPN/delegation edges for a disabled account' {
            # Build-AttackGraph creates a node for every user including disabled ones,
            # but must NOT create HasSPN / CanDelegate edges for disabled accounts.
            $u = _MakeUser 'disabled_acct' -Enabled $false `
                -SPNs @('MSSQLSvc/sql.corp.local:1433') -UnconsDel $true
            $data  = _MakeCollectedData -Users @($u)
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'

            # No HasSPN edge should exist for a disabled user
            $spnEdges = @($graph.Edges | Where-Object {
                $_.EdgeType -eq 'HasSPN' -and $_.SourceId -eq 'USER:disabled_acct'
            })
            $spnEdges | Should -BeNullOrEmpty

            # No CanDelegate edge should exist either
            $delEdges = @($graph.Edges | Where-Object {
                $_.EdgeType -eq 'CanDelegate' -and $_.SourceId -eq 'USER:disabled_acct'
            })
            $delEdges | Should -BeNullOrEmpty
        }
    }

    Context 'Group membership edges (MemberOf)' {

        It 'Creates a MemberOf edge when a user is in Domain Admins' {
            $users  = @(_MakeUser 'alice' -MemberOf @('CN=Domain Admins,CN=Users,DC=corp,DC=local'))
            $groups = @(_MakeGroup 'Domain Admins' -Members @('CN=alice,DC=corp,DC=local'))
            $data   = _MakeCollectedData -Users $users -Groups $groups
            $graph  = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'

            $memberEdges = @($graph.Edges | Where-Object { $_.EdgeType -eq 'MemberOf' })
            $memberEdges | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SPN (HasSPN) edge' {

        It 'Creates a HasSPN edge for a user with a service principal name' {
            $users = @(_MakeUser 'svc_sql' -SPNs @('MSSQLSvc/sqlserver.corp.local:1433'))
            $data  = _MakeCollectedData -Users $users
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'

            $spnEdges = @($graph.Edges | Where-Object { $_.EdgeType -eq 'HasSPN' })
            $spnEdges | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Unconstrained delegation (CanDelegate) edge' {

        It 'Creates a CanDelegate edge for a user with TrustedForDelegation' {
            $users = @(_MakeUser 'delegator' -UnconsDel $true)
            $data  = _MakeCollectedData -Users $users
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'

            $delEdges = @($graph.Edges | Where-Object { $_.EdgeType -eq 'CanDelegate' })
            $delEdges | Should -Not -BeNullOrEmpty
        }
    }

    Context 'SID history (HasSIDHistory) edge' {

        It 'Creates a HasSIDHistory edge when SIDHistory is populated' {
            $u = _MakeUser 'migrated_user'
            $u | Add-Member -NotePropertyName 'SIDHistory' `
                -NotePropertyValue @([PSCustomObject]@{ AccountDomainSid = 'S-1-5-21-111-222-333' }) `
                -Force
            $data  = _MakeCollectedData -Users @($u)
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'

            $sidEdges = @($graph.Edges | Where-Object { $_.EdgeType -eq 'HasSIDHistory' })
            $sidEdges | Should -Not -BeNullOrEmpty
        }
    }
}

# ---------------------------------------------------------------------------
Describe 'Find-AttackPaths' {

    Context 'No paths in an empty graph' {

        It 'Returns an empty array without throwing' {
            $data  = _MakeCollectedData
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'
            { Find-AttackPaths -Graph $graph } | Should -Not -Throw
            $paths = Find-AttackPaths -Graph $graph
            $paths | Should -BeNullOrEmpty
        }
    }

    Context 'Direct path — user is already in Domain Admins' {

        It 'Finds a 1-hop attack path' {
            # Alice is a member of Domain Admins → direct Tier 0 access
            $users  = @(
                _MakeUser 'alice' -MemberOf @('CN=Domain Admins,CN=Users,DC=corp,DC=local')
            )
            $groups = @(
                _MakeGroup 'Domain Admins' -Members @('CN=alice,DC=corp,DC=local')
                _MakeGroup 'Administrators' -Members @()
            )
            $data  = _MakeCollectedData -Users $users -Groups $groups
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'
            $paths = Find-AttackPaths -Graph $graph

            $paths | Should -Not -BeNullOrEmpty
            # The shortest path should start at alice's user node
            ($paths | Where-Object { $_.StartNode -eq 'alice' }) | Should -Not -BeNull
        }
    }

    Context 'MaxDepth and MaxPaths limits' {

        It 'Respects MaxPaths limit' {
            # Build a graph with multiple Tier 0 members
            $users = @(1..5 | ForEach-Object {
                _MakeUser "admin$_" -MemberOf @('CN=Domain Admins,CN=Users,DC=corp,DC=local')
            })
            $groups = @(_MakeGroup 'Domain Admins' -Members ($users | ForEach-Object { $_.DistinguishedName }))
            $data  = _MakeCollectedData -Users $users -Groups $groups
            $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'

            $paths = Find-AttackPaths -Graph $graph -MaxPaths 2
            $paths.Count | Should -BeLessOrEqual 2
        }

        It 'Returns no paths when MaxDepth is 0' {
            $users  = @(_MakeUser 'alice' -MemberOf @('CN=Domain Admins,CN=Users,DC=corp,DC=local'))
            $groups = @(_MakeGroup 'Domain Admins' -Members @('CN=alice,DC=corp,DC=local'))
            $data   = _MakeCollectedData -Users $users -Groups $groups
            $graph  = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'

            $paths = Find-AttackPaths -Graph $graph -MaxDepth 0
            $paths | Should -BeNullOrEmpty
        }
    }

    Context 'Path risk assignment' {

        It 'Short paths are rated Critical or High' {
            $users  = @(_MakeUser 'alice' -MemberOf @('CN=Domain Admins,CN=Users,DC=corp,DC=local'))
            $groups = @(_MakeGroup 'Domain Admins' -Members @('CN=alice,DC=corp,DC=local'))
            $data   = _MakeCollectedData -Users $users -Groups $groups
            $graph  = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'
            $paths  = Find-AttackPaths -Graph $graph

            $short = $paths | Where-Object { $_.PathLength -le 2 }
            foreach ($p in $short) {
                $p.Risk | Should -BeIn @('Critical', 'High')
            }
        }
    }
}
