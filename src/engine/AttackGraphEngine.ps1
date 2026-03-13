#Requires -Version 5.1
<#
.SYNOPSIS
    AD-Wall Attack Path Graph Engine
.DESCRIPTION
    Builds a directed graph model of the AD environment (users, groups, computers,
    ACL edges, trusts, and certificate templates) and identifies shortest attack
    paths to privileged access (Domain Admin / Tier 0). Uses BFS for path discovery.

    Graph edge types:
    - MemberOf       : account/group is a direct member of a group
    - CanDelegate    : host/user has unconstrained delegation (can capture TGTs)
    - CanDCSync      : account has Replicating Directory Changes (DCSync capable)
    - HasWriteACL    : account has GenericAll/WriteDacl/WriteOwner over a Tier 0 object
    - CanEnrollESC   : account can enroll in a vulnerable cert template
    - TrustEdge      : domain/forest trust relationship
    - AdminSDHolder  : account has suspicious ACE on AdminSDHolder
    - HasSPN         : user account has an SPN (Kerberoastable path)
    - HasSIDHistory  : account has privileged SID in SIDHistory

.NOTES
    Author: AD-Wall Project
    Version: 1.0.0
#>

Set-StrictMode -Version Latest

#region Graph Construction

function Build-AttackGraph {
    <#
    .SYNOPSIS
        Builds a directed attack-path graph from collected AD data.
    .DESCRIPTION
        Takes the full collected-data hashtable and constructs an adjacency list
        representing all exploitable relationships between AD objects.
        Nodes: users, groups, computers, domains, cert templates.
        Edges: group membership, delegation, ACL rights, trust paths, cert enrollment.
    .PARAMETER CollectedData
        Hashtable from the collector phase (Users, Groups, Computers, ACLs, Trusts,
        CertificateTemplates, EnrollmentPermissions, DomainControllers).
    .PARAMETER DomainName
        FQDN of the domain being assessed.
    .EXAMPLE
        $graph = Build-AttackGraph -CollectedData $data -DomainName 'corp.local'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CollectedData,

        [Parameter(Mandatory = $false)]
        [string]$DomainName = $env:USERDNSDOMAIN
    )

    Write-Verbose "Building AD attack-path graph..."

    # Graph: { Nodes = @{nodeId -> @{...}}, Edges = [list of edge objects] }
    $nodes = [System.Collections.Generic.Dictionary[string, hashtable]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $edges = [System.Collections.Generic.List[hashtable]]::new()

    # Tier 0 group names
    $tier0Names = @(
        'Domain Admins','Enterprise Admins','Schema Admins',
        'Administrators','Account Operators','Backup Operators',
        'Domain Controllers','ENTERPRISE DOMAIN CONTROLLERS',
        'Group Policy Creator Owners'
    )

    # --- Helper closures ---
    $addNode = {
        param([string]$id, [string]$type, [string]$name, [bool]$tier0 = $false, [hashtable]$props = @{})
        if (-not $nodes.ContainsKey($id)) {
            $nodes[$id] = @{
                NodeId     = $id
                NodeType   = $type
                Name       = $name
                IsTier0    = $tier0
                Properties = $props
            }
        }
    }

    $addEdge = {
        param([string]$src, [string]$tgt, [string]$type, [string]$details = '')
        $edges.Add(@{
            SourceId = $src
            TargetId = $tgt
            EdgeType = $type
            Details  = $details
        })
    }

    # --- Domain root node ---
    $domainNode = "DOMAIN:$DomainName"
    & $addNode $domainNode 'Domain' $DomainName $false

    # --- Users ---
    $users      = @(if ($CollectedData.ContainsKey('Users'))     { $CollectedData.Users }     else { @() })
    $groups     = @(if ($CollectedData.ContainsKey('Groups'))    { $CollectedData.Groups }    else { @() })
    $computers  = @(if ($CollectedData.ContainsKey('Computers')) { $CollectedData.Computers } else { @() })
    $acls       = @(if ($CollectedData.ContainsKey('ACLs'))      { $CollectedData.ACLs }      else { @() })
    $trusts     = @(if ($CollectedData.ContainsKey('Trusts'))    { $CollectedData.Trusts }    else { @() })
    $templates  = @(if ($CollectedData.ContainsKey('CertificateTemplates'))  { $CollectedData.CertificateTemplates }  else { @() })
    $enrollPerms= @(if ($CollectedData.ContainsKey('EnrollmentPermissions')) { $CollectedData.EnrollmentPermissions } else { @() })
    $dcs        = @(if ($CollectedData.ContainsKey('DomainControllers'))     { $CollectedData.DomainControllers }     else { @() })

    # Build group DN→name lookup + tier0 flags
    $groupByDN   = @{}
    $groupByName = @{}
    foreach ($g in $groups) {
        $gid  = "GROUP:$($g.SamAccountName)"
        $tier0 = $g.SamAccountName -in $tier0Names
        & $addNode $gid 'Group' $g.SamAccountName $tier0 @{ DN = $g.DistinguishedName }
        if ($g.DistinguishedName) { $groupByDN[$g.DistinguishedName]   = $g }
        if ($g.SamAccountName)   { $groupByName[$g.SamAccountName]    = $g }
    }

    $dcNames = @($dcs | ForEach-Object { if ($_.DnsHostName) { $_.DnsHostName } else { $_.Name } })

    # User nodes + membership edges + SPN/delegation edges
    foreach ($u in $users) {
        if (-not $u.SamAccountName) { continue }
        $uid   = "USER:$($u.SamAccountName)"
        $tier0 = [bool]($u.AdminCount -eq 1)
        & $addNode $uid 'User' $u.SamAccountName $tier0 @{
            DN              = $u.DistinguishedName
            Enabled         = $u.Enabled
            AdminCount      = $u.AdminCount
            PasswordLastSet = $u.PasswordLastSet
        }

        # MemberOf edges
        $memberOf = @($u.MemberOf | Where-Object { $_ })
        foreach ($groupDN in $memberOf) {
            if ($groupByDN.ContainsKey($groupDN)) {
                $targetGrp = $groupByDN[$groupDN]
                $tgt = "GROUP:$($targetGrp.SamAccountName)"
                & $addEdge $uid $tgt 'MemberOf' "Direct member of $($targetGrp.SamAccountName)"
            }
        }

        # HasSPN edge (Kerberoastable)
        if ($u.Enabled -and $u.ServicePrincipalNames.Count -gt 0) {
            & $addEdge $uid $domainNode 'HasSPN' "SPNs: $($u.ServicePrincipalNames -join '; ')"
        }

        # Unconstrained delegation
        if ($u.Enabled -and $u.TrustedForDelegation) {
            & $addEdge $uid $domainNode 'CanDelegate' 'Unconstrained Kerberos delegation'
        }

        # SID History (privileged SID → Tier 0 access)
        if ($u.SIDHistory.Count -gt 0) {
            & $addEdge $uid $domainNode 'HasSIDHistory' "SID History: $($u.SIDHistory -join '; ')"
        }

        # AS-REP roastable (no pre-auth)
        $UAC_NOPREAUTH = 0x400000
        if ($u.Enabled -and ($u.UserAccountControl -band $UAC_NOPREAUTH)) {
            & $addEdge $uid $domainNode 'ASREPRoastable' 'No Kerberos pre-authentication required'
        }
    }

    # Group MemberOf (nested group) edges
    foreach ($g in $groups) {
        $gid = "GROUP:$($g.SamAccountName)"
        $memberOf = @($g.MemberOf | Where-Object { $_ })
        foreach ($parentDN in $memberOf) {
            if ($groupByDN.ContainsKey($parentDN)) {
                $parentGrp = $groupByDN[$parentDN]
                $tgt = "GROUP:$($parentGrp.SamAccountName)"
                & $addEdge $gid $tgt 'MemberOf' "Nested group: $($g.SamAccountName) in $($parentGrp.SamAccountName)"
            }
        }
        # Group → Domain edge for Tier 0
        if ($g.SamAccountName -in $tier0Names) {
            & $addEdge $domainNode "GROUP:$($g.SamAccountName)" 'ContainsTier0' "Tier 0 group"
        }
    }

    # Computer nodes
    # Pre-compute short DC names once (strip FQDN suffix) for O(1) per-computer lookup
    $dcShortNames = @($dcNames | ForEach-Object { $_ -replace '\..*$','' })

    foreach ($c in $computers) {
        if (-not $c.SamAccountName) { continue }
        $cid   = "COMPUTER:$($c.SamAccountName)"
        $isDC  = ($c.SamAccountName -replace '\$$','') -in $dcShortNames
        & $addNode $cid 'Computer' $c.SamAccountName $isDC @{
            DN      = $c.DistinguishedName
            Enabled = $c.Enabled
            OS      = $c.OperatingSystem
        }
        # Unconstrained delegation on non-DC computer
        if ($c.Enabled -and $c.TrustedForDelegation -and -not $isDC) {
            & $addEdge $cid $domainNode 'CanDelegate' 'Unconstrained delegation on computer'
        }
    }

    # ACL edges — dangerous rights over Tier 0 objects
    $dangerousRights = @('GenericAll','WriteDacl','WriteOwner','GenericWrite','WriteProperty',
                         'CreateChild','Self','ExtendedRight')
    $tier0DNPatterns = @(
        'CN=AdminSDHolder,CN=System',
        'CN=Domain Admins',
        'CN=Enterprise Admins',
        'CN=Schema Admins',
        'CN=Administrators,CN=Builtin'
    )

    foreach ($ace in $acls) {
        $objectDN = $ace.ObjectDN
        if (-not $objectDN) { continue }

        $isOverTier0 = $tier0DNPatterns | Where-Object { $objectDN -like "*$_*" }
        $hasDCSync   = $ace.ObjectType -in @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
            '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
        )

        $identity = $ace.IdentityReference
        if (-not $identity) { continue }

        # Resolve identity to node id
        $srcNodeId = $null
        $sam = $identity -replace '^[^\\]+\\',''

        # Check if user
        $matchUser = $users | Where-Object { $_.SamAccountName -eq $sam } | Select-Object -First 1
        if ($matchUser) { $srcNodeId = "USER:$sam" }
        else {
            $matchGrp = $groups | Where-Object { $_.SamAccountName -eq $sam } | Select-Object -First 1
            if ($matchGrp) { $srcNodeId = "GROUP:$sam" }
        }

        if ($null -ne $srcNodeId) {
            if ($hasDCSync) {
                & $addEdge $srcNodeId $domainNode 'CanDCSync' "DCSync right on $objectDN"
            }
            if ($isOverTier0) {
                $rights = if ($ace.Rights) { $ace.Rights } else { $ace.ActiveDirectoryRights }
                $hasDangerous = $dangerousRights | Where-Object { $rights -match $_ }
                if ($hasDangerous) {
                    & $addEdge $srcNodeId "GROUP:Domain Admins" 'HasWriteACL' "Dangerous ACE ($($hasDangerous -join ',')) on $objectDN"
                }
            }
        }
    }

    # Trust edges
    foreach ($t in $trusts) {
        if (-not $t.TargetName) { continue }
        $trustNode = "DOMAIN:$($t.TargetName)"
        & $addNode $trustNode 'Domain' $t.TargetName $false @{ TrustType = $t.TrustType }

        $direction = if ($t.Direction -match 'Outbound|Both') { 'TrustEdge' } else { 'TrustEdgeInbound' }
        & $addEdge $domainNode $trustNode $direction "Trust direction: $($t.Direction), SIDFiltering: $($t.SIDFilteringEnabled)"
    }

    # Certificate template enrollment edges
    $escVulnTemplates = @()
    foreach ($tmpl in $templates) {
        if (-not $tmpl.Name) { continue }
        $tmplNode = "CERTTEMPLATE:$($tmpl.Name)"
        & $addNode $tmplNode 'CertTemplate' $tmpl.Name $false @{
            EKUs           = $tmpl.ExtendedKeyUsage
            SubjectAltName = $tmpl.SubjectAltNameFlags
            RequiresApproval = $tmpl.RequiresManagerApproval
        }

        # ESC1: enrollee-supplied SAN + authentication EKU
        $isESC1 = $tmpl.SubjectAltNameFlags -gt 0 -and
                  $tmpl.RequiresManagerApproval -eq $false -and
                  ($tmpl.ExtendedKeyUsage -match 'Client Authentication|Smart Card Logon|Any Purpose')
        if ($isESC1) {
            $escVulnTemplates += $tmplNode
        }
    }

    foreach ($perm in $enrollPerms) {
        $tmplName = $perm.TemplateName
        if (-not $tmplName) { continue }
        $tmplNode = "CERTTEMPLATE:$tmplName"

        $identity = $perm.IdentityReference -replace '^[^\\]+\\',''
        $canEnroll = $perm.Rights -match 'Enroll|AutoEnroll|FullControl'
        if (-not $canEnroll) { continue }

        $srcNodeId = $null
        $matchUser = $users | Where-Object { $_.SamAccountName -eq $identity } | Select-Object -First 1
        if ($matchUser) { $srcNodeId = "USER:$identity" }
        else {
            $matchGrp = $groups | Where-Object { $_.SamAccountName -eq $identity } | Select-Object -First 1
            if ($matchGrp) { $srcNodeId = "GROUP:$identity" }
        }

        if ($null -ne $srcNodeId -and $tmplNode -in $escVulnTemplates) {
            & $addEdge $srcNodeId "GROUP:Domain Admins" 'CanEnrollESC' "Can enroll in vulnerable template $tmplName"
        }
    }

    $graph = @{
        DomainName  = $DomainName
        DomainNode  = $domainNode
        Tier0Nodes  = @($nodes.Keys | Where-Object { $nodes[$_].IsTier0 })
        Nodes       = $nodes
        Edges       = $edges
        NodeCount   = $nodes.Count
        EdgeCount   = $edges.Count
        GeneratedAt = (Get-Date -Format 'o')
    }

    Write-Verbose "Graph built: $($nodes.Count) nodes, $($edges.Count) edges"
    return $graph
}

#endregion

#region Path Finding (BFS)

function Find-AttackPaths {
    <#
    .SYNOPSIS
        Finds shortest attack paths from non-Tier0 nodes to Domain Admin / Tier 0 access.
    .DESCRIPTION
        Uses Breadth-First Search (BFS) over the attack graph to find shortest paths
        from any non-Tier0 account to Tier 0 control. Returns all paths up to MaxDepth.
    .PARAMETER Graph
        Attack graph built by Build-AttackGraph.
    .PARAMETER MaxDepth
        Maximum path length to explore. Default 5 (longer paths are less exploitable).
    .PARAMETER MaxPaths
        Maximum paths to return. Default 20.
    .EXAMPLE
        $paths = Find-AttackPaths -Graph $attackGraph
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph,

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 5,

        [Parameter(Mandatory = $false)]
        [int]$MaxPaths = 20
    )

    if ($Graph.NodeCount -eq 0 -or $Graph.EdgeCount -eq 0) {
        Write-Verbose "Graph is empty — no attack paths to compute."
        return @()
    }

    Write-Verbose "Computing attack paths (BFS, MaxDepth=$MaxDepth)..."

    # Build adjacency list: sourceId → list of {TargetId, EdgeType, Details}
    $adj = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[hashtable]]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($edge in $Graph.Edges) {
        if (-not $adj.ContainsKey($edge.SourceId)) {
            $adj[$edge.SourceId] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $adj[$edge.SourceId].Add($edge)
    }

    # Tier 0 target nodes — "GROUP:Domain Admins" and domain root are the ultimate targets
    $tier0Targets = @($Graph.Tier0Nodes)
    $tier0Targets += $Graph.DomainNode
    # Add DCSync-capable domain node
    $tier0Targets += "GROUP:Domain Admins"
    $tier0Targets = @($tier0Targets | Sort-Object -Unique)

    $foundPaths = [System.Collections.Generic.List[object]]::new()

    # BFS queue: each item = @{ NodeId, Path, Depth, EdgeChain }
    $queue = [System.Collections.Generic.Queue[hashtable]]::new()

    # Seed from all non-Tier0 user nodes
    foreach ($nodeId in $Graph.Nodes.Keys) {
        $node = $Graph.Nodes[$nodeId]
        if ($node.NodeType -eq 'User' -and -not $node.IsTier0 -and $node.Properties.Enabled) {
            $queue.Enqueue(@{
                NodeId    = $nodeId
                Path      = @($nodeId)
                Depth     = 0
                EdgeChain = @()
            })
        }
    }

    $visited  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    while ($queue.Count -gt 0 -and $foundPaths.Count -lt $MaxPaths) {
        $current = $queue.Dequeue()

        if ($current.Depth -ge $MaxDepth)    { continue }
        $visitKey = "$($current.NodeId)|$($current.Depth)"
        if (-not $visited.Add($visitKey))    { continue }

        if (-not $adj.ContainsKey($current.NodeId)) { continue }

        foreach ($edge in $adj[$current.NodeId]) {
            $nextId = $edge.TargetId

            # Check if target is Tier 0
            $reachedTier0 = ($nextId -in $tier0Targets) -or
                            ($Graph.Nodes.ContainsKey($nextId) -and $Graph.Nodes[$nextId].IsTier0)

            $newPath      = @($current.Path) + @($nextId)
            $newEdgeChain = @($current.EdgeChain) + @(@{
                SourceId = $current.NodeId
                TargetId = $nextId
                EdgeType = $edge.EdgeType
                Details  = $edge.Details
            })

            if ($reachedTier0) {
                $startNodeId = $newPath[0]
                $startNode   = if ($Graph.Nodes.ContainsKey($startNodeId)) { $Graph.Nodes[$startNodeId] } else { @{ Name = $startNodeId } }

                $foundPaths.Add([PSCustomObject]@{
                    PathId       = "AP-$($foundPaths.Count + 1)"
                    StartNode    = $startNode.Name
                    StartNodeId  = $startNodeId
                    EndNode      = if ($Graph.Nodes.ContainsKey($nextId)) { $Graph.Nodes[$nextId].Name } else { $nextId }
                    PathLength   = $newPath.Count - 1
                    Path         = $newPath
                    EdgeChain    = $newEdgeChain
                    EdgeTypes    = @($newEdgeChain | Select-Object -ExpandProperty EdgeType) -join ' → '
                    Risk         = if ($newPath.Count -le 2) { 'Critical' } elseif ($newPath.Count -le 3) { 'High' } else { 'Medium' }
                })
            }
            else {
                # Only continue if we haven't visited this node path
                if ($nextId -notin $current.Path) {
                    $queue.Enqueue(@{
                        NodeId    = $nextId
                        Path      = $newPath
                        Depth     = $current.Depth + 1
                        EdgeChain = $newEdgeChain
                    })
                }
            }
        }
    }

    $result = $foundPaths.ToArray() | Sort-Object PathLength
    Write-Verbose "Found $($result.Count) attack paths."
    return $result
}

#endregion

#region Graph Summary

function Get-GraphSummary {
    <#
    .SYNOPSIS
        Returns a summary of the attack graph (node/edge counts, Tier 0 exposure).
    .PARAMETER Graph
        Attack graph from Build-AttackGraph.
    .PARAMETER AttackPaths
        Optional: paths from Find-AttackPaths.
    .EXAMPLE
        Get-GraphSummary -Graph $graph -AttackPaths $paths
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Graph,

        [Parameter(Mandatory = $false)]
        [object[]]$AttackPaths = @()
    )

    $nodesByType  = $Graph.Nodes.Values | Group-Object { $_.NodeType }
    $edgesByType  = $Graph.Edges | Group-Object { $_.EdgeType }

    $tier0Nodes   = @($Graph.Nodes.Values | Where-Object { $_.IsTier0 })

    # Nodes that have at least one path to Tier 0
    $nodesWithPaths = @($AttackPaths | Select-Object -ExpandProperty StartNodeId -Unique)

    $summary = [PSCustomObject]@{
        DomainName            = $Graph.DomainName
        TotalNodes            = $Graph.NodeCount
        TotalEdges            = $Graph.EdgeCount
        NodesByType           = $nodesByType | ForEach-Object { [PSCustomObject]@{ Type = $_.Name; Count = $_.Count } }
        EdgesByType           = $edgesByType | ForEach-Object { [PSCustomObject]@{ Type = $_.Name; Count = $_.Count } }
        Tier0NodeCount        = $tier0Nodes.Count
        Tier0Nodes            = $tier0Nodes | Select-Object -ExpandProperty Name
        AttackPathCount       = $AttackPaths.Count
        NodesWithPaths        = $nodesWithPaths.Count
        CriticalPathCount     = @($AttackPaths | Where-Object { $_.Risk -eq 'Critical' }).Count
        HighPathCount         = @($AttackPaths | Where-Object { $_.Risk -eq 'High'     }).Count
        MediumPathCount       = @($AttackPaths | Where-Object { $_.Risk -eq 'Medium'   }).Count
        ShortestPathLength    = if ($AttackPaths.Count -gt 0) { ($AttackPaths | Measure-Object PathLength -Minimum).Minimum } else { 0 }
        GeneratedAt           = $Graph.GeneratedAt
    }

    return $summary
}

#endregion

Export-ModuleMember -Function Build-AttackGraph, Find-AttackPaths, Get-GraphSummary
