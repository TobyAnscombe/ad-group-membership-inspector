<#
.SYNOPSIS
    Enumerates the complete direct and indirect (nested) security/distribution group
    membership for an Active Directory user, decoding each group's scope and category,
    and emits a flat CSV (effective membership) plus a graph-shaped JSON (for the viewer).

.DESCRIPTION
    Built to support an AD -> Entra ID migration where nested group structures must be
    flattened and understood. It captures every source of membership that a naive
    'memberOf' read misses:

      1. Direct membership          - user.memberOf
      2. Nested / transitive        - recursive walk up each group's memberOf chain
                                       (equivalent to LDAP_MATCHING_RULE_IN_CHAIN
                                       1.2.840.113556.1.4.1941, but additionally yields
                                       the *path*, which the matching rule flattens away)
      3. Primary group              - reconstructed from primaryGroupID + domain SID,
                                       because it is stored on neither member nor memberOf
      4. Foreign / unresolved       - groups that cannot be resolved (e.g. cross-domain)
                                       are emitted as flagged placeholder nodes rather
                                       than crashing the walk

    Circular nesting is handled via a processed-set. Depth and a representative shortest
    path are derived with a breadth-first search over the resulting edge graph, keeping
    graph construction and path analysis cleanly separated.

    Group scope (Global / Universal / DomainLocal) and category (Security / Distribution)
    are read directly from the ActiveDirectory module's friendly properties - these are
    the signals that determine how each object converts in Entra, so they are the heart
    of the output.

.PARAMETER Identity
    The user to enumerate. Accepts sAMAccountName, UPN, DN, or SID.

.PARAMETER Server
    Optional domain controller or Global Catalog (host or host:3268). Point at a GC for
    forest-wide universal-group resolution in a multi-domain forest. Domain-local groups
    from other domains will not resolve via a GC and are flagged accordingly.

.PARAMETER Credential
    Optional alternate credential for the directory queries.

.PARAMETER Format
    CSV, JSON, or Both (default). JSON feeds the Cytoscape viewer; CSV is the flat
    effective-membership artefact for Entra mapping and bulk processing.

.PARAMETER OutputPath
    Output path prefix (without extension). Defaults to .\group-membership-<user>.
    The script appends .csv / .json.

.PARAMETER MaxDepth
    Recursion safety bound on nesting depth. Default 25. The processed-set already
    prevents infinite loops on circular nesting; this is a belt-and-braces guard.

.EXAMPLE
    .\Get-ADGroupMembershipGraph.ps1 -Identity jbloggs

.EXAMPLE
    .\Get-ADGroupMembershipGraph.ps1 -Identity jbloggs@corp.example -Server gc01:3268 -Format Both -OutputPath C:\temp\jbloggs

.NOTES
    Requires the ActiveDirectory module (RSAT). Read-only: performs no directory writes.
#>

#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Identity,

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateSet('CSV', 'JSON', 'Both')]
    [string]$Format = 'Both',

    [string]$OutputPath,

    [ValidateRange(1, 100)]
    [int]$MaxDepth = 25
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Shared splat for every directory call (server / credential are optional) -----------
$adParams = @{}
if ($PSBoundParameters.ContainsKey('Server'))     { $adParams['Server']     = $Server }
if ($PSBoundParameters.ContainsKey('Credential')) { $adParams['Credential'] = $Credential }

# --- State ------------------------------------------------------------------------------
$nodes      = @{}                                                   # SID (or DN if unresolved) -> node
$edges      = [System.Collections.Generic.List[object]]::new()      # member -> group relationships
$processed  = [System.Collections.Generic.HashSet[string]]::new()   # cycle guard, keyed by node id
$groupCount = 0
$stopwatch  = [System.Diagnostics.Stopwatch]::StartNew()

# --- Recursive expansion ----------------------------------------------------------------
# Resolves a group, registers it as a node, then walks its memberOf chain, recording an
# edge (this group -> parent group) for each hop. Returns the node id (SID) so the caller
# can wire up its own edge to this group.
function Expand-Group {
    param(
        [Parameter(Mandatory)][string]$GroupDN,
        [Parameter(Mandatory)][int]$Depth
    )

    try {
        $g = Get-ADGroup -Identity $GroupDN -Properties memberOf, description, mail @adParams
    }
    catch {
        # Unresolved (commonly a foreign/cross-domain principal). Flag it, don't crash.
        if (-not $nodes.ContainsKey($GroupDN)) {
            $nodes[$GroupDN] = [pscustomobject]@{
                id          = $GroupDN
                label       = ($GroupDN -split ',')[0] -replace '^CN='
                type        = 'group'
                scope       = $null
                category    = $null
                dn          = $GroupDN
                description = '<unresolved - possibly foreign/cross-domain>'
                mail        = $null
            }
            $script:groupCount++
            Write-Progress -Activity 'Expanding group membership' -Status "$script:groupCount group(s) found"
        }
        Write-Warning "Could not resolve group: $GroupDN"
        return $GroupDN
    }

    $sid = $g.SID.Value
    if (-not $nodes.ContainsKey($sid)) {
        $nodes[$sid] = [pscustomobject]@{
            id          = $sid
            label       = $g.SamAccountName
            type        = 'group'
            scope       = $g.GroupScope.ToString()       # Global | Universal | DomainLocal
            category    = $g.GroupCategory.ToString()    # Security | Distribution
            dn          = $g.DistinguishedName
            description = $g.Description
            mail        = $g.mail
        }
        $script:groupCount++
        Write-Progress -Activity 'Expanding group membership' -Status "$script:groupCount group(s) found"
    }

    # Walk each group's parents exactly once. Order doesn't matter: the first time we
    # process a group we emit all of its outgoing edges, so the graph ends up complete
    # regardless of which path reached it first.
    if ($processed.Add($sid) -and $Depth -lt $MaxDepth) {
        foreach ($parentDN in @($g.memberOf)) {
            $parentSid = Expand-Group -GroupDN $parentDN -Depth ($Depth + 1)
            $edges.Add([pscustomobject]@{ source = $sid; target = $parentSid; type = 'Nested' })
        }
    }
    return $sid
}

# --- Resolve the user -------------------------------------------------------------------
Write-Verbose "Resolving user '$Identity'..."
$user = Get-ADUser -Identity $Identity -Properties memberOf, primaryGroupID, mail, description @adParams
$userSid = $user.SID.Value

$nodes[$userSid] = [pscustomobject]@{
    id          = $userSid
    label       = $user.SamAccountName
    type        = 'user'
    scope       = $null
    category    = $null
    dn          = $user.DistinguishedName
    description = $user.Description
    mail        = $user.mail
}

# --- Direct memberships -----------------------------------------------------------------
Write-Verbose "Walking direct + nested memberships..."
foreach ($dn in @($user.memberOf)) {
    $gid = Expand-Group -GroupDN $dn -Depth 1
    $edges.Add([pscustomobject]@{ source = $userSid; target = $gid; type = 'Direct' })
}

# --- Primary group (the classic gotcha) -------------------------------------------------
# Stored as a RID in primaryGroupID, not in member/memberOf. Rebuild its SID from the
# user's domain SID + the RID, then resolve and walk it like any other group.
$domainSid  = $userSid -replace '-[^-]+$', ''
$primarySid = '{0}-{1}' -f $domainSid, $user.primaryGroupID
try {
    $pg   = Get-ADGroup -Identity $primarySid @adParams
    $pgid = Expand-Group -GroupDN $pg.DistinguishedName -Depth 1
    $edges.Add([pscustomobject]@{ source = $userSid; target = $pgid; type = 'Primary' })
}
catch {
    Write-Warning "Could not resolve primary group (SID $primarySid)."
}

Write-Progress -Activity 'Expanding group membership' -Completed

# --- Derive depth + representative shortest path via BFS from the user ------------------
$adjacency = @{}
foreach ($e in $edges) {
    if (-not $adjacency.ContainsKey($e.source)) {
        $adjacency[$e.source] = [System.Collections.Generic.List[string]]::new()
    }
    $adjacency[$e.source].Add($e.target)
}

$depthMap = @{ $userSid = 0 }
$pathMap  = @{ $userSid = @($user.SamAccountName) }
$queue    = [System.Collections.Generic.Queue[string]]::new()
$queue.Enqueue($userSid)

while ($queue.Count -gt 0) {
    $current = $queue.Dequeue()
    if (-not $adjacency.ContainsKey($current)) { continue }
    foreach ($next in $adjacency[$current]) {
        if (-not $depthMap.ContainsKey($next)) {
            $depthMap[$next] = $depthMap[$current] + 1
            $label = if ($nodes.ContainsKey($next)) { $nodes[$next].label } else { $next }
            $pathMap[$next]  = $pathMap[$current] + $label
            $queue.Enqueue($next)
        }
    }
}

# --- Classify membership type -----------------------------------------------------------
$directTargets  = @($edges | Where-Object { $_.type -eq 'Direct' }  | Select-Object -ExpandProperty target)
$primaryTargets = @($edges | Where-Object { $_.type -eq 'Primary' } | Select-Object -ExpandProperty target)

function Get-MembershipType {
    param([string]$Sid, [string]$NodeType)
    if ($NodeType -eq 'user')        { return 'Self' }
    if ($primaryTargets -contains $Sid) { return 'Primary' }
    if ($directTargets  -contains $Sid) { return 'Direct' }
    return 'Indirect'
}

# --- Annotate nodes (for JSON) ----------------------------------------------------------
foreach ($sid in @($nodes.Keys)) {
    $n = $nodes[$sid]
    $d = if ($depthMap.ContainsKey($sid)) { $depthMap[$sid] } else { $null }
    Add-Member -InputObject $n -NotePropertyName depth          -NotePropertyValue $d -Force
    Add-Member -InputObject $n -NotePropertyName membershipType -NotePropertyValue (Get-MembershipType -Sid $sid -NodeType $n.type) -Force
}

# --- Build the flat CSV rows (one per effective group) ----------------------------------
$rows = foreach ($sid in $nodes.Keys) {
    $n = $nodes[$sid]
    if ($n.type -eq 'user') { continue }
    [pscustomobject]@{
        User           = $user.SamAccountName
        GroupName      = $n.label
        GroupScope     = $n.scope
        GroupCategory  = $n.category
        MembershipType = Get-MembershipType -Sid $sid -NodeType $n.type
        Depth          = $n.depth
        Path           = ($pathMap[$sid] -join ' -> ')
        GroupSID       = $sid
        GroupDN        = $n.dn
        Description    = $n.description
        Mail           = $n.mail
    }
}
$rows = @($rows) | Sort-Object Depth, GroupName

# --- Resolve output paths ---------------------------------------------------------------
if (-not $OutputPath) {
    $safeName  = $user.SamAccountName -replace '[^\w.-]', '_'
    $OutputPath = Join-Path (Get-Location) "group-membership-$safeName"
}
$csvPath  = "$OutputPath.csv"
$jsonPath = "$OutputPath.json"

$outDir = Split-Path -Path $OutputPath -Parent
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# --- Emit -------------------------------------------------------------------------------
if ($Format -in 'CSV', 'Both') {
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV  written: $csvPath" -ForegroundColor Green
}

if ($Format -in 'JSON', 'Both') {
    $graph = [pscustomobject]@{
        metadata = [pscustomobject]@{
            user        = $user.SamAccountName
            userDN      = $user.DistinguishedName
            generated   = (Get-Date).ToString('o')
            server      = if ($adParams.ContainsKey('Server')) { $adParams['Server'] } else { '(default DC)' }
            totalGroups = $rows.Count
        }
        nodes = @($nodes.Values)
        edges = @($edges)
    }
    $graph | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "JSON written: $jsonPath" -ForegroundColor Green
}

# --- Console summary --------------------------------------------------------------------
$stopwatch.Stop()
$elapsed    = $stopwatch.Elapsed
$elapsedStr = if ($elapsed.TotalMinutes -ge 1) {
    '{0}m {1:D2}s' -f [Math]::Floor($elapsed.TotalMinutes), $elapsed.Seconds
} else {
    '{0:F1}s' -f $elapsed.TotalSeconds
}

Write-Host ""
Write-Host "Effective group membership for '$($user.SamAccountName)'" -ForegroundColor Cyan
Write-Host ("  Total groups : {0}" -f $rows.Count)
Write-Host  "  By membership:"
$rows | Group-Object MembershipType | Sort-Object Name |
    ForEach-Object { Write-Host ("    {0,-9} {1}" -f $_.Name, $_.Count) }
Write-Host  "  By scope:"
$rows | Group-Object GroupScope | Sort-Object Name |
    ForEach-Object { Write-Host ("    {0,-12} {1}" -f $_.Name, $_.Count) }
Write-Host  "  By category:"
$rows | Group-Object GroupCategory | Sort-Object Name |
    ForEach-Object { Write-Host ("    {0,-13} {1}" -f $_.Name, $_.Count) }

$maxDepthSeen = ($rows | Measure-Object -Property Depth -Maximum).Maximum
Write-Host ("  Max nesting depth  : {0}" -f $maxDepthSeen)
Write-Host ("  Elapsed            : {0}" -f $elapsedStr)
