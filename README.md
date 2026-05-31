# AD Group Membership — Nesting Inspector

Enumerates the complete **direct and indirect (nested)** group membership for an
Active Directory user, decodes each group's scope and category, and produces:

- a flat **CSV** — the effective-membership list, one row per group, for Entra ID
  mapping and bulk processing;
- a graph-shaped **JSON** — `{ nodes, edges }` consumed by the HTML viewer for
  untangling *how* the nesting is structured.

Built to support an **AD → Entra ID** migration, where the existing
Global / Universal / Domain-Local nested structure must be flattened and understood.

## Layout

```
.
├── .vscode/                  # editor settings + recommended extensions
├── .github/workflows/        # gitleaks secret scan (SARIF → code scanning)
├── Get-ADGroupMembershipGraph.ps1
├── group-membership-viewer.html
├── output/                   # generated CSV/JSON land here (git-ignored)
├── PSScriptAnalyzerSettings.psd1
├── .gitleaks.toml
├── .editorconfig
└── .gitignore
```

## Requirements

- **PowerShell** with the **ActiveDirectory** module (RSAT). The module handles
  ranged retrieval of large groups automatically and exposes `GroupScope` /
  `GroupCategory` directly, avoiding manual `groupType` bitmask decoding.
- A modern browser for the viewer. It loads Cytoscape.js + dagre from CDN, so the
  machine running the viewer needs internet access.

## Usage

Generate the data (run from the project root so output lands in `output/`):

```powershell
.\Get-ADGroupMembershipGraph.ps1 -Identity jbloggs -OutputPath .\output\jbloggs

# multi-domain forest — point at a Global Catalog:
.\Get-ADGroupMembershipGraph.ps1 -Identity jbloggs@corp.example -Server gc01:3268 -OutputPath .\output\jbloggs
```

Then open `group-membership-viewer.html` in a browser and drag the generated
`.json` onto it.

### What gets captured

| Source                | How |
|-----------------------|-----|
| Direct membership     | `user.memberOf` |
| Nested / transitive   | Recursive walk up each group's `memberOf` chain (equivalent to the `1.2.840.113556.1.4.1941` in-chain matching rule, but additionally records the *path*) |
| Primary group         | Reconstructed from `primaryGroupID` + domain SID — stored on neither `member` nor `memberOf` |
| Foreign / unresolved  | Flagged as placeholder nodes rather than crashing the walk |

Circular nesting is handled with a processed-set; depth and a representative
shortest path are derived via BFS from the user over the resulting edge graph.

### Reading the viewer

- **Colour = scope** (Global / Universal / Domain-Local) — this is the
  Entra-conversion signal at a glance.
- **Shape = category** — ellipse for Security, rounded-rectangle for Distribution;
  the user is the diamond root.
- **Click a node** to trace every nesting paths back to the user and dim the rest.
- Scope filters, group search, and a per-node detail flyout (DN / depth / notes).

## Sanity check on first run

Verify against a user you know by hand. The two things most worth eyeballing:

1. the **primary group** (usually Domain Users) appears — the membership most
   homegrown scripts silently miss;
2. the **total count** is roughly what you'd expect. A known user returning far
   fewer groups than reality usually means nesting spans domains and you're hitting
   the GC / domain-local limitation (domain-local groups from *other* domains do
   not resolve over a Global Catalog and show as `unresolved`).

## Troubleshooting

**`The script cannot be run because it contains a '#requires' statement for module 'ActiveDirectory'`**
The ActiveDirectory RSAT feature is not installed. In an elevated PowerShell session:
```powershell
Add-WindowsFeature RSAT-AD-PowerShell          # Windows Server
# or, on Windows 10/11:
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

**`cannot be loaded because running scripts is disabled on this system`**
The execution policy is blocking the script. Run once to allow local scripts:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Or unblock the specific file:
```powershell
Unblock-File .\Get-ADGroupMembershipGraph.ps1
```

**Output files land in the wrong place**
The default output path is relative to `Get-Location` at run time. Either `cd` to the
project root first, or always pass `-OutputPath` explicitly:
```powershell
.\Get-ADGroupMembershipGraph.ps1 -Identity jbloggs -OutputPath .\output\jbloggs
```

**The script appears to hang**
It is walking the group tree — on a large AD with deep nesting this can take several
minutes. A progress bar shows the running count of groups discovered; leave it running.

**Some groups show as `unresolved`**
Expected when using a Global Catalog (`-Server host:3268`) and the membership includes
Domain-Local groups from other domains — these don't resolve over a GC. See the Known
limitation section in [CLAUDE.md](CLAUDE.md) for the full explanation.

**Access denied warnings on specific groups**
The account running the script lacks read access to those group objects. The walk
continues and the groups are flagged rather than crashing. Elevate to a domain admin
or use `-Credential` to supply an account with broader read rights if full coverage is
needed.

## Security note

Generated CSV/JSON contain real usernames, DNs and the group structure of the
directory. `.gitignore` keeps them out of version control, and the gitleaks
workflow guards against committed secrets. Treat the `output/` directory as
sensitive.
