# CLAUDE.md

Guidance for working on this repo. Read before making changes.

## What this is

A read-only tooling project for an **AD → Entra ID** migration. It enumerates a
user's complete direct + nested AD group membership and emits two artefacts:

- `Get-ADGroupMembershipGraph.ps1` — PowerShell enumeration tool → flat CSV
  (effective membership, for Entra mapping) + graph JSON (`{nodes, edges}`).
- `group-membership-viewer.html` — Cytoscape.js + dagre viewer that
  ingests the JSON to untangle the nesting (CDN-loaded; needs internet).

See `README.md` for full usage. Scope is **single-user** by design for now.

## Working agreement (standing preferences)

- **Plan before implementing.** Lay out the approach and get agreement before
  writing code. Re-plan if stuck rather than thrashing.
- **Simplicity first · No laziness · Minimal impact.** Smallest change that fully
  solves the problem. No half-done edges, no stubs left behind.
- Before calling anything done, apply the **"would a staff engineer approve?"**
  bar. Demand elegance.
- When a correction reveals a recurring pitfall, **capture it under Lessons below**
  so it isn't repeated next session.

## Conventions

- PowerShell: `Set-StrictMode -Version Latest`, approved verbs only, OTBS
  formatting, 4-space indent. Lint with the bundled `PSScriptAnalyzerSettings.psd1`.
- **The tool is read-only. Never add a directory write/modify operation** without
  an explicit request — it performs no AD writes by design.
- Generated CSV/JSON contain real usernames, DNs and group structure. They are
  **sensitive** and git-ignored. Never commit `output/` contents or relax
  `.gitignore` to let them through.

## Invariants — do not regress these

These are correctness-critical and easy to break:

1. **Primary group** is included — reconstructed from `primaryGroupID` + the
   domain SID, because it lives on neither `member` nor `memberOf`. Most naive
   scripts miss it; this one must not.
2. **Circular nesting** is handled via the processed-set; `-MaxDepth` is a
   belt-and-braces bound, not the cycle guard.
3. **Ranged retrieval** of large groups (>1500 members) is delegated to the
   ActiveDirectory module. Don't switch to raw LDAP without restoring paging.
4. **Foreign / unresolved** principals are flagged as placeholder nodes, never
   allowed to throw and abort the walk.
5. Graph construction and path analysis stay **separate**: recursion builds
   nodes/edges; a BFS from the user derives depth + shortest path afterward.

## Known limitation

Cross-domain: a Global Catalog (`-Server gc:3268`) resolves Universal groups
forest-wide, but **Domain-Local groups from other domains do not resolve over a
GC** and surface as `unresolved`. Correct AD behaviour, not a bug. If membership
genuinely spans domains, the answer is per-domain passes merged — not a hack
around the GC.

## Running / testing

- Real execution needs a domain-joined host with the **ActiveDirectory module
  (RSAT)** and a live directory — i.e. a domain-joined Windows machine, not a generic dev box.
- Day-to-day iteration here is therefore mostly **static + lint** (PSScriptAnalyzer).
  Don't assume you can run the tool end-to-end in every environment.
- No build step and no automated test suite (yet). If adding tests, Pester is the
  natural fit; plan the structure first.

## Settled decisions (don't re-open without reason)

- PowerShell over Python — AD-native, lowest friction on a domain-joined box.
- Recursive `memberOf` walk over the `1.2.840.113556.1.4.1941` in-chain matching
  rule — the walk yields the *path*, which the matching rule flattens away.
- Two outputs split by purpose: CSV = flat effective set; JSON = full edge graph.
- Cytoscape.js + dagre, CDN-loaded (work laptop has internet); colour = scope,
  shape = Security/Distribution.
- AD security groups have no enabled/disabled state — don't add such a flag.

## Lessons

_(Append corrections here as they come up, newest first.)_
