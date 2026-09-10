---
created: 2026-05-19T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.7 (1M context)
status: active
repo: citrate-inference-gateway
tier: T1
---

# Agent Entry — citrate-inference-gateway

> **Lightweight subset.** This file points back to the canonical
> agentile framework lineage. Start here whenever you (human or AI)
> are working in **citrate-inference-gateway**.

## What this repo is

Rust inference gateway. External boundary for inference requests.

Repo tier: **T1** — see scope definitions in
[`audits/2026-05/2026-05-19-federation-split-audit/01_SCOPE.md`](../../citrate-agentile-archive/audits/2026-05/2026-05-19-federation-split-audit/01_SCOPE.md)
in the archive.

## What to read, in order

1. **This file** (you're here).
2. **Federation control plane** — [`citrate-federation/agentile/AGENT_ENTRY.md`](https://github.com/CitrateNetwork/citrate-federation/blob/main/agentile/AGENT_ENTRY.md). The active control-plane entry.
3. **Active sprint** — [`citrate-federation/agentile/CURRENT.md`](https://github.com/CitrateNetwork/citrate-federation/blob/main/agentile/CURRENT.md). What is the federation working on right now?
4. **Core rules** — [`citrate-federation/agentile/rules/CORE_RULES.md`](https://github.com/CitrateNetwork/citrate-federation/blob/main/agentile/rules/CORE_RULES.md). Non-negotiables across the federation.
5. **Pre-split historical context** — [`citrate-agentile-archive`](https://github.com/CitrateNetwork/citrate-agentile-archive). Read **only** when investigating the May-2026 monorepo split or earlier history.
6. **Org defaults (SECURITY, CoC, AUDIT_POSTURE)** — [`CitrateNetwork/.github`](https://github.com/CitrateNetwork/.github).

## Audit lineage

This repo participates in the federation-wide audit cadence captured in
[`citrate-agentile-archive/audits/AUDIT_INDEX.md`](https://github.com/CitrateNetwork/citrate-agentile-archive/blob/main/audits/AUDIT_INDEX.md).

The **current federation audit** is:
- [`audits/2026-05/2026-05-19-federation-split-audit/`](https://github.com/CitrateNetwork/citrate-agentile-archive/tree/main/audits/2026-05/2026-05-19-federation-split-audit)
- This repo's slice: [`per-repo/citrate-inference-gateway/`](https://github.com/CitrateNetwork/citrate-agentile-archive/tree/main/audits/2026-05/2026-05-19-federation-split-audit/per-repo/citrate-inference-gateway)

When a TOB plugin sweep or compliance crosswalk produces findings here,
they are filed under that per-repo folder in the archive, **not** in
this `.agentile/` directory. This file stays a stable, lightweight
pointer.

## What lives here, locally

| Path                          | Purpose                                                       |
|-------------------------------|---------------------------------------------------------------|
| `.agentile/AGENT_ENTRY.md`    | This file — entry point.                                       |
| `.agentile/audits/` (future)  | Local audit notes that never need to live in the archive.      |
| `.agentile/sprints/` (future) | Sprints scoped to this repo only.                              |
| `.agentile/adrs/` (future)    | Repo-local architectural decisions.                            |

A repo-scoped audit lives **here**. A federation-wide audit lives in the
archive. The dividing line is: if the audit touches multiple repos, it
goes in the archive; if it's confined to this repo's internals, it can
live here.

## Cross-repo references

- **Manifest pin**: `manifest.toml` in [`citrate-federation`](https://github.com/CitrateNetwork/citrate-federation)
  is the canonical truth for which rev of this repo the federation is
  pinned to.
- **Org policy**: [`CitrateNetwork/.github`](https://github.com/CitrateNetwork/.github) holds
  org-wide SECURITY.md / CONTRIBUTING / AUDIT_POSTURE.md.

## Status

This file is created/regenerated when:
1. A new federation audit opens (current: 2026-05-19).
2. The repo's tier changes.
3. The agentile framework conventions change.

Any other change should go to a sibling file in `.agentile/`, not here.
