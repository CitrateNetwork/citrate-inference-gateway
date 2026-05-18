---
created: 2026-05-18T16:00:00Z
branch: main
author: monorepo-split / PSL-13
status: active
---

# Audit Tier — `citrate-inference-gateway`

**Classification**: **Tier 1 — full audit** before first stable (`v1.0.0`) release tag.

## Rationale

x402 payment middleware + provider dispatch. Payment-flow + supply-chain audit required.

## What this means concretely

- **Full code audit** by an external security firm covering: cryptographic primitives, key handling, attack surface, dependency tree (cargo audit + npm audit + pip audit), build supply chain, CI/CD pipeline integrity.
- **No stable release tag** without a written audit attestation from the firm referencing the exact commit SHA.
- **Prerelease tags** (`v0.x.y-rc.N`) may ship without audit but MUST carry a `prerelease: true` flag on the GitHub Release and a clear warning in the release notes.
- **Re-audit cadence**: every major version (`v1.0.0`, `v2.0.0`, ...) AND any change that materially expands attack surface (new precompile, new signing primitive, new external API).

## Decision authority

Per **D6** of the May 2026 federation-split decisions, every repo audits before its first stable release. This document classifies what "audit" means for this specific repo.

Tier changes require: (a) commit to this file explaining the change, AND (b) sign-off from the operator listed in this repo's CODEOWNERS file (when present) or from the federation lead.

## See also

- `POST_SPLIT_PUNCH_LIST.md` in the [monorepo archive](https://github.com/CitrateNetwork/citrate-monorepo-archive) — PSL-13 is the source of this file.
- Federation-wide audit posture sweep — in progress; see the archive's CATALOG.

