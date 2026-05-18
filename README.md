---
created: 2026-05-18T04:50:00Z
branch: main
author: monorepo-split
status: active
split-from-monorepo-at: b3ccd5c7
split-from-monorepo-tag: pre-split-v0.4.0
archived-monorepo: https://github.com/CitrateNetwork/citrate-monorepo-archive
agentile-archive: https://github.com/CitrateNetwork/citrate-agentile-archive
---

# citrate-inference-gateway

OpenAI-compatible HTTP gateway over the Citrate compute marketplace. Translates `/v1/chat/completions` and `/v1/batch` into x402-gated `InferenceRouter` / `ComputeMarketplace` dispatches.

## Crates

| Path | Crate | Role |
|---|---|---|
| `gateway/` | `citrate-inference-gateway` | OpenAI-compatible HTTP server + provider dispatch |
| `crates/x402-axum` | `x402-axum` | HTTP 402 Payment Required middleware for axum |

## Chain dependency

This repo consumes `citrate-wallet-core` from `CitrateNetwork/citrate-chain` via an **SSH git dep** (federation-transition interim):

```toml
citrate-wallet-core = { git = "ssh://git@github.com/CitrateNetwork/citrate-chain", branch = "main" }
```

When `citrate-chain` publishes to crates.io after its first audited release, swap to a semver dep.

### Local development

Cargo will use your system's SSH agent. Make sure you have a personal SSH key registered on your GitHub account (org membership grants read access to `citrate-chain`). Then:

```bash
cargo check --workspace
cargo test --workspace
```

### CI

CI uses a repo-scoped deploy key on `citrate-chain` (read-only). The private key is stored as the `CHAIN_DEPLOY_KEY` repo secret and injected into the runner's SSH agent via `webfactory/ssh-agent`.

## Build + run

```bash
# Local devnet
cargo run --bin citrate-inference-gateway -- --rpc-url http://localhost:8545

# Tests
cargo test --workspace --locked
```

## Repository context

Split from the Citrate monorepo on 2026-05-18 via `git filter-repo`, preserving 201 commits of per-file history affecting `gateway/` and `crates/x402-axum/`.

- **Monorepo archive**: https://github.com/CitrateNetwork/citrate-monorepo-archive
- **Agentile archive**: https://github.com/CitrateNetwork/citrate-agentile-archive
- **Chain**: https://github.com/CitrateNetwork/citrate-chain

## Releases

This repo versions independently. Per the CitrateNetwork release policy, every stable release tag requires a re-audit pass.

## License

[MIT](LICENSE).
