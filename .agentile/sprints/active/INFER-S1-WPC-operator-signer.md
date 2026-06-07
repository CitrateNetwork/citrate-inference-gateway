---
name: INFER-S1-WPC-operator-signer
description: WP-C — the gateway operator wallet/signer (the INFER-S1 keystone). AWS KMS custody (key never plaintext), single-writer nonce manager, per-epoch spend cap, requestPoolCompute dispatch. Anvil e2e proves sign+submit+nonce; live KMS + custody review are deploy gates.
created: 2026-06-06
branch: feat/infer-s1-wpc-operator-signer
author: Larry Klosowski (saulbuilds) + Claude (Opus 4.8, 1M context)
status: active
tier: 1
---

# INFER-S1 / WP-C — gateway operator wallet / signer (the keystone)

> `marketplace` mode loads no chain key. Gateway-initiated pool dispatch
> (`requestPoolCompute`) needs a funded, custody-safe signer. This is residual
> risk **R1 (BLOCKER)**. The signer is buildable + testable now; the
> *settlement/refund* half (poll + `reclaimExpiredJob`) is **WP-D**.

## Source of truth (link, don't copy — Rule 9)
- **Handoff:** `citrate-labs/handoffs/INFER_GATEWAY_WPCD_DISPATCH_HANDOFF.md` (WP-C/WP-D).
- **Chain surface:** `ComputePool.requestPoolCompute` (chain main, settlement #29 merged).
- **Custody decision (lead):** **AWS KMS from the start** — no encrypted-file interim.

## Design
- **`Signer` trait** (in `x402-axum/src/sign_tx.rs`): `address()` + async
  `sign_hash() → (recovery_id, r, s)`. The sighash is built here; the signer only
  signs it, so the key never leaves custody. `sign_settlement_tx_with(signer, tx)`
  is signer-agnostic and **byte-identical** to the existing local `sign_settlement_tx`
  (the contract every signer must meet — pinned by a test). `SettlementTx` gained a
  `value` field (settlement = 0; pool dispatch = payment).
- **`AwsKmsSigner`** (gateway, feature `aws-kms`): KMS holds the key. `GetPublicKey`
  → SPKI → operator address; `Sign(digest, ECDSA_SHA_256)` → DER → k256 decodes +
  **low-S normalizes** → `recover_id` derives the EIP-155 `v` against the KMS address.
  AWS deps are **feature-gated** so the default build/CI stays lean.
- **`LocalSigner`** (k256): tests + the anvil e2e only. The tripwire forbids it in
  the production loader.
- **`NonceManager`**: single-writer (mutex), seeds from `eth_getTransactionCount(...,
  "pending")` once, hands out strictly increasing nonces, resyncs from chain on a
  submit failure → no reuse/gap under concurrency.
- **`SpendCap`**: per-epoch wei ceiling (blast-radius bound); `dispatch` counts the
  payment against it → `SpendCapExceeded` (402).
- **`OperatorWallet`**: ties signer + nonce + spend cap + RPC; `dispatch_pool_compute`
  builds calldata, reserves a nonce, signs via the `Signer`, `eth_sendRawTransaction`.
  `from_env` is the **fail-closed** production loader (KMS key configured but
  `aws-kms` not built → error, never run without a signer).

## Acceptance (gate)
1. ✅ Gateway **signs + submits `requestPoolCompute` on anvil**; the tx mines with
   `from == operator` (`infer_wpc_anvil_e2e`).
2. ✅ **Nonce serialization under concurrency** — 5 concurrent dispatches → 5 distinct
   nonces, all mine (no reuse/gap).
3. ✅ Key **never plaintext** in production — KMS custody; `LocalSigner` tests-only;
   tripwire enforces it.
4. ✅ Spend cap bounds per-epoch dispatch; calldata + SPKI→address + DER→(r,s) +
   recover-id all vector-tested (no AWS needed).
5. ✅ Byte-identical signer-agnostic path (KMS == local output).
6. ✅ No regression — 156 gateway + 112 x402-axum tests pass; clippy clean; **audit clean**.

## KMS adapter — implemented via SigV4, audit-clean (2026-06-07)
The first WP-C PR (#10) **descoped** the full AWS SDK because it transitively pulled a
vulnerable legacy rustls (RUSTSEC-2026-0098/0099/0104 in `rustls-webpki 0.101.7`, via
`aws-smithy-http-client`'s `hyper-rustls 0.24` connector) the audit gate denies. This
follow-up **re-introduces the `AwsKmsSigner` without the SDK's HTTP client**: it calls
KMS's JSON API directly with **`aws-sigv4`** request signing + the gateway's existing
**reqwest** (rustls 0.23). Verified: `aws-sdk-kms`/`aws-config`/`rustls-webpki 0.101.7`
are **absent** from the lock; `cargo audit` exits **0**. `from_env` now builds the
`AwsKmsSigner` under the `aws-kms` feature (still fail-closed: configured-but-unbuilt
→ error, never a local-key fallback). Setup + a one-command **live round-trip check**:
`.agentile/runbooks/AWS_KMS_OPERATOR_SIGNER.md`. The funded-deploy step still gates on
the **citrate-security custody review**.

## Honest constraints (documented)
- **Live AWS KMS network signing can't run in CI/sandbox** (no AWS creds). The
  `AwsKmsSigner` compiles (feature build verified) and its crypto (DER decode, low-S,
  SPKI→address, recover-id) is vector-tested; the live KMS round-trip + a funded
  testnet run are **deploy-gated on the citrate-security custody review** the handoff
  requires. Do NOT point at a funded testnet before that review.
- The anvil e2e signs with `LocalSigner` (= anvil's prefunded acct 0); production
  swaps in `AwsKmsSigner`, which yields byte-identical EIP-155 output (proven test).
- **WP-D consumes this:** invoke `dispatch_pool_compute` on a pooled request, poll
  `JobCompleted`/`JobFailed`, and call `reclaimExpiredJob` on timeout (chain #29).
  `build_router` doesn't wire the dispatch path yet — that's WP-D.

## Status log (Rule 4)
- 2026-06-06 — Feasibility verified (aws-sdk-kms builds feature-gated; anvil present;
  reqwest jsonrpc reused). Spec-first: x402-axum `Signer` + byte-identical path +
  recover-id (vector-tested) → gateway nonce/spend-cap/calldata (unit-tested) →
  `AwsKmsSigner` (feature build + DER/SPKI vectors) → **anvil e2e GREEN** (sign+submit
  + nonce serialization). `from_env` fail-closed loader + tripwire (validated).
  **WP-C gate met.**

## Next (WP-D)
Wire `dispatch_pool_compute` into the gateway request path (pooled selection), poll
completion, refund-on-timeout via `reclaimExpiredJob`. Then a funded-testnet run
**after** citrate-security custody review.
