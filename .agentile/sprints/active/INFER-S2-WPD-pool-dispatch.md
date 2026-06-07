---
name: INFER-S2-WPD-pool-dispatch
description: WP-D — gateway-initiated pool dispatch + settlement. Replace the 503 (PoolDispatchUnimplemented) with dispatch_pool_compute → poll JobCompleted/JobFailed → reclaimExpiredJob on timeout. Built on WP-C signer (PR #10) + chain #29. Reclaim primitive done; dispatch+poll+wiring gated.
created: 2026-06-06
branch: feat/infer-s2-wpd-pool-dispatch
author: Larry Klosowski (saulbuilds) + Claude (Opus 4.8, 1M context)
status: active
tier: 1
---

# INFER-S2 / WP-D — gateway-initiated pool dispatch + settlement

> The capstone: when selection chooses a pool, actually dispatch it on-chain,
> poll to completion, return the result, and refund the buyer on timeout. This
> is the 503 → settled-pooled-request path. Built on **WP-C** (the operator
> signer, PR #10) and **chain #29** (settlement + `reclaimExpiredJob`, merged).

## Source of truth (link, don't copy — Rule 9)
- **Handoff:** `citrate-labs/handoffs/INFER_GATEWAY_WPCD_DISPATCH_HANDOFF.md`.
- **Chain surface (merged):** `ComputePool.requestPoolCompute` / `jobs(jobId).status`
  / `JobCompleted`/`JobFailed` / `reclaimExpiredJob` (chain main, #29).
- **Built on:** WP-C `OperatorWallet` (PR #10).

## The wiring point (verified at gateway main)
`chat.rs:271` returns `GatewayError::PoolDispatchUnimplemented(pl.name)` (503) when
`select_dispatch_target` (`selection.rs`) yields `DispatchTarget::Pool(PoolEntry)`.
WP-D replaces that branch with the dispatch path. (The `/v1/batch` pool path is the
same treatment.)

## Design
1. **Dispatch** — `OperatorWallet::dispatch_pool_compute(pool_id, job_spec, max_price,
   payment)` (WP-C): sign + submit `requestPoolCompute`, get the `jobId` (from the
   `ComputeRequested` log / the call return).
2. **Poll** — watch `JobCompleted(jobId,poolId)` / `JobFailed(jobId,poolId)` via
   `eth_getLogs` (cleaner than decoding the `PoolJob` struct, whose dynamic `jobSpec`
   shifts offsets), with a deadline. On `JobCompleted` → return the result; on
   `JobFailed` → the contract already refunded the requester, credit the buyer's key.
3. **Reclaim on timeout** — `OperatorWallet::reclaim_expired_job(jobId)` after
   `JOB_DEADLINE`: the gateway is the `requester`, so it reclaims escrow, then credits
   the buyer's key balance. **Built + anvil-tested in this sprint.**

## Status — what's built vs gated
- ✅ **Reclaim primitive (this sprint):** `encode_reclaim_expired_job` +
  `OperatorWallet::reclaim_expired_job` — sign + submit `reclaimExpiredJob`, nonce-
  serialized, refactored the submit/nonce-resync into `submit_signed` shared with
  dispatch. **Anvil e2e: signs + submits, tx mines, `from == operator`.** Calldata
  vector-tested. (7 signer unit tests, 3 anvil e2e — dispatch, concurrent-nonce, reclaim.)
- ⏳ **Dispatch+poll+result + the `chat.rs` 503-replacement** — the larger half.
  **Gated on:**
  - **WP-C #10 merged** (this branch builds on it).
  - **The KMS custody slice** — `OperatorWallet::from_env` errors until the AWS KMS
    adapter lands (descoped from #10 for the audit). Production can't load a signer
    into `AppState`, so the live dispatch path can't activate until then + the
    **citrate-security custody review** the handoff requires.
  - **The SELL execution backend** — a full pooled-inference e2e (dispatch →
    pool runs the job → `JobCompleted` → result) needs pool members that actually run
    jobs; INFER depends on SELL execution. Until then the poll/reclaim logic is
    testable on anvil against the contract, but not end-to-end-with-inference.

## Acceptance (full WP-D, definition of done)
1. A pooled request dispatches on-chain (no 503); `requestPoolCompute` signed+submitted.
2. `JobCompleted` observed → the buyer receives the result.
3. A timeout → `reclaimExpiredJob` refunds the buyer's key balance; event recorded.
4. Nonce serialized under concurrency; key never plaintext; custody reviewed.
5. Anvil e2e for dispatch + reclaim (done); full inference e2e after SELL.

## Status log (Rule 4)
- 2026-06-06 — Oriented (wiring point `chat.rs:271`; selection `DispatchTarget::Pool`;
  poll via `JobCompleted`/`JobFailed` logs). Built + anvil-tested the **reclaim refund
  primitive**. Remainder (dispatch+poll+result+chat-wiring) staged behind #10 merge +
  the KMS custody slice + SELL execution backend.

## Next
Once #10 merges + the KMS custody slice lands: wire `chat.rs` (and `/v1/batch`) to
dispatch+poll+reclaim, add `eth_getLogs` job-event polling, credit the buyer's key on
`JobFailed`/reclaim, and the full inference e2e once SELL execution is available.
