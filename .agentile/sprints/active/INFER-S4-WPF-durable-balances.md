---
name: INFER-S4-WPF-durable-balances
description: WP-F — make the marketplace money store durable & crash-atomic (TD-22). Converge the balance store onto the persistent RocksDB KeyRecord; debit/refund apply exactly once across a restart. Sliced F1 (balances, this sprint) + F2 (in-flight batch resume, next).
created: 2026-06-05
branch: feat/infer-s4-wpf-durable-balances
author: Larry Klosowski (saulbuilds) + Claude (Opus 4.8, 1M context)
status: active
tier: 1
---

# INFER-S4 / WP-F — durable balances + batch persistence (gateway)

> **The live money-loss bug (TD-22):** in `marketplace` mode the API-key
> balance store is **in-memory** (`auth.rs ApiKeyStore`, `RwLock<HashMap>`,
> constructed `ApiKeyStore::new()` at `lib.rs:117,158`). A restart **wipes
> every key balance** and every in-flight batch. PR #4's RocksDB persistence
> covered the `local-proxy` **quota** store only, never balances. So "balances
> survive restart" is **not** done for the thing that bills money.

## Source of truth (link, don't copy — Rule 9)
- **Handoff/WP:** `citrate-labs/handoffs/INFER_GATEWAY_WPS.md` §WP-F (PR #11).
- **Tech debt:** `citrate-federation/.agentile/gtm-spine/TECH_DEBT.md` TD-22 (+ TD-23 convergence).
- **Gate (BDD):** `citrate-federation/.agentile/gtm-spine/features/INFER-S4-persistence-recovery.feature`.
- **Planset:** `.agentile/planset/2026-06-04-gateway-apikey-hardening/PLANSET.md`.

## Convergence decision (TD-23, ratified — lead)
**Converge.** Fold the balance into the persistent RocksDB store rather than
maintaining a second, volatile store. The marketplace money path uses the
durable store; the in-memory `HashMap` backing is retired for production.

## Money-flow (verified at `gateway@f1f738f`)
- `ApiKeyLayer` **debits the full quoted cost up front** (`auth.rs:354`,
  `state.keys.debit(&key_id, price)`), and **refunds** on downstream error
  (`auth.rs:422`, full) or over-estimate (`auth.rs:400`, the difference).
- A **batch** debits its whole escrow up front through the same layer, then
  `process_batch` refunds the errored slots at terminal (`batch.rs:469`).
- `debit`/`refund` hold the write lock through check-and-deduct (atomic vs
  concurrent callers) — but **nothing is durable**.
- **What a restart loses:** every balance (HashMap gone) **and** every
  in-flight `BatchRecord` — including the up-front escrow debit that
  `process_batch` would have refunded. Buyer funds are silently stranded.

## Slicing (Rule 1 — each slice complete; handoff "land one, rebase the other")
- **F1 (this sprint) — durable, crash-atomic balances.** The core of TD-22.
- **F2 (next sprint) — durable in-flight batch + resume.** The harder WAL +
  boot-recovery half. (`ChatCompletionResponse` is `Serialize`-only today —
  F2 must add `Deserialize` to persist slot responses.)

## F1 scope (in)
1. **Extend the persistent `KeyRecord`** (`keystore.rs`) with the marketplace
   money fields — `balance_grains` (`[u8;32]` big-endian), `deposit_address`
   (`[u8;20]`), `backing` (`u8`) — serde-defaulted so existing local-proxy
   records deserialize unchanged.
2. **Crash-atomic durable balance ops** on `PersistentKeyStore`:
   `create_balance_key`, `get_balance_record`, `debit_balance`, `refund_balance`,
   `revoke` — each a **per-key-locked** read-modify-write with a **synced**
   RocksDB put (`WriteOptions::set_sync(true)`) as the single commit point.
3. **Back `ApiKeyStore` with a backend enum** — `Memory(RwLock<HashMap>)` via
   `new()` (tests, unchanged) vs `Persistent(Arc<PersistentKeyStore>)` via
   `open(path)` (production). The async `get`/`debit`/`refund`/`revoke` +
   `create_key*` API is **byte-identical**, so the audited x402 / `ApiKeyLayer`
   / batch paths are untouched.
4. **Wire marketplace boot** (`run_marketplace`) to `ApiKeyStore::open(path)`
   (env `CITRATE_GATEWAY_KEYSTORE_PATH`, `0700`), so balances are durable.
5. Preserve every existing invariant: the RM-B1 / BUYER_WEBAPP-001/002 debit
   bounds, the `0700` keystore dir, and **plaintext bearer never persisted**
   (only `sha256`).

## F1 scope (out → F2 or later)
- In-flight batch persistence + resume (F2).
- Usage metering durability (best-effort by planset; F2/later).
- Full record unification / deleting the `Memory` backend (after F2 lands).

## Acceptance (F1 definition of done)
1. **Exactly-once across restart:** `debit_then_crash_reload_applies_exactly_once`
   — debit, drop+reopen the store, balance reflects the debit once (not zero,
   not twice). Mirrors `keystore.rs::restart_preserves_records_and_daily_quota`.
2. **Balance survives restart;** revoke survives; refund-after-revoke still credits.
3. **No double-debit under concurrency:** N concurrent debits of a funded key
   never overspend; total debited == sum of successes; balance == start − debited.
4. **Bounds preserved:** insufficient-balance debit is rejected and writes nothing.
5. **Security invariants:** on-disk schema holds only `sha256(bearer)`; no plaintext.
6. **API stability:** every existing `auth.rs`/x402/batch test passes unchanged
   (Rule 2 — test count monotone non-decreasing).
7. Marketplace boot opens the durable store; a tripwire guards the bug-class
   (money store constructed in-memory in production).

## Test plan (spec-first → RED → GREEN)
- `gateway/src/keystore.rs` `#[cfg(test)]` — durable balance unit + crash-reload.
- `gateway/tests/infer_wpf_durable_balances.rs` — store-level exactly-once,
  concurrency no-double-debit, restart, bounds, security.
- Confirm RED (methods/fields absent) before implementing.

## Status log (Rule 4)
- 2026-06-05 — Sprint opened in isolated worktree (`feat/infer-s4-wpf-durable-balances`
  off `gateway main@f1f738f`). Money-flow mapped + verified. Convergence ratified.
  F1/F2 slice drawn.
- 2026-06-05 — Wrote failing F1 tests (`tests/infer_wpf_durable_balances.rs`); RED
  (durable API absent). Implemented durable balances in `keystore.rs` (additive
  `bal:` namespace + per-key lock + synced writes) and the `ApiKeyStore` backend
  enum (`Memory`/`Persistent`) with a byte-identical async API. Wired production
  `build_router` to `marketplace_key_store()`. **GREEN: 144 gateway tests pass, 0
  fail** (incl. the 51 pre-existing integration tests on the audited x402 path).
- 2026-06-05 — Tripwire `scripts/ci/check_durable_money_store.py` — validated
  (passes clean, fails when the volatile `ApiKeyStore::new()` is reinjected into
  `build_router`). clippy clean on changed files.
- 2026-06-05 — **F1 gate met.** F2 (durable batch + resume) staged below.

## Acceptance check-off (F1)
1. ✅ `debit_then_crash_reload_applies_exactly_once` (drop+reopen → balance once).
2. ✅ Balance/revoke survive restart; refund-after-revoke credits durably.
3. ✅ `concurrent_debits_never_overspend` — 33/50 of 30-grain debits on a 1000 key
   commit; total == start − Σ successes; durable across restart.
4. ✅ Insufficient debit refused, persists nothing.
5. ✅ Security: `bal:` schema holds only `sha256(bearer)`; namespaces coexist
   (existing local-proxy `record:`/`quota:` deserialize unchanged — additive).
6. ✅ API stability: every pre-existing auth/x402/batch test passes unchanged
   (92→94 lib tests; Rule 2 holds).
7. ✅ Production boot opens the durable store when configured (fatal if it can't
   open; loud-warning in-memory only in dev); CI tripwire guards the bug-class.

## Retrospective (F1)
**The trap I avoided.** The obvious "fold balance into `KeyRecord`" reading of the
convergence decision would have **broken every deployed local-proxy box**: bincode
is positional/non-self-describing, so adding fields to `KeyRecord` makes the
already-persisted records fail to deserialize → 500 on every request after deploy.
The safe converge is an **additive `bal:` namespace** in the same store — one
durable store, balance in it, zero migration. A `quota_and_balance_namespaces_coexist`
test pins that.

**The audited path stayed audited.** TD-23/the keystore comment warned against
refactoring the x402-coupled path. The `ApiKeyStore` backend enum keeps the async
`get`/`debit`/`refund`/`revoke` API byte-identical, so `ApiKeyLayer` + x402 + batch
never changed — proven by the 51 integration tests passing untouched.

**Honest seam.** The production binary's metered `ApiKeyLayer` path isn't wired in
`build_router` yet (only `build_router_with_auth`, a test builder, applies it). So
F1 makes the store durable and wires it into production `AppState`, but the metered
path going live in the binary is downstream WP-C/D/E work. Documented, not hidden.

## F2 — durable in-flight batch + resume (next sprint)
The harder WAL + boot-recovery half: persist `BatchRecord`/`RequestSlot` state so a
mid-batch crash resumes remaining slots (no completed slot re-run) and never strands
the up-front escrow debit. Needs `ChatCompletionResponse: Deserialize` (today
`Serialize`-only, `openai.rs:43`). Chaos test: kill mid-batch repeatedly → balances
reconcile, no buyer loses funds.

## Handoff (post-merge)
- Advance TD-22 (F1 landed; full discharge after F2).
- Manifest: no chain pin change; gateway is a leaf for this WP.
