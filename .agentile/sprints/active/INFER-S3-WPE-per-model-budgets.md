---
name: INFER-S3-WPE-per-model-budgets
description: WP-E — per-model spend budgets ("5 SALT of llama, unlimited mistral"). An orthogonal, durable sub-ledger enforced in the chat handler (where the model + exact cost are known); the overall-balance debit path is untouched. Cross-model batch attribution staged as E2.
created: 2026-06-06
branch: feat/infer-s3-wpe-per-model-budgets
author: Larry Klosowski (saulbuilds) + Claude (Opus 4.8, 1M context)
status: active
tier: 1
---

# INFER-S3 / WP-E — per-endpoint (per-model) budgets

> Institutions want per-model caps: "5 SALT of llama-3.1-8b, unlimited mistral."
> Today a key has a single `balance_grains` — one app can drain the whole key.

## Source of truth (link, don't copy — Rule 9)
- **Handoff/WP:** `citrate-labs/handoffs/INFER_GATEWAY_WPS.md` §WP-E (PR #11).
- **Tech debt:** closes the INFER-S3 gap; builds on the durable store (TD-22, F1/F2).
- **Gate (BDD):** `citrate-federation/.agentile/gtm-spine/features/INFER-S3-per-endpoint-budgets.feature`.

## The architecture constraint (verified at gateway main)
`PricingStrategy::price_for` **cannot consume the request body** (the layer must
forward it intact), so the `ApiKeyLayer` prices roughly against the *default*
model and debits the **overall balance**; the **chat handler** re-prices exactly
from the parsed body (`req.model`, `quote_chat_request_cost`) and attaches
`ApiKeyCharge`. **The model name is known in the handler, not the layer.** So
per-model enforcement lives in the handler.

## Design — an orthogonal, durable sub-ledger
- **Storage:** a per-model budget is `mbudget:<sha256(key)>:<model> → remaining
  grains` ([u8;32]). **Additive namespace** — NOT a field on `BalanceRecord`
  (bincode is positional; a field-add would break already-persisted `bal:`
  records, same trap as F1). No change to `BalanceRecord` or the `debit`/`refund`
  signatures.
- **Two orthogonal ledgers, both atomic:**
  - **Overall balance** — debited by the layer (rough) + corrected by settle.
    Caps total spend. **Unchanged.**
  - **Per-model budget** — debited by the handler by the *exact* cost. Caps
    per-model spend. A model with no `mbudget:` entry = uncapped.
  A request must pass **both**. Spending 5 SALT of llama reduces both the llama
  budget (5→0) and the overall balance; when the llama budget hits 0, llama 402s
  while mistral + the overall balance still work.
- **Store API (both backends, byte-identical):** `set_model_budget`,
  `get_model_budgets`, `debit_model_budget` (no-op if uncapped; atomic
  check+deduct under the per-key lock), `refund_model_budget` (no-op if uncapped).
  Persistent: `mbudget:` namespace + synced writes. Memory (tests): in `ApiKeyRecord`.
- **Handler wiring (`chat.rs`):** after `actual_cost`, before `run_dispatch`,
  `debit_model_budget(key, req.model, actual_cost)` — `Err` → reject
  `ModelBudgetExceeded` (the layer's overall debit refunds via the error-settle
  path). On `run_dispatch` error after the model debit, `refund_model_budget`
  (the handler knows the model). The over-estimate case needs no model refund —
  the model budget is debited the *exact* cost.
- **Admin CLI:** `citrate-gateway-admin set-model-budget <key> <model> <grains>` +
  `list-model-budgets <key>`.

## Scope (in)
Per-model budget sub-ledger (persistent + memory); atomic debit/refund;
`ModelBudgetExceeded` 402; handler enforcement for `/v1/chat/completions`; admin
CLI; tripwire for the wrong-bucket / split-ledger bug-class.

## Scope (out → E2 / later)
- **Cross-model BATCH attribution** (R2 audit-sensitive): a batch debits its escrow
  up front via the layer (single amount); per-model attribution needs the batch
  escrow flow reworked to debit/refund per model per slot. Staged as **E2**.
- Live-in-the-binary metered path (still WP-C/D — `build_router` doesn't apply the
  `ApiKeyLayer` yet; WP-E is exercised via `build_router_with_auth` + store tests).

## Acceptance (definition of done)
1. **Model budget exhausts independently:** spend the llama budget → further llama
   requests 402 `ModelBudgetExceeded` while mistral (and the overall balance) work.
2. **Refund attribution:** a failed llama request refunds the **llama** budget
   (not the overall, not another model); over-estimate touches only the overall.
3. **No cross-model leakage / no overspend under concurrency:** N concurrent
   debits of one model budget never overspend; other models unaffected.
4. **Uncapped models unaffected:** a key with no budget for model M behaves exactly
   as today (overall balance only).
5. **Durable across restart;** admin CLI sets/inspects; bounds (RM-B1) preserved.
6. **API stability:** every existing auth/x402/batch test passes unchanged (Rule 2).
7. Tripwire guards the bug-class; store-level + handler tests; clippy clean.

## Test plan (spec-first → RED → GREEN)
- `gateway/tests/infer_wpe_model_budgets.rs` — store-level: exhaust-independently,
  refund-to-right-bucket, concurrency-no-overspend, uncapped-passthrough, restart.
- Handler enforcement via the auth test harness.
- Confirm RED (methods absent) before code.

## Status log (Rule 4)
- 2026-06-06 — Sprint opened (worktree off gateway `main@2e5951d`, has F1+F2).
  Architecture verified (model known in handler, not layer). Orthogonal-sub-ledger
  design chosen (additive `mbudget:` namespace; no `BalanceRecord`/debit-signature
  change).
- 2026-06-06 — Spec-first RED → GREEN. `keystore.rs`: `ModelBudgetError` +
  `set/get/debit/refund_model_budget` (`mbudget:<hash>:<model>`, per-key lock +
  synced write). `auth.rs`: `ApiKeyStore` delegates per backend (Memory uses
  `ApiKeyRecord.model_budgets`). `chat.rs`: handler debits the model budget by the
  exact cost (402 `ModelBudgetExceeded` on overflow), refunds it on dispatch error
  (only when actually debited). `error.rs`: `ModelBudgetExceeded` → 402. Admin CLI:
  `set-model-budget` / `list-model-budgets`. Tripwire
  `scripts/ci/check_model_budget_enforced.py` (validated). **155 gateway tests pass,
  0 fail** (148 → 155); clippy clean.
- 2026-06-06 — **WP-E gate met** (single-request). Cross-model BATCH attribution
  staged as E2.

## Acceptance check-off
1. ✅ Model budget exhausts independently — `model_budget_exhausts_independently`
   (llama `Exceeded` while mistral, uncapped, passes); handler returns 402.
2. ✅ Refund attributes to the right bucket — `refund_attributes_to_the_right_model_bucket`;
   handler refunds the model budget only on dispatch error (over-estimate is overall-only).
3. ✅ No overspend under concurrency — `concurrent_model_debits_never_overspend`
   (exactly 30/50 of 10-grain debits on a 300 budget).
4. ✅ Uncapped models unaffected — `uncapped_model_is_passthrough` (no-op, no budget created).
5. ✅ Durable across restart — `model_budget_survives_restart`; admin CLI sets/inspects.
6. ✅ API stability — all pre-existing tests pass unchanged (Rule 2: 148 → 155).
7. ✅ Tripwire guards the bug-class (drop the handler's `debit_model_budget` → CI fails).

## Retrospective
**Let the architecture pick where enforcement lives.** The handoff said "debit()
checks model THEN overall in one critical section." But `price_for` can't consume
the body, so the layer never sees the model — only the handler does. Forcing the
model into `debit()` would have meant the layer buffering+re-emitting the body (a
risky change to the audited x402 path). Instead the per-model cap is an **orthogonal
sub-ledger** debited in the handler (where model + exact cost are known); the overall
balance path is **untouched**. Both invariants still hold (overall never overspent —
layer; per-model never overspent — handler, atomic). Same outcome, a fraction of the
blast radius, audited path unchanged.

**The bincode lesson, a third time.** Per-model budgets are a separate `mbudget:`
namespace, not a field on `BalanceRecord` — adding fields to a bincode struct breaks
already-persisted records. F1, F2, and now E all reached for an additive namespace
for the same reason.

**Refund only what you debited.** The handler tracks `model_debited` so a transient
store error (which skips the debit) never triggers a refund that would over-credit
the model budget. Small bool, real correctness.

## Scope landed vs staged
- **Landed (this PR):** per-model budgets on `/v1/chat/completions` — store + handler
  + admin CLI + tripwire, durable + tested.
- **Staged (E2):** cross-model BATCH attribution (R2 audit-sensitive) — the batch
  debits its escrow up front via the layer (single amount); per-model attribution
  needs the batch escrow flow reworked to debit/refund per model per slot.
- **Seam (shared with F1/WP-E/WP-D):** the metered `ApiKeyLayer` isn't live in the
  production binary yet (only `build_router_with_auth`); WP-E is exercised via that
  harness + store tests. Metered path going live = WP-C/D.

## Next (WP-C, decided)
WP-C signer custody = **KMS/HSM from the start** (lead's call) — confirm provider
(AWS KMS / GCP / etc.) at WP-C kickoff; reuse `x402-axum` `sign_settlement_tx`.

## Next (WP-C, decided)
WP-C signer custody = **KMS/HSM from the start** (lead's call) — confirm provider
(AWS KMS / GCP / etc.) at WP-C kickoff; reuse `x402-axum` `sign_settlement_tx`.
