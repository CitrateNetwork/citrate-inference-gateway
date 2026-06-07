---
created: 2026-06-06T08:30:00Z
branch: feat/infer-s3-wpe-per-model-budgets
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
sprint: INFER-S3-WPE-per-model-budgets
purpose: retrospective for WP-E — per-model spend budgets ("5 SALT of llama, unlimited mistral")
---

# Let the architecture place the check

> WP-E gives a key per-model caps: an institution can say "5 SALT of llama, the
> rest unlimited" so one app can't drain the whole key. The handoff said the
> obvious thing — `debit()` checks the model budget and the overall balance in
> one critical section. I built something different, and the reason is the whole
> point.

## The layer can't see the model

The metered path prices in two stages: the `ApiKeyLayer` debits a *rough* amount
up front, and the chat handler re-prices *exactly* from the parsed body. Why two
stages? Because `PricingStrategy::price_for` **cannot consume the request body** —
the layer has to forward it intact to the handler. So the layer prices against the
*default* model with assumed token counts; it never learns which model the caller
actually asked for. The model name lives only in the handler.

That single fact rules out the handoff's "put it in `debit()`" design. To do that,
the layer would have to buffer the body, parse the model, and re-emit the body
downstream — a real change to the audited x402-coupled path, for a feature that
isn't even live in the production binary yet. Not worth it.

## An orthogonal sub-ledger instead

So the per-model budget became its own thing: a `mbudget:<key>:<model> → remaining`
sub-ledger, debited **in the handler** where the model and the exact cost are known.
The overall-balance path — layer debit, settle refund — never changed. Two ledgers,
each atomic in its own right:

- overall balance: enforced by the layer; caps total spend.
- per-model budget: enforced by the handler; caps per-model spend.

A request must pass both. Spending llama's 5 SALT drops both the llama budget and the
overall balance; when llama hits zero it 402s while mistral and the overall balance
keep working. The handoff's invariant ("model spend ≤ model budget, total ≤ balance")
holds exactly — I just didn't need one critical section spanning two concerns the
architecture keeps apart. Same guarantee, a fraction of the blast radius, and the
audited path is byte-for-byte unchanged (every pre-existing test passes untouched).

## Two details that are easy to get wrong

**Refund only what you debited.** The handler debits the model budget before
dispatch and refunds it if dispatch fails. But a *transient store error* skips the
debit — so I track a `model_debited` bool and only refund when the debit actually
landed. Without it, a backend hiccup followed by a dispatch error would credit back
grains the budget never lost — over-crediting the cap. One bool, real correctness.

**The bincode lesson, for the third time.** The budget is a separate namespace, not
a field on `BalanceRecord`. Adding fields to a bincode-serialized struct breaks every
already-persisted record (positional encoding). F1 (balances), F2 (batches), and now
E all reached for an additive namespace for exactly this reason. It's becoming a
reflex, which is the right outcome.

## State at gate

- `keystore.rs`: `ModelBudgetError` + `set/get/debit/refund_model_budget`
  (`mbudget:` namespace, per-key lock + synced write).
- `auth.rs`: `ApiKeyStore` delegates per backend; `error.rs`: `ModelBudgetExceeded` → 402.
- `chat.rs`: handler debits the model budget by exact cost, refunds on failure.
- Admin CLI: `set-model-budget` / `list-model-budgets`. Tripwire validated.
- 155 gateway tests pass, 0 fail. **Staged (E2):** cross-model BATCH attribution.
