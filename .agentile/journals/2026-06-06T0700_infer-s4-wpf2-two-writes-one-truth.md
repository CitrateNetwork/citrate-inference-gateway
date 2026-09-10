---
created: 2026-06-06T07:00:00Z
branch: feat/infer-s4-wpf-durable-balances
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
sprint: INFER-S4-WPF-durable-balances
purpose: retrospective for WP-F slice F2 — durable in-flight batches + crash-safe exactly-once settlement
---

# Two writes, one truth

> F1 made balances durable. F2 closes the other half of TD-22: a batch debits
> its whole escrow up front, then refunds the errored slots when it finishes.
> The `BatchStore` was in-memory, so a crash mid-batch lost the record — the
> refund never ran, and the buyer's escrow just… stayed gone.

## The bug isn't "persist the batch" — it's the settlement

The tempting framing is "persist `BatchRecord` to RocksDB and you're done." But
durability of the batch state isn't the hard part. The hard part is that the
terminal refund is **two writes**: credit the buyer's balance, and mark the batch
settled. Those live in different places, and a crash *between* them is the whole
ballgame:

- credit, then crash before the mark → recovery sees an unsettled batch → refunds
  **again**. Double refund; the gateway eats it.
- mark, then crash before the credit → recovery sees a settled batch → skips it.
  The buyer is **never** refunded. Stranded funds — the exact TD-22 failure.

No ordering of two independent writes fixes this. The only fix is making them
**one** write. So `keys` and `batches` share a single `PersistentKeyStore`, and
settlement is a single synced RocksDB `WriteBatch`: balance credit + `batchset:`
marker + terminal snapshot, atomic. Replay it as many times as recovery wants — the
marker makes every call after the first a no-op. Exactly once, by construction, not
by careful sequencing. The test that matters calls `settle_batch_refund` twice and
asserts the balance moved once.

## What I deliberately did NOT do

The feature says "resume the remaining slots." I made `process_batch` resume-safe
(it skips already-`Done` slots), but recovery **refunds** interrupted slots instead
of **re-running** them. That's a real scope decision, and I'm flagging it rather
than letting "resume" quietly mean "refund": re-running inference at boot needs the
full dispatch path wired into recovery and an idempotency story for slots that were
mid-flight to a provider. Refund-on-recovery is money-safe *today* — no buyer ever
loses funds — and the slot-skip groundwork means re-dispatch is a clean follow-on,
not a rewrite. Shipping the safe 80% with the seam named beats shipping the risky
100% under time pressure, especially in code that moves money.

## The smaller landmine

`ChatCompletionResponse` can't `Deserialize` — two of its fields are `&'static
str`. So I persist a **slim** projection (states, quotes, request — not response
bodies). Recovered `Done` slots keep their money accounting but lose their output
text. Acceptable, documented. The alternative (making `object`/`finish_reason`
owned `String`s) is a broader change to a hot type for a recovery-only benefit —
deferred on purpose. Same instinct as F1's "don't widen `KeyRecord`": let the
serialization format's limits shape the schema, don't fight them mid-PR.

## State at gate (F2)

- `keystore.rs`: `settle_batch_refund` (atomic credit + marker + snapshot),
  `mark_batch_settled`, `persist_batch`, `load_batches`, `batch_was_settled`.
- `batch.rs`: slim `PersistedBatch`/`PersistedSlot`; `BatchStore` durable handle +
  `checkpoint` + `recover`; `process_batch` resume-safe + atomic `settle_batch`.
- `auth.rs`/`lib.rs`: `keys` + `batches` share one `PersistentKeyStore`; boot
  recovery runs in `build_router`.
- Tests: `tests/infer_wpf2_batch_settlement.rs` (4) — exactly-once settle, enumerate,
  flag, recovery exactly-once. **148 gateway tests pass, 0 fail.** Tripwire updated.
- TD-22 fully addressed (balances F1 + batches F2).
