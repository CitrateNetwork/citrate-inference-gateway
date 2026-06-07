---
created: 2026-06-06T05:30:00Z
branch: feat/infer-s4-wpf-durable-balances
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
sprint: INFER-S4-WPF-durable-balances
purpose: retrospective for WP-F slice F1 — making the marketplace API-key balance store durable & crash-atomic (TD-22)
---

# The money store that forgot everything on restart

> TD-22, in one line: in `marketplace` mode the thing that holds buyers' SALT
> balances was a `RwLock<HashMap>` built fresh at every boot. Restart the
> process and every balance — and every in-flight batch's escrow — is gone.
> PR #4 added RocksDB persistence, but only for the local-proxy *quota* store,
> never the balances. "WP-B persistence" was done for the thing that
> rate-limits and not done for the thing that bills money.

## Two ways to "converge" — one of them breaks production

The convergence decision (TD-23) read "fold the balance into the persistent
`KeyRecord`, retire the in-memory store." Taken literally, that means adding
fields to `KeyRecord`. I started to — and stopped, because **bincode is
positional and not self-describing.** Every local-proxy box already on disk has
5-field `KeyRecord`s. Deserialize those with a 7-field struct and bincode runs
off the end of the buffer: `io error: unexpected end`. The fix would 500 every
request on every deployed proxy the moment it shipped.

So "converge" became: **one durable store, balance under an additive `bal:`
namespace**, leaving the existing `record:`/`quota:` bytes untouched. Zero
migration. A `quota_and_balance_namespaces_coexist_across_restart` test pins it:
a quota key and a balance key live in the same DB, each invisible to the other's
read path, both surviving a restart. Same spirit as the decision, none of the
blast radius. The lesson I keep relearning: a serialization format's
capabilities are part of the schema design, not an implementation detail you
discover later.

## Keeping the audited path audited

The keystore comment was blunt: don't refactor the x402-coupled path under a
persistence change. So `ApiKeyStore` grew a backend enum — `Memory` for tests,
`Persistent(RocksDB)` for production — behind a **byte-identical** async API.
`ApiKeyLayer`, x402, and the batch refund path never learned a new type. The
proof isn't an assertion; it's the 51 pre-existing integration tests on that
path passing **unchanged** alongside the new ones (144 total, 0 failed).

Crash-atomicity is the boring-on-purpose part: every balance mutation is a
read-check-deduct under a **per-key lock**, committed with a **synced** RocksDB
write (`set_sync(true)`). The synced put is the single linearization point — a
debit that returns `Ok` has reached disk, so it applies exactly once across a
kill (`debit_then_crash_reload_applies_exactly_once`), and 50 threads racing one
funded key commit exactly `floor(1000/30)=33` debits, never 34, never a lost
update.

## The seam I refuse to paper over

Here's the honest part. The production binary doesn't actually *bill* yet. The
metered `ApiKeyLayer` is wired in `build_router_with_auth` — a test builder —
not in `build_router`, which `main.rs` boots. So F1 makes the store durable and
puts it in production's `AppState`, ready, but "every request debits a durable
balance end-to-end" waits on the metered path going live in the binary (WP-C/D/E).
I could have called WP-F "done" and let that ambiguity ride. Instead the sprint
says it in plain text and the boot path warns loudly if it ever runs the money
store in-memory. A volatile money store is a bug; a volatile money store that's
*silent* is the bug that costs you a buyer.

## State at gate (F1)

- `keystore.rs`: `BalanceRecord` + `BalanceError` + durable `create_balance_key`
  / `get_balance` / `debit_balance` / `refund_balance` (per-key lock, synced).
- `auth.rs`: `ApiKeyStore` backend enum, identical async API; `KeyBacking` u8.
- `lib.rs`: `build_router` → `marketplace_key_store()` (durable when configured,
  fatal if misconfigured, in-memory+warn only in dev).
- Tests: `tests/infer_wpf_durable_balances.rs` (5) + 2 keystore unit tests;
  144 gateway tests pass, 0 fail. Tripwire `scripts/ci/check_durable_money_store.py`.
- Advances TD-22 (full discharge after F2: durable in-flight batch + resume).
