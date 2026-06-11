---
created: 2026-06-11T00:00:00Z
branch: audit/secrem02-gateway-fail-closed
author: Fable 5 (Claude Code)
sprint: SECREM-02-followup-remediation
status: active
repo: citrate-inference-gateway
baseline_test_count: 172
---

# citrate-inference-gateway — SECREM-02 Remediation Log

> Coverage matrix: `citrate-security/planset/2026-06-10-followup-remediation.md`.
> Protocol: re-verify → red test → fail-closed fix → suite green → mutation pass.

## Phase 4 — WP 4.2 (logged retroactively; landed 2026-06-10)

| Finding | Sev | Red test(s) | Fix | Suite | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-GATEWAY-04 | Low | local-proxy max_tokens tests | Hard-cap per-request `max_tokens` in local-proxy (`3910437`, merged `f04986d`) | ✓ | — | **FIXED** |

## Phase 5 — WP 5.2 (fail-closed control surfaces + paid-path binding)

| Finding | Sev | Red test(s) | Fix | Suite (≥172?) | Mutation | Disposition |
|---|---|---|---|---|---|---|
| FUA-GATEWAY-01 | High | `open_chat_gate_tests` ×4 (`open_chat_without_dev_profile_is_refused`, bind-loopback matrix) | `resolve_open_chat`: `CITRATE_GATEWAY_OPEN_CHAT=1` mounts the unauthenticated routes ONLY with explicit `CITRATE_GATEWAY_DEV_MODE=1`; otherwise refused with a loud error (`gateway/src/lib.rs`). `main.rs` refuses to start when the active open profile is bound non-loopback (`open_chat_bind_allowed`) | 183 ✓ | M1 (refused→on) killed ×1 | **FIXED** |
| prior 2026-05-31-001 | High | `paid_path::unissued_nonce_rejected_402`, `issued_nonce_is_single_use` | **Challenge-nonce replay ledger**: `x402-axum::ledger::NonceLedger` (capped, TTL-pruned); `make_challenge` records every minted nonce; `run_paid_path` consumes (present + unexpired + single-use) before any chain work; new `X402Error::ChallengeNotIssued` → 402. 4 ledger unit tests; existing paid-path/observability tests converted to the real challenge→pay handshake | 183 ✓ | M2 (skip consume) killed ×2 | **FIXED** |
| FUA-GATEWAY-02 | Med | `provider` tests ×6 (`valid_binding_signature_verifies`, tampered-output / wrong-provider / wrong-model / malformed-sig fail closed, acceptance-policy matrix) | **Result authentication + job binding**: provider may sign `keccak(CITRATE-RESULT-V1 ‖ model_hash ‖ keccak(prompt) ‖ keccak(output))` with its registered key (`signature` field, 65-byte r‖s‖v); present-but-invalid → dispatch failure (failover, no success/escrow release); `CITRATE_GATEWAY_REQUIRE_SIGNED_RESULTS=1` makes the signature mandatory; empty output always a failure (`provider.rs`, `chat.rs::run_dispatch`) | 183 ✓ | M3 (absent-accepted-when-required) killed ×1; M4 (address compare dropped) killed ×3 | **FIXED** (unsigned-allowed mode is the documented pilot trust assumption; flip the env in any paid deployment) |
| FUA-GATEWAY-03 | Low | `keystore::daily_quota_is_atomic_under_concurrency` (64 racing consumes vs quota 16) | Daily-quota read-compare-write now runs under the same per-key `lock_for` mutex the balance RMW uses (`keystore.rs::try_consume`) | 183 ✓ | M5 (lock removed) killed — test failed 5/5 runs | **FIXED** |

## Notes
- Baseline (Phase 0): **172** across 20 suites → post-fix **183** (+11; x402-axum 111→118, gateway lib 105→110 net of moved coverage). Rule-2 ratchet satisfied. Zero failures.
- The nonce ledger is in-memory and single-instance by design (today's topology);
  a multi-instance deploy needs sticky routing or a shared store — documented in
  `ledger.rs`.
- A failed settle burns its challenge nonce (consume-before-settle). Clients
  re-challenge via the 402 they receive; consume-after-settle would have allowed
  concurrent pre-settle double-spend attempts.
- **Live-deploy action (ops):** gateway.citrate.ai currently runs `OPEN_CHAT=1`
  on a public bind (per `GATEWAY_DEPLOY_HANDOFF.md`). On upgrade it will refuse
  that profile — switch it to `build_router_with` (x402) or front it with the
  local-proxy `cgk_` wall.
- Prior x402/gateway findings NOT in this WP's scope, still open per `07_…`:
  -002 (ABI `as_usize` panics), -003 (CSPRNG fail-open fallback), -004
  (unauthenticated batch reads), -006 (revert collapsed to NonceReplayed),
  -007 (placeholder treasury), keystore prod fail-closed guard (005 part b)
  → Phase 6.4 / 7 sweep.
- `cargo-mutants` automation = Phase 8; mutations here were manual revert-and-run.

## Phase 6 — WP 6.4a (prior-audit residuals: -002/-003/-004/-006/-007 + keystore prod guard)

Baseline at start of WP: **301 passed / 0 failed** across the workspace
(post-5.2 tree at `36590ab`). Post-fix: **316 / 0** (+15). All findings
re-verified at the exact sites before any change.

| Finding | Sev | Red test(s) | Fix | Suite (≥301?) | Mutation | Disposition |
|---|---|---|---|---|---|---|
| prior 2026-05-31-002 | Med | `queries::tests::hostile_*` ×4 — confirmed RED (3 × `U256::as_usize` panic in primitive-types, 1 × `64 + len*32` overflow panic at queries.rs:482) | `abi_len_bounded()` — length word checked against the items the actual buffer can hold BEFORE any usize conversion; wired into `decode_address_array`, `decode_bytes32_array`, `decode_provider_info` (the three sites the follow-up report pinned). Error, never panic; mirrors the existing `decode_string_at_offset_word` hardening | 316 ✓ | M1 (bound check removed → `low_u64`) killed ×4 | **FIXED** |
| prior 2026-05-31-003 | Med | `nonce::tests::entropy_failure_fails_closed_no_fallback`, `construction_fails_closed_without_entropy` (red = new fail-closed API; pre-fix code had no failure surface to test — fallback was silent by construction) | Time-seeded SplitMix64 fallback **deleted**. `fill_random` → `Result`; `next_nonce()` returns `NonceEntropyError` (challenge path maps to 500 via `X402Error::Internal`); `NonceSource::new()` panics at boot without entropy (`try_new()` for fallible callers — the layer builder uses it). `tracing::error!` telemetry on every entropy failure. Test-only thread-local failure injection | 316 ✓ | M2 (fail-open: injected failure "succeeds" with deterministic bytes) killed ×2 | **FIXED** |
| prior 2026-05-31-004 | Med | `smoke_wp_03_3::batch_reads_require_submit_time_credentials` (RED: unauth read returned 200, submit had no `read_token`), `smoke_wp_03_4::api_key_batch_reads_bound_to_owning_key` | Reads bound to the submitter: API-key batches require the owning key's bearer (compared SHA-256↔SHA-256, never raw); key-less submits (x402 — and the open-chat dev profile, whose exposure is now bounded by the same token) mint a one-time `brt_` read token returned exactly once in the submit response, SHA-256 at rest (`read_token_hash`, `#[serde(default)]` for old snapshots). Wrong/no credential → 404 byte-identical to unknown-id (no existence oracle) + `gateway_batch_read_denied_total` metric. Pre-6.4a persisted batches (no owner, no token hash) fail closed | 316 ✓ | M3 (`batch_read_authorized` → always true) killed ×2 | **FIXED** |
| prior 2026-05-31-006 | Low | `paid_path::settle_revert_reports_neutral_reason_with_tx_hash` (RED: reason was "nonce replayed") — replaces the pre-6.4a test that pinned the misleading mapping; `observability::settle_revert_fires_on_rejected_with_neutral_reason` | New `X402Error::SettleReverted(tx_hash_hex)` (402): the status=false branch reports **"settle reverted"** neutrally; the 402 body gains a `detail` field carrying the error Display incl. the settle tx hash for on-chain inspection. Receipt-level revert-reason decoding remains a documented follow-on (the receipt object carries no reason) | 316 ✓ | M4 (revert → `NonceReplayed` regression) killed ×2 | **FIXED** |
| prior 2026-05-31-007 | Low | `money_address_tests` ×4 (placeholder in 3 case forms, zero, unset, garbage, real-accepted) — red = new validator; pre-fix the literal was unconditionally wired | Placeholder literal `0x8951…e24b` **removed from the wiring**: `build_router_with` / `build_router_with_auth` now take explicit `wsalt_address` + `treasury` args, validated by `validate_money_address` (rejects unset/garbage/zero/the retired placeholder), panic at startup on failure (fail closed). The literal survives only as `RETIRED_PLACEHOLDER_ADDR`, used to reject itself, and in test mock fixtures. All 8 test call sites updated to explicit non-placeholder addresses | 316 ✓ | M5 (placeholder check removed) killed ×1 | **FIXED** |
| prior 2026-05-31-005 part b | Low (advisory) | `marketplace_store_policy_tests` ×3 (prod+no-keystore refused; dev volatile allowed; path durable) — red = new resolver; pre-fix `open_marketplace_store` only `warn!`'d | `resolve_marketplace_store(keystore_path, dev_mode)` pure resolver (WP 5.2 `resolve_open_chat` pattern; prod = absence of `CITRATE_GATEWAY_DEV_MODE=1`): `Durable` / `VolatileDevAllowed` / `RefusedProdVolatile`. `open_marketplace_store` **panics** ("REFUSING TO START") on the refused arm — money state never volatile in production | 316 ✓ | M6 (refused arm → dev-allowed) killed ×1 | **FIXED** |

### Notes / deviations
- **Red-test deviation:** -003/-007/-005b red tests target fail-closed APIs that
  did not exist pre-fix (the old behavior was *silent*), so their "red" state is
  the absence of the API (compile-fail) rather than a runtime assertion failure.
  -002/-004/-006 red tests were run against the pre-fix tree and confirmed
  failing (panic / 200-instead-of-404 / "nonce replayed").
- **Baseline bookkeeping:** the Phase 5 log row says "183"; that figure counted a
  subset of suites. This WP's like-for-like workspace totals: 301 → 316 (+15 =
  4 ABI + 2 nonce + 4 money-address + 3 store-policy + 2 batch-read tests, net of
  the one replaced paid-path test renamed in place). Zero failures; rule-2
  ratchet satisfied.
- **API changes (callers must update):**
  - `build_router_with(…)` / `build_router_with_auth(…)` gained required
    `wsalt_address: &str, treasury: &str` params.
  - `NonceSource::next_nonce()` now returns `Result<H256, NonceEntropyError>`;
    `NonceSource::try_new()` added; `X402Layer::build()` errors if entropy is
    unavailable.
  - Batch submit responses for key-less payers now include `read_token`
    (one-time); all `GET /v1/batch/{id}[ /output]` calls require the submit
    credential. SDK/chatbot clients polling batches must persist and present it.
- **Live-deploy action (ops):** a marketplace-mode boot without
  `CITRATE_GATEWAY_KEYSTORE_PATH` now refuses to start unless
  `CITRATE_GATEWAY_DEV_MODE=1`. The free-endpoints-only profile is affected too
  (the guard is at store-open time) — set the keystore path in
  `packaging/*.service` before rolling this out.
- **Out of scope, observed:** `payer_api_key_id` stores the plaintext bearer in
  the durable batch record (refund path needs the raw key for
  `settle_batch_refund`); at-rest hashing of that field would require a refund
  redesign — flagged for the Phase 7 sweep. The `0x8951…e24b` literal also remains
  as inert mock-fixture data in test files and x402-axum's #[cfg(test)] helpers.
- Mutation testing was manual revert-and-run (cargo-mutants automation = Phase 8).
  One process note: mutations are now applied only on committed trees after an
  early restore mishap during this WP ate two uncommitted fixes (caught by the
  suite, redone, re-verified).
