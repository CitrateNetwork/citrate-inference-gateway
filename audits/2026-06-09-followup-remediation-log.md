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
