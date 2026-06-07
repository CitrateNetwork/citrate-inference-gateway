---
created: 2026-06-07T10:00:00Z
branch: feat/infer-s1-wpc-encrypted-file-signer
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
sprint: INFER-S1-WPC-operator-signer
purpose: retrospective for the DEV/TESTNET encrypted-file signer + the first live testnet pool dispatch
---

# The testnet key with a mainnet fence

> WP-C shipped the KMS signer and the custody sign-off. But standing up KMS
> billing to run *one testnet dry-run* is the wrong order of operations. We
> wanted to dispatch a pool job on chain 40204 today, not next month. So we
> added a second custody path — an encrypted V3 keystore — without weakening the
> rule that mainnet must be KMS.

## The whole risk is one env var

An encrypted key file is a plaintext key the moment you decrypt it. The danger
isn't the file; it's that `from_env` could quietly load one in production. So the
fence isn't "don't write a LocalSigner" — it's three things stacked:

1. **Precedence.** If `CITRATE_GATEWAY_KMS_KEY_ID` is set, KMS wins, full stop.
   The encrypted-file branch is only reachable when no KMS key is configured.
2. **An explicit, loud opt-in.** The keystore branch refuses to build unless
   `CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER=1` is set, and when it does build it logs
   a warning naming the operator address and the words "do NOT use on mainnet."
   You cannot get here by forgetting to set something — only by setting it.
3. **The tripwire that was already there.** `check_no_plaintext_operator_key.py`
   still passes: `from_env` constructs no `LocalSigner` literal. The
   `EncryptedFileSigner` wraps one *internally* (after a scrypt decrypt), but the
   production-custody decision in `from_env` never names it.

The lesson I keep relearning: a guard that lives in code review is a wish. A
guard that fails the build (tripwire) or fails closed at startup (the opt-in
error) is a fact. We have both, so the testnet convenience can't silently become
a mainnet liability.

## RED → GREEN, including the guard itself

The tests don't just prove the signer signs. `from_env_fails_closed_without_optin_then_builds_with_it`
asserts the *refusal* first — keystore configured, opt-in absent → error — and
only then the success path. The fence is a tested behaviour, not a comment.
The anvil e2e proves the encrypted-file signer lands `requestPoolCompute` with
`from == operator`, byte-identical to what KMS would have produced.

## The dispatch that wasn't there to dispatch to

The interesting failure was discovering `nextPoolId == 0` on testnet: the
ComputePool was deployed but no pool existed, so *any* dispatch would revert on
`poolExists`. A dry-run that mines-with-revert proves you can sign and submit,
but it doesn't prove the path works. So the honest dry-run meant standing up the
world the contract expects: `createPool` (minProviders 1, price 0.001 SALT) →
`joinPool` with the 10-SALT-per-GPU stake → *then* dispatch. Reading the
contract's `require`s told me exactly what state to build; guessing would have
burned an afternoon on reverts.

The payoff was unambiguous: chain 40204, status 1, `ComputeRequested(pool=0,
job=0, requester=operator, 0.001 SALT)`, operator nonce 0 → 1. The gateway's
non-KMS custody path signed and landed a real pool dispatch. The migration to
KMS later is a no-op for everything downstream — the `Signer` output is
identical, so nonces, the spend cap, and the dispatch encoding don't know or
care which custody backed the signature. That's the point of having split
"build the sighash" from "sign it" back in the first WP-C: today it let us swap
the *custody* without touching the *wallet*.

## What I'd carry forward

- When you add a convenience path next to a security-critical one, write the
  test that proves the convenience *can't reach* the critical context — before
  the test that proves the convenience works.
- "Dry-run on testnet" usually means "first build the on-chain preconditions the
  contract asserts." Read the `require`s; they're the setup script.
