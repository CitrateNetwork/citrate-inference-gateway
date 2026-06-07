---
created: 2026-06-06T09:30:00Z
branch: feat/infer-s1-wpc-operator-signer
author: Larry Klosowski (@SaulBuilds) + Claude Opus 4.8 (1M context)
status: active
sprint: INFER-S1-WPC-operator-signer
purpose: retrospective for WP-C — the gateway operator wallet / AWS KMS signer (the INFER-S1 keystone)
---

# The key never leaves

> WP-C gives the gateway a hot wallet that signs pool-dispatch txs. The whole
> point of choosing AWS KMS over an encrypted key file is that the private key
> never exists in the gateway's memory — KMS signs, the gateway assembles. The
> design has to make that physically true, not aspirational.

## Split "build the sighash" from "sign it"

The existing x402 signing did everything in one function with a local secret.
KMS can't work that way: the key is in KMS, and KMS hands back only `(r, s)` over
a 32-byte digest. So the refactor that makes KMS possible is also the one that
makes "the key never leaves" true: a `Signer` trait whose only job is to sign a
hash. The sighash (RLP + keccak) is built outside the signer; the `LocalSigner`
and the `AwsKmsSigner` differ only in *where the ECDSA happens*.

The test that anchors this is `signer_trait_path_is_byte_identical_to_local`: the
signer-agnostic path must produce the exact same EIP-155 bytes as the old local
path. That byte-for-byte equality is the contract the KMS signer must meet, and
it means the anvil e2e (which signs with a `LocalSigner`) genuinely exercises the
production assembly — only the key source is swapped.

## The hard part of KMS isn't the SDK

I expected the AWS SDK to be the work. It wasn't. The fiddly part is that KMS
gives you a DER-encoded signature and *no recovery id*. Ethereum needs `v`. So:
decode the DER (k256 does this), **normalize to low-S** (EIP-2 — KMS can return
either S), and then **recover the id yourself** by trying both 0 and 1 and seeing
which one `ecrecover`s back to the operator address you got from KMS's public key.
All of that is pure logic with no network in it, so it's vector-tested without a
single AWS call. `GetPublicKey` returns an SPKI blob whose trailing 65 bytes are
the uncompressed point — address is just `keccak(point[1..])[12..]`.

## What I could and couldn't prove here

I can't make a live KMS call in this sandbox — there are no AWS credentials, and
there shouldn't be. So I drew the line honestly: the `AwsKmsSigner` *compiles*
(the feature build is verified), its crypto is *vector-tested*, and the full
sign→submit→mine→nonce-serialization path is *proven on a live anvil* with the
`LocalSigner` that yields byte-identical output. The live KMS round-trip and a
funded-testnet run are deploy-gated on the citrate-security custody review the
handoff requires — which is exactly where a hot-wallet key belongs: behind a
review, not behind a green CI check.

## Two custody details

**Feature-gate the blast radius.** The AWS SDK is ~30 crates. Gating it behind
`aws-kms` keeps the default build and the 25-minute CI lean; production turns it
on. The `Signer` trait and `LocalSigner` are always there.

**Fail closed.** `from_env` returns `None` when no KMS key is configured (pool
dispatch simply stays unavailable). But if a key *is* configured and the binary
was built without `aws-kms`, it errors — it must never silently run the
marketplace signer-less, and it must never fall back to a local key. The tripwire
makes the latter a CI failure: `from_env` may not mention `LocalSigner`.

## Postscript — the audit had the last word

I shipped the `AwsKmsSigner` (feature-gated) and called it done. Then the CI audit
caught what I'd waved past: the full AWS SDK transitively pulls a *vulnerable legacy
rustls* (RUSTSEC-2026-0098/0099/0104), and no feature flag removes it. The repo's
policy is "fix don't ignore," and it's right to be — a signing gateway shouldn't carry
a cert-verification CVE because a transitive connector dragged it in. So the SDK
adapter came back out: this slice ships the signer framework + the KMS-agnostic crypto
(DER decode, SPKI→address, recover-id — all k256-tested, no AWS), audit-clean, and the
`aws-sdk-kms` *network client* lands in the security-reviewed custody slice that already
gates the funded deploy. The lesson rhymes with the rest of this work: a green I hadn't
tried to break (here, "it compiles") wasn't the same as done. The audit was the test I
hadn't run.

## State at gate

- `x402-axum`: `Signer` trait + `sign_settlement_tx_with` + `ecrecover`/`recover_id`
  + `LocalSigner`; `SettlementTx` gained `value`. Byte-identical + recovery tests.
- `gateway/signer.rs`: `NonceManager`, `SpendCap`, `OperatorWallet::dispatch_pool_compute`,
  the KMS crypto helpers (`parse_kms_der_signature`, `address_from_spki`), `from_env`
  (fail-closed). Unit + anvil e2e. The `AwsKmsSigner` network adapter is deferred to the
  security-reviewed custody slice (audit-clean build).
- 156 gateway + 112 x402-axum tests pass; tripwire validated; **audit clean**. **WP-D consumes this.**
