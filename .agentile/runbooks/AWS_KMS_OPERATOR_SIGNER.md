---
created: 2026-06-07T00:00:00Z
branch: feat/infer-s1-wpc-aws-kms-sigv4
author: Larry Klosowski (saulbuilds) + Claude (Opus 4.8, 1M context)
status: active
---

# Runbook — AWS KMS operator signer (INFER-S1 / WP-C)

The gateway signs pool-dispatch txs (`requestPoolCompute`, `reclaimExpiredJob`)
with an operator wallet whose **private key lives only in AWS KMS** — the gateway
sends KMS a 32-byte digest and assembles the EIP-155 signature from KMS's `(r,s)`
+ public key. No plaintext key ever exists in the gateway. The adapter calls KMS
over SigV4 + the gateway's own reqwest (audit-clean — no AWS-SDK rustls).

> **Gate:** do NOT point at a funded chain until **citrate-security** reviews
> custody (the handoff requirement). This runbook gets you to a *validated* signer
> on anvil/dev; the funded-deploy step waits on that review.

## 1. Create the KMS key (asymmetric secp256k1, sign/verify)

```bash
aws kms create-key \
  --key-spec ECC_SECG_P256K1 \
  --key-usage SIGN_VERIFY \
  --description "citrate-gateway operator signer (INFER-S1)" \
  --tags TagKey=app,TagValue=citrate-gateway
# Note the KeyId/Arn from the output, e.g. arn:aws:kms:us-east-1:123456789012:key/abcd...
aws kms create-alias --alias-name alias/citrate-gateway-operator \
  --target-key-id <KeyId>
```

`ECC_SECG_P256K1` is the curve Ethereum uses; `SIGN_VERIFY` + the SDK call uses
`ECDSA_SHA_256` with `MessageType=DIGEST` (we pass the keccak digest directly).

## 2. Grant the gateway's IAM principal `Sign` + `GetPublicKey`

Attach to the gateway's role/user (least privilege — only this key):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Sign", "kms:GetPublicKey"],
    "Resource": "arn:aws:kms:us-east-1:123456789012:key/abcd..."
  }]
}
```

## 3. Configure the gateway (env)

```bash
# AWS auth (env keys for dev; in prod prefer an instance role / IRSA — the
# credential-sourcing hardening is part of the citrate-security review).
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# export AWS_SESSION_TOKEN=...           # if using temporary creds

# Operator signer
export CITRATE_GATEWAY_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/abcd...
export CITRATE_GATEWAY_COMPUTE_POOL=0x<ComputePool address on the target chain>
export CITRATE_GATEWAY_OPERATOR_SPEND_CAP_WEI=1000000000000000000000   # per-epoch blast-radius bound
export CITRATE_GATEWAY_OPERATOR_EPOCH_BLOCKS=300                       # ~epoch window
```

Build the gateway **with the feature** (the AWS deps are feature-gated so the
default build/CI stays lean + audit-clean):

```bash
cargo build -p citrate-inference-gateway --features aws-kms --release
```

## 4. Validate the live round-trip (your one-command check)

```bash
cargo test -p citrate-inference-gateway --features aws-kms \
  --test infer_wpc_kms_live -- --nocapture
```

On success it prints the **operator address** and `✓ live KMS round-trip OK`
(the KMS signature recovers that address). If the env isn't set it SKIPS.

Troubleshooting:
- `load AWS KMS signer` fails → check creds + `kms:GetPublicKey` on the key.
- `KMS sign` fails → check `kms:Sign` + the key is `ECC_SECG_P256K1` SIGN_VERIFY.
- `did not recover operator` → key spec mismatch (must be secp256k1).

## 5. Fund the operator wallet

The operator address (from step 4) needs SALT on the target chain to pay
`requestPoolCompute`'s `msg.value`. Top it up; the per-epoch spend cap
(`CITRATE_GATEWAY_OPERATOR_SPEND_CAP_WEI`) bounds the blast radius.

## 6. Custody review — ✅ SIGNED OFF (2026-06-07)
Custody review **signed off by Larry Klosowski (@SaulBuilds), federation owner /
sole maintainer (= citrate-security authority)** on 2026-06-07, after review of the
SigV4-over-reqwest adapter (gateway PR #12, audit-clean): the key never leaves KMS,
`from_env` is fail-closed, the per-epoch spend cap bounds blast radius, and no
plaintext key path exists (CI tripwire). The operator signer is **cleared to point
at a chain**.

**Standing hardening (track, not blocking the gate):** move credential sourcing to
an instance role / IRSA (over env keys) before production scale; document the
key-rotation procedure; wire low-balance + spend-cap alerting. These are operational
follow-ups, not custody blockers.
