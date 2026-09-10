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
# Note the KeyId/Arn from the output, e.g. arn:aws:kms:us-east-1:<account-id>:key/abcd...
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
    "Resource": "arn:aws:kms:us-east-1:<account-id>:key/abcd..."
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
export CITRATE_GATEWAY_KMS_KEY_ID=arn:aws:kms:us-east-1:<account-id>:key/abcd...
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

---

## Appendix A — DEV/TESTNET encrypted-file signer (no AWS)

For local dev and **testnet dry-runs** you can defer KMS billing and use an
**encrypted V3 keystore** (scrypt + AES-128-CTR — the same format `cast wallet`
writes). It produces byte-identical EIP-155 output to the KMS signer.

> **Mainnet boundary:** this path is testnet-only. `OperatorWallet::from_env`
> gives **KMS precedence** and only builds the encrypted-file signer behind an
> explicit `CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER=1` opt-in (and logs a loud
> warning). The CI tripwire `scripts/ci/check_no_plaintext_operator_key.py`
> keeps a plaintext key path out of production. Do **not** set
> `CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER=1` on a mainnet deploy.

### A.1 Generate the operator keystore + print the address to fund

```bash
echo "a-strong-passphrase" > /run/operator.pw      # keep off argv/history
cargo run -p citrate-inference-gateway --bin citrate-gateway-admin -- \
  --keystore /tmp/unused \
  operator-keygen --out ./operator.keystore.json --password-file /run/operator.pw
# → prints "Operator address (fund this on testnet): 0x…"  (stdout = the address)
```

### A.2 Configure the gateway (env)

```bash
export CITRATE_GATEWAY_OPERATOR_KEYSTORE=./operator.keystore.json
export CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD_FILE=/run/operator.pw
export CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER=1            # testnet opt-in (NEVER mainnet)
export CITRATE_GATEWAY_COMPUTE_POOL=0x8b36c15552394ce44173a29d054dc5ca482e65d3
export CITRATE_GATEWAY_OPERATOR_SPEND_CAP_WEI=1000000000000000000   # 1 SALT/epoch
# (leave CITRATE_GATEWAY_KMS_KEY_ID unset — KMS takes precedence if set)
```

### A.3 Fund the operator

Send SALT to the address from A.1 (covers `requestPoolCompute`'s `msg.value`
plus gas). On testnet, fund from the faucet key in `.env.testnet`.

### A.4 Dry-run a pool dispatch

`requestPoolCompute` requires an **active pool with `memberCount >= minProviders`**
and `msg.value >= pricePerUnit`. If none exists yet, create one + join it
(`createPool` then `joinPool` with `MIN_STAKE_PER_GPU` = 10 SALT/GPU), then:

```bash
cargo run -p citrate-inference-gateway --bin citrate-gateway-admin -- \
  --keystore /tmp/unused \
  operator-dispatch \
    --rpc https://rpc.citrate.ai --chain-id 40204 \
    --pool 0x8b36c15552394ce44173a29d054dc5ca482e65d3 \
    --keystore ./operator.keystore.json --password-file /run/operator.pw \
    --pool-id 0 --payment-wei 1000000000000000 --max-price-wei 1000000000000000 \
    --job-spec "infer-dryrun:llama-3.1-8b"
# → prints the operator address + the submitted tx hash (stdout = the hash)
```

### A.5 Worked testnet evidence (2026-06-07, chain 40204)

Run end-to-end against the live testnet ComputePool
(`0x8b36…65d3`), operator key held only in an encrypted keystore:

| step | tx | result |
|------|----|--------|
| createPool `infer-dryrun` (minProviders 1, price 0.001 SALT) | `0xf95dac85…cc9427` | poolId **0**, Active |
| joinPool(0, 1 GPU) stake 10 SALT | `0x84643e0a…d62928` | memberCount 1, totalGPUs 1 |
| **gateway operator-dispatch → requestPoolCompute** | `0xc6880093…be3545` | **status 1**, `ComputeRequested(pool=0, job=0, requester=operator, 0.001 SALT)` |

The dispatch tx's `from` and the `ComputeRequested.requester` are the
encrypted-file operator EOA, and the operator nonce advanced 0 → 1 — proving the
gateway's non-KMS custody path signs + lands a real pool dispatch on chain.

### A.6 Migrating to KMS later

When AWS billing is ready, follow §§1–4 above and set
`CITRATE_GATEWAY_KMS_KEY_ID`. KMS takes precedence automatically; drop
`CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER` and the keystore env. No code change — the
`Signer` output is byte-identical, so nonce/spend-cap/dispatch behaviour is
unchanged.
