---
created: 2026-04-23T00:00:00Z
last_updated: 2026-07-16
branch: feat/compute-marketplace-buildout
author: saulbuilds
sprint: CM-03
status: active
---

# Citrate Inference Gateway — Operator Runbook

**Audience**: engineers and operators deploying / babysitting an
instance of `citrate-inference-gateway` on a Citrate testnet or
mainnet environment.

This is the single source of truth for day-2 ops. Sprint documents
(`.agentile/planset/compute-marketplace-buildout/CM-03-*`) describe
*why* the gateway exists; this document is about keeping it running.

---

## 1. What the gateway is

The gateway binary picks one of two router builds at boot from
`CITRATE_GATEWAY_MODE` (see `main.rs`):

- **`local-proxy`** (`infer.citrate.ai`) — **production-ready.** A lean
  authenticated passthrough to a local OpenAI-compatible upstream (e.g.
  `llama-server`). `cgk_` Bearer-gated (`local_proxy.rs`), per-key
  per-second rate limit + daily quota, backed by a durable
  **encrypted-at-rest** RocksDB key store (see §1.1). Keys are minted /
  revoked / listed with the `citrate-gateway-admin` CLI (§4.3).
- **`marketplace`** (default — `gateway.citrate.ai`) — the on-chain
  compute-marketplace gateway described by the endpoint table below.
  API-key balances and in-flight batches are now durable and
  crash-atomic (INFER-S4; see §1.1). **Not fully wired: pool dispatch**
  returns 503 (`PoolDispatchUnimplemented`, `chat.rs`) — the pool
  slice-2 gateway-wallet path is unfinished. Individual-provider x402
  dispatch works; pool routing does not.

The marketplace router translates OpenAI-shaped API calls into
dispatched inference jobs on the Citrate compute marketplace.

| Endpoint | Auth | Handled in |
|----------|------|-----------|
| `GET  /health` | — | `health.rs` |
| `GET  /v1/models` | — | `models.rs` |
| `GET  /metrics` | — | `metrics.rs` |
| `POST /v1/chat/completions` | x402 or API key | `chat.rs` |
| `POST /v1/batch` | x402 or API key | `batch.rs` |
| `GET  /v1/batch/{id}` | caller-owned id | `batch.rs` |
| `GET  /v1/batch/{id}/output` | caller-owned id | `batch.rs` |
| `GET  /v1/usage` | API key (Bearer) | `usage.rs` |

Outbound dependencies:

- **Chain RPC** (Citrate testnet / mainnet) — used for ModelRegistry,
  ComputePricingOracle, InferenceRouter reads + X402 settlement tx.
- **Provider HTTPS endpoints** — listed on-chain by
  `InferenceRouter.getProviders(bytes32)` per model hash.
- **Operator wallet** — the gateway signs `settlePayment` calls with
  this key; needs SALT to pay gas.

### 1.1 Durable key/balance store

Both modes persist through a single RocksDB `PersistentKeyStore`
(`keystore.rs`), **not** an in-memory map. Every value is encrypted at
rest with AES-256-GCM-SIV under a per-namespace key derived from a
master key (ENCRYPT-S1); the master is sourced via
`GATEWAY_STORE_KEY_FILE` env → `<keystore>.master.key`. A legacy
plaintext store is refused at boot until migrated with
`citrate-gateway-admin migrate-encrypt`.

- **local-proxy:** the store holds `cgk_` key records + per-key rate /
  daily-quota counters (durable across restart).
- **marketplace:** the same store additively holds API-key
  `balance_grains` and the batch settlement markers. Debit/refund are
  per-key-locked, synced, and crash-atomic; a restart replays batch
  settlement exactly once (INFER-S4 F1 balances + F2 batch resume).
  Only `sha256(bearer)` is persisted, never the plaintext token.

Store path: `CITRATE_GATEWAY_KEYSTORE_PATH` (dir created `0700`).

---

## 2. Configuration

All runtime knobs are environment variables. Default values are for
local devnet — override for testnet / mainnet.

| Variable | Default | Purpose |
|----------|---------|---------|
| `CITRATE_GATEWAY_CHAIN_ID` | `40204` | Citrate testnet chain id |
| `CITRATE_GATEWAY_RPC_URL` | `http://127.0.0.1:8545` | JSON-RPC endpoint |
| `CITRATE_GATEWAY_LISTEN_ADDR` | `127.0.0.1:9800` | HTTP listen socket. Loopback by default (SECREM-01 SVC-5); set `0.0.0.0:9800` for an intentional remote/container bind — logs a warning when bound non-loopback. |
| `CITRATE_GATEWAY_MODEL_REGISTRY` | deployed-addresses default | ModelRegistry contract |
| `CITRATE_GATEWAY_PRICING_ORACLE` | deployed-addresses default | ComputePricingOracle |
| `CITRATE_GATEWAY_INFERENCE_ROUTER` | deployed-addresses default | InferenceRouter |
| `CITRATE_GATEWAY_MODE` | `marketplace` | `local-proxy` or `marketplace` (§1) |
| `CITRATE_GATEWAY_KEYSTORE_PATH` | — | RocksDB key/balance store dir (`0700`); required for the durable store (§1.1) |
| `GATEWAY_STORE_KEY_FILE` | `<keystore>.master.key` | Master key file for at-rest encryption (§1.1) |
| `LOG_FORMAT` | `pretty` | `json` for structured logs |
| `RUST_LOG` | `info,citrate_gateway=debug` | Log filter |

**Not exposed via env yet** (in-code defaults only):
- Operator wallet secret — must be supplied via
  `build_router_with` / `build_router_with_auth` for any binary that
  enables paid endpoints. See `main.rs` for the wiring point.
- Facilitator + wsalt addresses — same, wired at build time.

---

## 3. Deployment checklist

Before you flip traffic to a new gateway:

- [ ] Chain RPC reachable: `curl $CITRATE_GATEWAY_RPC_URL -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' -H 'content-type: application/json'` returns expected chain id
- [ ] Contract addresses match the active deployment (`DEPLOYED_ADDRESSES.md`)
- [ ] Operator wallet has **≥ 10 SALT** for settlement gas (see §6 alert threshold)
- [ ] `GET /health` returns `{"ok":true}` after startup
- [ ] `GET /metrics` returns Prometheus text-exposition with **every**
      metric in §5 listed (even at zero); a missing metric means the
      recorder install failed
- [ ] Prometheus scraper targets `/metrics` with a 10-second interval
      (counters in §5 are low cardinality)
- [ ] Grafana has imported `ops/grafana/gateway-dashboard.json`
- [ ] Alert rules wired for thresholds in §6
- [ ] One synthetic end-to-end test: POST `/v1/chat/completions` with
      a test API key or live x402 client, expect 200 + OpenAI-shape body

---

## 4. Operations

### 4.1 Start / stop

```bash
# Foreground (dev)
cargo run --release --bin citrate-inference-gateway

# Systemd (production) — unit file not shipped in this slice; use:
ExecStart=/usr/local/bin/citrate-inference-gateway
Restart=on-failure
RestartSec=3
EnvironmentFile=/etc/citrate/gateway.env
```

Restart is safe: the key/balance store is durable (§1.1). In-flight
chat completions are lost on SIGTERM (they're synchronous HTTP, no
persistence). In marketplace mode, in-flight batches are persisted;
boot recovery refunds any un-terminal slot to the buyer exactly once
(INFER-S4 F2) rather than losing the escrow.

### 4.2 Health check

`GET /health` stays 200 even when the chain RPC is unreachable —
this is deliberate so load balancers don't flap on transient chain
outages. Check chain reachability separately via `/metrics`
(see "chain unavailable" counter in §5 slice-2 additions).

### 4.3 API key creation (`citrate-gateway-admin` CLI)

The admin CLI ships in the same crate and shares the durable store.
It reads `CITRATE_GATEWAY_KEYSTORE_PATH` and the master key (§1.1).

```bash
# Mint a cgk_ key (prints the plaintext token ONCE)
citrate-gateway-admin create --label alice \
  --quota-rps 5 --daily-requests 10000

# List active + revoked keys (hash prefix + label + quotas)
citrate-gateway-admin list

# Revoke a key (effective on next request)
citrate-gateway-admin revoke cgk_...

# One-time migrate a legacy plaintext store to encrypted-at-rest
citrate-gateway-admin migrate-encrypt
```

Keys minted here are usable immediately by a running `local-proxy`
gateway pointed at the same keystore path.

### 4.4 Key rotation / revocation

- **Revoke**: `citrate-gateway-admin revoke <cgk_id>` marks the key
  revoked; the next request with that key gets 401.
- **Rotate**: mint a new key, inform the user, revoke the old one.
- The store is durable and encrypted at rest, so revocations and
  balances survive rolling restarts (§1.1).

---

## 5. Metrics catalogue

All metrics are counters exposed on `GET /metrics` in Prometheus
text-exposition format. See `gateway/src/metrics.rs` for the
canonical names.

| Metric | Labels | What moves it |
|--------|--------|---------------|
| `gateway_chat_requests_total` | `outcome=success\|error` | Every `/v1/chat/completions` handler exit |
| `gateway_batch_submissions_total` | — | Every accepted `/v1/batch` POST |
| `gateway_api_key_requests_total` | `outcome=funded\|exhausted\|unknown\|revoked` | Every API-key layer decision |
| `gateway_usage_rows_emitted_total` | — | Every successful chat that credited a key |
| `gateway_provider_dispatch_failures_total` | — | Each failover attempt after a provider 5xx / timeout |

Adding a metric requires updating this table AND
`gateway/src/metrics.rs::describe_metrics`. The smoke test
(`tests/smoke_wp_03_6.rs`) enforces that every catalogued metric
appears in the exposition.

---

## 6. Alerts

Alert on log patterns and metric deltas. Recommended thresholds
below assume a 10-second scrape interval and 1-minute alert windows.

### 6.1 Operator wallet running dry (HIGH PRIORITY)

Slice-1 metric doesn't expose operator wallet balance directly.
Approximate via `gateway_chat_requests_total{outcome="error"}` rate
spiking while `gateway_provider_dispatch_failures_total` stays flat
— that's usually a settlement failure, most often insufficient SALT.

Once the slice-2 balance gauge (`gateway_operator_salt_grains`) lands,
alert on:

```
gateway_operator_salt_grains / 1e18 < 10
```

Response: top up the operator wallet from the treasury (see §7.2).

### 6.2 Provider pool collapse

```
rate(gateway_provider_dispatch_failures_total[5m]) > 0.1
```

Response: check
- `InferenceRouter.getProviders(modelHash)` on-chain — are any active?
- Provider endpoints reachable from the gateway host?
- Most recent reputation updates — did a provider get slashed?

### 6.3 API-key abuse

```
rate(gateway_api_key_requests_total{outcome="unknown"}[5m]) > 5
```

Response: someone's fuzzing keys. Check WAF / upstream rate limit.

### 6.4 Batch pipeline stuck

Once slice 2 adds a per-batch age gauge:
```
max(gateway_batch_age_seconds) > 3600
```

For slice 1, check logs for `batch request errored` lines near a
given `batch_id`.

---

## 7. Incident response

### 7.1 Chain RPC unreachable

- `/health` stays 200 (by design — load balancer shouldn't flap).
- Requests to `/v1/chat/completions` return 503 with
  `{"error":{"message":"chain unavailable: ..."}}`.
- Check the configured `CITRATE_GATEWAY_RPC_URL`. Run the same
  `eth_chainId` curl from §3.
- Failover: point `CITRATE_GATEWAY_RPC_URL` at a backup RPC and
  restart.

### 7.2 Operator wallet out of SALT

- Settlement calls fail with `ChainUnavailable` at the x402 layer.
- Top-up procedure (no CLI yet; manual tx):
  1. From treasury wallet, send SALT to the operator address.
  2. Wait 1 block for confirmation.
  3. Next incoming request should settle.
- Slice 2 will auto-withdraw from treasury above the threshold.

### 7.3 Provider mass failure

- Symptom: every `/v1/chat/completions` returns 503
  "all providers failed" or "no providers available for model".
- Check on-chain: `cast call $INFERENCE_ROUTER "getProviders(bytes32)" $MODEL_HASH`.
  If empty, no one's registered for that model.
- If the pool is non-empty but everyone's failing, check provider
  health — could be a correlated network event.

### 7.4 Gateway under-provisioned

- CPU-bound symptoms: latency spikes, 5xx rate climbs.
- Vertical scale first (the gateway is cheap; each request touches
  chain RPC + a provider HTTPS call).
- Horizontal: multiple gateway instances behind a load balancer are
  safe; state is either local-cached (OK to duplicate) or
  on-chain-anchored (settlement nonces are NonceSource-generated
  per process, so duplication is correct).

---

## 8. Log patterns worth watching

Structured JSON logs (`LOG_FORMAT=json`) include trace IDs. Search
patterns:

| Pattern | Meaning |
|---------|---------|
| `"provider dispatch failed, trying next"` | Provider 5xx; failover engaged |
| `"batch request errored"` | One batch slot moved to Errored |
| `"chain unavailable"` | Chain RPC outage or contract revert |
| `"pricing unavailable"` | Oracle call failed; everything 503 |

---

## 9. Pending work (slice references)

**Landed since slice 1** (reflected above):
- Durable, encrypted-at-rest RocksDB store for keys + balances +
  batches (INFER-S4 F1/F2; ENCRYPT-S1). §1.1
- Admin CLI `citrate-gateway-admin` with create / revoke / list /
  migrate-encrypt. §4.3
- `local-proxy` mode (`cgk_` auth, per-key rate limit + daily quota).
  §1

**Still pending** (do not assume these work):
- **Marketplace pool dispatch** — `chat.rs` returns 503
  (`PoolDispatchUnimplemented`); the slice-2 gateway-wallet
  `requestPoolCompute` path is unfinished. Individual-provider x402
  dispatch works.
- SALT → wSALT auto-wrap watcher.
- Operator wallet balance gauge + auto-topup (see §6.1, §7.2).
- Re-dispatch (vs refund) of interrupted batch inference on recovery;
  persisting slot response bodies across restart.
- Slice 3: on-chain `postJob` per batch request; `eth_subscribe`
  event subscription for JobCompleted/JobFailed.

Update this runbook when a slice lands — keep §5 catalogue and §6
alerts as the canonical references.
