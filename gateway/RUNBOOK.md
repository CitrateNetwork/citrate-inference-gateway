---
created: 2026-04-23T00:00:00Z
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

The gateway is a stateless HTTP façade that translates OpenAI-shaped
API calls into dispatched inference jobs on the Citrate compute
marketplace. It does not hold long-lived state beyond in-memory
caches (batch store, usage store, API-key balances — all RocksDB-
backed in a later slice).

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

The binary is stateless; restart is safe. In-flight chat completions
are lost on SIGTERM (they're synchronous HTTP, no persistence). Batch
runs that haven't reached terminal state are lost (slice 2 adds
RocksDB durability).

### 4.2 Health check

`GET /health` stays 200 even when the chain RPC is unreachable —
this is deliberate so load balancers don't flap on transient chain
outages. Check chain reachability separately via `/metrics`
(see "chain unavailable" counter in §5 slice-2 additions).

### 4.3 API key creation (slice 1 admin surface)

Until the `citrate-gateway-admin` CLI lands (slice 2), keys are minted
by linking the `auth::create_key` function. For testing and internal
pilots, a small helper binary pointing at the same in-process store
is the supported path. See `gateway/src/auth.rs::create_key`.

### 4.4 Key rotation / revocation

- **Revoke**: `ApiKeyStore::revoke(key_id)` flips the `revoked` bit;
  next request with that key gets 401.
- **Rotate**: mint a new key, inform the user, revoke the old one.
- In slice 1 (in-memory), rotation is tied to the gateway process
  lifetime. Rolling restarts wipe the store. Do not deploy slice 1
  to production unless acceptable.

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

This runbook reflects **WP-03.6 slice 1** — the set of endpoints and
behaviours live as of commit 786e6423+. The CM-03 sprint file tracks
the deferred items:

- Slice 2: RocksDB persistence for batches, keys, usage
- Slice 2: Admin CLI `citrate-gateway-admin` with create/revoke/list
- Slice 2: SALT → wSALT auto-wrap watcher
- Slice 2: Operator wallet balance gauge + auto-topup
- Slice 3: On-chain `postJob` per batch request
- Slice 3: `eth_subscribe` event subscription for JobCompleted/JobFailed

Update this runbook when a slice lands — keep §5 catalogue and §6
alerts as the canonical references.
