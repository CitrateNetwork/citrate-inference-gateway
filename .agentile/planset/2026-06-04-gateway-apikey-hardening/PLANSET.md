---
created: 2026-06-04T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.8 (1M context)
status: active
repo: citrate-inference-gateway
tier: T1
sprint: gateway-apikey-hardening
---

# PLANSET — Secure `infer.citrate.ai` with an API-key gateway (local-proxy mode)

## The problem (verified live 2026-06-04)

`https://infer.citrate.ai` is **fully open**. An unauthenticated
`POST /v1/chat/completions` returns a real model completion — anyone on the
internet can consume the GPU for free, uncapped. Evidence:

```
$ curl -s -X POST https://infer.citrate.ai/v1/chat/completions \
    -H 'content-type: application/json' \
    --data '{"model":"gemma-4-E4B-it-Q4_K_M","messages":[{"role":"user","content":"say OK"}],"max_tokens":5}'
{"choices":[{"message":{"role":"assistant","content":"OK"}}], "usage":{"total_tokens":20}, ...}   # 200, no key
```

## Current state (what's deployed vs what's in this repo)

- **Live:** `infer.citrate.ai` is a resident **`llama-server`** on `127.0.0.1:8081`
  fronted by **Caddy** (TLS). No auth, no rate limit, no metering.
- **This repo's binary (`gateway/src/main.rs`)** boots the **open** router:
  `build_router(config)` — auth is NOT wired in `main`.
- **But the hardened key machinery already exists** and is the part worth reusing:
  - `gateway/src/auth.rs` — `ApiKeyStore`, `ApiKeyLayer`, `create_key*`
    (`cgk_<uuid>` tokens), **stored only as `sha256(key_id)`** (no plaintext at
    rest), atomic debit, `revoke`, and `Authorization` redaction from logs
    (`SetSensitiveRequestHeadersLayer`).
  - `build_router_with_auth(...)` wires `ApiKeyLayer` **outside** an `X402Layer`.
  - `rocksdb = "0.22"` and `sled = "0.34"` are **already** workspace deps.
- **Architectural mismatch to know:** `gateway/src/provider.rs` dispatches to
  **on-chain marketplace providers' `/infer`** endpoint (a custom protocol via
  `InferenceRouter`/`ComputeMarketplace`). It does **not** speak OpenAI to a local
  llama-server. So the full gateway is a *marketplace product*, not a proxy for the
  single resident model.

## Decision (and why)

**Ship a lean "local-proxy" mode that reuses `auth.rs` to put an API-key wall in
front of the existing llama-server — do NOT stand up the on-chain marketplace /
x402 path to protect one model.**

Rationale:
- The security goal is "authenticate + meter access to one resident OpenAI
  endpoint." The marketplace dispatch (chain RPC, contracts, x402 settlement) is
  unnecessary coupling and a **Tier-1 audit surface** we shouldn't drag into a
  security fix.
- The valuable, already-hardened asset is the **key model** (hashed-at-rest,
  revocation, redaction, atomic debit). We keep that and drop the chain/x402.
- Smaller attack surface, faster to ship, simpler to operate.

The full marketplace gateway (`build_router_with_auth` + x402) remains the future
evolution and ships later **behind its Tier-1 audit** — out of scope here.

## Target topology

```
client (chatbot / explorer server) ──HTTPS──► Caddy (TLS, infer.citrate.ai)
                                                  │  forwards Authorization
                                                  ▼
                                   gateway local-proxy (127.0.0.1:9800)
                                     • ApiKeyLayer  (cgk_ bearer, hashed)
                                     • per-key rate limit + quota
                                     • OpenAI passthrough (SSE-preserving)
                                                  │
                                                  ▼
                                   llama-server (127.0.0.1:8081)   [unchanged]
```

`/health` stays open. Everything under `/v1/*` requires a valid `cgk_` key.

## Key-distribution model (two tiers — important)

1. **Gateway keys (`cgk_…`) are service-to-service, server-side only.** The
   chatbot and the explorer each hold **one** gateway key in their **server** env
   (`CITRATE_GATEWAY_API_KEY`). They are never exposed to browsers.
2. **End-users get *app* keys, not gateway keys.** The explorer already issues
   per-user keys + rate limits for `/api/v1` and `/api/mcp`; `/api/chat` gates the
   user with their app key, then calls the gateway with the server-side gateway
   key. The GPU is only ever reached through an authenticated, metered app backend.

## Work packages

- **WP-1 — Local-proxy router + OpenAI passthrough.** Add
  `build_local_proxy_router(store, upstream_url)` that mounts `ApiKeyLayer` (no
  `X402Layer`) over a passthrough handler forwarding `/v1/chat/completions`,
  `/v1/completions`, `/v1/models` to `CITRATE_GATEWAY_UPSTREAM_URL`. **Preserve
  SSE streaming** (stream the body through; don't buffer). Keep `/health` free.
  Reuse the existing `SetSensitiveRequestHeadersLayer` + `TraceLayer`.
- **WP-2 — Persistent key store (RocksDB).** Back `ApiKeyStore` with RocksDB
  (dep already present): load all records on boot, persist on create/revoke/debit.
  Continue keying by `sha256(key_id)` (records hold no plaintext). Atomic,
  crash-safe debit. Restart must preserve keys + balances. File perms `0600`.
- **WP-3 — Admin provisioning surface.** A `citrate-gateway-admin` binary:
  `create --label <l> [--quota-rps N] [--daily-tokens N]` (prints the plaintext
  `cgk_…` **once**), `revoke <id>`, `list`, `show <id>`. Operates directly on the
  RocksDB store; local/SSH-only, no network exposure. (An admin HTTP API on a
  loopback-only port behind an admin token is an acceptable alternative.)
- **WP-4 — Per-key rate limit + quota.** Independent of balance (the local model
  isn't x402-billed): enforce a per-key **requests/sec** and a **daily token (or
  request) quota**; return `429` with `Retry-After` on exceed. Counters in the
  keystore; reset daily.
- **WP-5 — Wire `main.rs`.** `CITRATE_GATEWAY_MODE=local-proxy` selects
  `build_local_proxy_router`; new env: `CITRATE_GATEWAY_UPSTREAM_URL`
  (`http://127.0.0.1:8081`), `CITRATE_GATEWAY_KEYSTORE_PATH` (RocksDB dir),
  `CITRATE_GATEWAY_LISTEN_ADDR` (`127.0.0.1:9800`). The default mode is unchanged.
- **WP-6 — Deploy + cutover.** systemd unit for the proxy on `127.0.0.1:9800`;
  flip the Caddy upstream for `infer.citrate.ai` from `:8081` → `:9800` (Caddy must
  forward the `Authorization` header; it already forwards CORS + 300s timeouts).
  Verify unauth → `401`, keyed → `200`.
- **WP-7 — Client wiring (two-tier).** Mint a server-side `cgk_` for the chatbot
  and one for the explorer; set `CITRATE_GATEWAY_API_KEY` in each app's **prod**
  env (already consumed by `openAICompatibleProvider`). Confirm end-users are gated
  by app keys + rate limits and never see the gateway key.

## Acceptance criteria (Done = all green)

- Unauthenticated `POST /v1/chat/completions` → **401** (no GPU consumed).
- Valid `cgk_` key → **200**, response **streams** (SSE intact).
- Revoked key → **401**. Unknown key → **401**.
- Gateway **restart preserves** keys + balances + quota counters (RocksDB).
- `Authorization` header **never** appears in logs/traces.
- Exceeding a key's rate/quota → **429** with `Retry-After`.
- `/health` remains open and returns 200.
- Chatbot + explorer answer in prod using their server-side keys; the open path is gone.

## Security checklist

- [x] Keys hashed at rest (`sha256(key_id)`) — already in `auth.rs`.
- [ ] Plaintext key shown exactly **once** at creation; never logged/stored.
- [ ] RocksDB keystore dir perms `0600`, owned by the service user.
- [ ] TLS-only at the edge (Caddy); gateway binds loopback only.
- [ ] Per-key rate limit + daily quota (abuse + cost control).
- [ ] Revocation effective immediately.
- [ ] `Authorization` redaction verified in `json` log mode.
- [ ] Admin surface is local/SSH-only (no public admin endpoint).
- [ ] Rotate the chatbot/explorer keys on a schedule; document the procedure.

## Out of scope (future, separate sprints)

- The on-chain **marketplace dispatch** + **x402 settlement** path
  (`build_router_with_auth`, `provider.rs`, `X402Layer`) — ships later behind the
  repo's **Tier-1 external audit**.
- Billing/credits reconciliation, usage dashboards, multi-model routing.

## References

- `gateway/src/auth.rs` — `ApiKeyStore`, `ApiKeyLayer`, `create_key*`, `revoke`.
- `gateway/src/lib.rs` — `build_router`, `build_router_with_auth`, layer ordering.
- `gateway/src/main.rs` — boot path (currently the open router).
- `gateway/src/provider.rs` — on-chain provider dispatch (why we don't reuse it here).
- Handoff brief: `citrate-labs/handoffs/GATEWAY_APIKEY_HANDOFF.md`.
