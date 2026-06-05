---
created: 2026-06-04T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.7 (1M context)
status: active
repo: citrate-inference-gateway
tier: T1
sprint: gateway-apikey-hardening
---

# Deploy runbook — local-proxy cutover for `infer.citrate.ai`

> WP-6 + WP-7 of the planset. Reads the planset for the "why";
> this file is the "what to type". One operator, one ssh session.

## 0. Preconditions on the droplet

- `citrate-llama.service` is up on `127.0.0.1:8081` (the bare llama-server
  from `HANDOFF_GEMMA_SEED.md` / `HANDOFF_LLAMA_SERVER.md`).
- Caddy is up and currently terminates TLS for `infer.citrate.ai` →
  `127.0.0.1:8081` (per `TLS_Handoff.md`).
- `citrate` system user already exists (owns the llama-server).
- Build host has SSH access to `CitrateNetwork/citrate-chain` (the
  workspace pulls `citrate-wallet-core` as a git dep — see workspace
  `Cargo.toml` line 102).

## 1. Build

On the build host:

```bash
git -C citrate-inference-gateway fetch origin
git -C citrate-inference-gateway checkout main
git -C citrate-inference-gateway pull
cd citrate-inference-gateway
cargo build --release -p citrate-inference-gateway
# Produces two binaries:
#   target/release/citrate-inference-gateway   (the gateway)
#   target/release/citrate-gateway-admin       (the key admin CLI)
```

## 2. Install on the droplet

```bash
sudo install -m 0755 target/release/citrate-inference-gateway /usr/local/bin/
sudo install -m 0750 target/release/citrate-gateway-admin     /usr/local/bin/

# Keystore dir — owned by the service user, 0700.
sudo install -d -m 0700 -o citrate -g citrate /var/lib/citrate-gateway

# systemd unit.
sudo install -m 0644 packaging/citrate-inference-gateway.service \
    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable citrate-inference-gateway
sudo systemctl start citrate-inference-gateway

# Sanity (note: /v1/* requires a key now — expect 401, not 200):
curl -s http://127.0.0.1:9800/health
# {"ok":true}
curl -s -o /dev/null -w '%{http_code}\n' \
  http://127.0.0.1:9800/v1/models
# 401
```

## 3. Mint the two server-side keys

The chatbot and the explorer each need exactly one `cgk_` key. The
plaintext is printed to stdout once — save it immediately.

```bash
# Defaults: 5 rps, 10000 req/day (conservative tier per planset).
# Override if you need different limits.
sudo -u citrate /usr/local/bin/citrate-gateway-admin create \
    --label chatbot-prod
# captures stdout; eprintln warnings go to stderr.

sudo -u citrate /usr/local/bin/citrate-gateway-admin create \
    --label explorer-prod
```

Copy each plaintext `cgk_…` token into the right Vercel project env:

| App        | Vercel project                                  | Env var name                   |
|------------|--------------------------------------------------|--------------------------------|
| chatbot    | `saulbuilds-projects/citrate-chatbot`            | `CITRATE_GATEWAY_API_KEY`      |
| explorer   | `saulbuilds-projects/citrate-explorer`           | `CITRATE_GATEWAY_API_KEY`      |

Trigger a redeploy on each Vercel project so the new env takes effect.

## 4. Flip the Caddy upstream

Edit `/etc/caddy/Caddyfile` so the `infer.citrate.ai` site block points
at `127.0.0.1:9800` instead of `127.0.0.1:8081`. The full block we want
is in `packaging/infer.citrate.ai.Caddyfile.snippet`.

```bash
sudo cp packaging/infer.citrate.ai.Caddyfile.snippet \
    /etc/caddy/sites/infer.citrate.ai
# (or paste the contents into the existing block — adjust to match
# your Caddyfile layout.)

sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

## 5. Verify the open path is closed

From any off-droplet machine:

```bash
# Unauth → 401 (was 200 before the cutover):
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
    https://infer.citrate.ai/v1/chat/completions \
    -H 'content-type: application/json' \
    -d '{"model":"gemma-4-E4B-it-Q4_K_M","messages":[{"role":"user","content":"ping"}],"max_tokens":1}'
# 401

# With a valid key → 200 + JSON completion:
curl -s -X POST https://infer.citrate.ai/v1/chat/completions \
    -H "Authorization: Bearer $CHATBOT_KEY" \
    -H 'content-type: application/json' \
    -d '{"model":"gemma-4-E4B-it-Q4_K_M","messages":[{"role":"user","content":"say OK"}],"max_tokens":5}'
# {"choices":[{"message":{"role":"assistant","content":"OK"}}],...}

# Streaming preserved (SSE chunks visible):
curl -N -X POST https://infer.citrate.ai/v1/chat/completions \
    -H "Authorization: Bearer $CHATBOT_KEY" \
    -H 'content-type: application/json' \
    -d '{"model":"gemma-4-E4B-it-Q4_K_M","stream":true,"messages":[{"role":"user","content":"hi"}],"max_tokens":8}'
# data: {...}\n\ndata: {...}\n\ndata: [DONE]\n\n
```

Then open the chatbot (https://citrate-chatbot.vercel.app) and the
explorer playground — both should answer through the new gated path
with no UI change. The 5 M open-path completions/day risk is gone.

## 6. Rotate / revoke procedure

```bash
# Mint a replacement first (overlap), then revoke the old one:
sudo -u citrate /usr/local/bin/citrate-gateway-admin create --label chatbot-prod
# Update CITRATE_GATEWAY_API_KEY in Vercel, redeploy, smoke test.
sudo -u citrate /usr/local/bin/citrate-gateway-admin revoke <old-cgk-token>
# Verify with: curl ... -H "Authorization: Bearer <old>"  → 401
```

`list` shows the on-disk state any time:

```bash
sudo -u citrate /usr/local/bin/citrate-gateway-admin list
```

## 7. Rollback

If the gateway misbehaves, the previous topology is one Caddy edit + reload:

```bash
# Point Caddy back at the bare llama-server:
sudo sed -i 's|127\.0\.0\.1:9800|127.0.0.1:8081|' /etc/caddy/sites/infer.citrate.ai
sudo systemctl reload caddy
# The open path is back; stop the gateway to free :9800:
sudo systemctl stop citrate-inference-gateway
```

This is intentionally trivial — the cutover is a single Caddy line.
The keystore on disk is unaffected by rollback; minting/restoring is
non-destructive.
