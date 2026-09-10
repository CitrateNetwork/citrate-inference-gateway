---
created: 2026-06-04T00:00:00Z
branch: main
author: Saul Loveman + Claude Opus 4.7 (1M context)
status: active
repo: citrate-inference-gateway
tier: T1
sprint: gateway-apikey-hardening
---

# Key rotation — `cgk_` API keys for the local-proxy gateway

> Sister doc to `DEPLOY_RUNBOOK.md`. The runbook is one-shot ("how the
> cutover happened"); this one is the recurring procedure for minting,
> rotating, and revoking the `cgk_` keys that gate `infer.citrate.ai`.

## When to rotate

| Trigger | Urgency | Action |
|---|---|---|
| Routine cadence — every **90 days** per the planset security checklist | calendar | overlap-rotate (§ "Rotate without downtime") |
| Suspected leak (key seen in a screenshot, log, Slack, PR diff, etc.) | **now** | revoke first, then re-mint |
| Employee offboarding who had RocksDB / SSH access to the droplet | within 24h | revoke all keys they could have read + re-mint |
| Quota / abuse signal (sustained 429s, unexpected traffic shape) | when triaged | revoke the offending key, mint a replacement with tighter limits |
| Service spin-down (chatbot or explorer retired) | with the spin-down | revoke; do not re-mint |

## Operator preconditions

- SSH to the droplet as `root` (key: `~/.ssh/citrate-do`).
- Vercel CLI logged in, or web access to the `saulbuilds-projects` org.
- The droplet path layout (unchanged unless the unit file's
  `CITRATE_GATEWAY_KEYSTORE_PATH` changed):

```
/var/lib/citrate-gateway/keystore   # RocksDB dir, 0700 citrate:citrate
/usr/local/bin/citrate-gateway-admin
/usr/local/bin/citrate-inference-gateway
/etc/systemd/system/citrate-inference-gateway-local-proxy.service
```

## Rotate without downtime (preferred — chatbot / explorer)

The local-proxy gateway is single-writer against RocksDB, so minting
a key requires the gateway briefly stopped. The window is < 2 seconds;
infer.citrate.ai will return **502** during it (Caddy fails through to
no upstream). For traffic that hates 502s, schedule during a low-traffic
window.

```bash
ssh -i ~/.ssh/citrate-do root@<gateway-droplet> 'bash -s' <<'EOF'
set -euo pipefail
systemctl stop citrate-inference-gateway-local-proxy
# Mint the replacement BEFORE revoking the old key — overlap means the
# old key keeps working until step 4. If anything fails between here
# and "redeploy on Vercel", you can roll back by restarting the unit
# and leaving Vercel on the old key.
NEW_KEY=$(sudo -u citrate /usr/local/bin/citrate-gateway-admin \
    --keystore /var/lib/citrate-gateway/keystore \
    create --label chatbot-prod 2>/dev/null)
systemctl start citrate-inference-gateway-local-proxy
echo "NEW_KEY=$NEW_KEY"   # capture this — shown ONCE.
EOF
```

Then on your workstation:

```bash
# 1. Paste $NEW_KEY into Vercel:
vercel env rm  CITRATE_GATEWAY_API_KEY production --yes \
    --cwd ~/Projects/Citrate-Labs/tutorials/citrate-chatbot
echo "$NEW_KEY" | vercel env add CITRATE_GATEWAY_API_KEY production \
    --cwd ~/Projects/Citrate-Labs/tutorials/citrate-chatbot

# 2. Redeploy so the running prod uses the new env.
vercel --prod --cwd ~/Projects/Citrate-Labs/tutorials/citrate-chatbot

# 3. Smoke test the redeployed app (chat sends a real prompt + gets a reply).
#    Don't proceed to step 4 until this passes — once you revoke the old
#    key, there is no rollback short of minting another.
```

Then revoke the OLD key:

```bash
ssh -i ~/.ssh/citrate-do root@<gateway-droplet> 'bash -s' <<'EOF'
set -euo pipefail
systemctl stop citrate-inference-gateway-local-proxy
sudo -u citrate /usr/local/bin/citrate-gateway-admin \
    --keystore /var/lib/citrate-gateway/keystore \
    revoke "<OLD_CGK_TOKEN>"
systemctl start citrate-inference-gateway-local-proxy
EOF
```

Same procedure for `explorer-prod` — swap the labels and the Vercel
project (`saulbuilds-projects/citrate-explorer`).

## Rotate during an incident (skip overlap)

If a key is believed compromised, revoke first, mint after — the brief
chatbot / explorer outage is the right tradeoff against a live GPU drain.

```bash
ssh -i ~/.ssh/citrate-do root@<gateway-droplet> 'bash -s' <<'EOF'
set -euo pipefail
systemctl stop citrate-inference-gateway-local-proxy
sudo -u citrate /usr/local/bin/citrate-gateway-admin \
    --keystore /var/lib/citrate-gateway/keystore \
    revoke "<COMPROMISED_CGK_TOKEN>"
NEW_KEY=$(sudo -u citrate /usr/local/bin/citrate-gateway-admin \
    --keystore /var/lib/citrate-gateway/keystore \
    create --label chatbot-prod 2>/dev/null)
systemctl start citrate-inference-gateway-local-proxy
echo "NEW_KEY=$NEW_KEY"
EOF
# update Vercel + redeploy as in the no-downtime procedure.
```

## Auditing what's live

```bash
ssh -i ~/.ssh/citrate-do root@<gateway-droplet> \
    'systemctl stop citrate-inference-gateway-local-proxy && \
     sudo -u citrate /usr/local/bin/citrate-gateway-admin \
        --keystore /var/lib/citrate-gateway/keystore list && \
     systemctl start citrate-inference-gateway-local-proxy'
```

`list` shows the SHA-256 hash prefix, label, rps cap, and daily quota
for every key. The plaintext bearer is **not** recoverable — if you
lose the token after minting, the only path forward is mint-new +
revoke-old.

A line marked `REVOKED` means the record is still on disk but no longer
authenticates. Revoked records are kept indefinitely so the audit trail
of "key X existed and was revoked at time Y" is intact.

## Quota tuning

Quotas are immutable post-mint by design (mint flow is the audit point).
To change a key's quota, mint a replacement with the new flags and
revoke the original.

```bash
# Higher-traffic chatbot tier:
sudo -u citrate /usr/local/bin/citrate-gateway-admin \
    --keystore /var/lib/citrate-gateway/keystore \
    create --label chatbot-prod --quota-rps 20 --daily-requests 200000
```

Tiered defaults the planset assumes:

| Tier | `--quota-rps` | `--daily-requests` |
|---|---:|---:|
| Conservative (current) | 5 | 10 000 |
| Generous | 20 | 100 000 |
| Uncapped | 0 | 0 |

`0` disables that dimension entirely.

## What rotation does **not** require

- No Caddy reload (the bearer wall lives in the gateway, not Caddy).
- No code changes (`CITRATE_GATEWAY_API_KEY` is the only thing that
  changes — and only in Vercel env, not the repo).
- No DNS, no cert renewal, no llama-server bounce.

If a rotation procedure asks for any of these, something has drifted
from the design — flag it in `handoffs/GATEWAY_APIKEY_HANDOFF.md` and
update this doc.

## Backup / recovery

The keystore is a RocksDB directory at `/var/lib/citrate-gateway/keystore`.
For backup:

```bash
ssh -i ~/.ssh/citrate-do root@<gateway-droplet> 'bash -s' <<'EOF'
systemctl stop citrate-inference-gateway-local-proxy
tar -C /var/lib/citrate-gateway -czf /root/keystore-$(date +%Y%m%d).tgz keystore
systemctl start citrate-inference-gateway-local-proxy
EOF
# scp the tarball off-host into your password manager / encrypted vault.
```

Recovery is "untar + start" — the keystore is portable across hosts
of the same arch / glibc. **Do not check the tarball into git** — the
file holds the `sha256(key_id)` hashes, which would expedite brute-force
search if combined with the plaintext-token format (`cgk_<32 hex>`).
RocksDB at rest holds no plaintext; treat the tarball as sensitive
anyway because a compromised backup is a compromised quota counter.

## Related docs

- `DEPLOY_RUNBOOK.md` — initial cutover (one-shot).
- `PLANSET.md` — work-package decomposition + security checklist.
- `handoffs/GATEWAY_APIKEY_HANDOFF.md` (in `citrate-labs`) — high-level
  brief, decision log, and open questions.
