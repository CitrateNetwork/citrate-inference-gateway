# ENCRYPTED_MONEY_STORE — operating the encrypted gateway money store

**Program:** ENCRYPT-S1 / WP-2 (federation planset
`2026-07-04-encrypt-s1-federation-encryption.md`, inventory row A11)
**Applies to:** the WP-F durable RocksDB store (`gateway/src/keystore.rs`) used by
both gateway modes — balances (`bal:`), in-flight batches (`batch:`/`batchset:`),
API-key records (`record:`/`quota:`), per-model budgets (`mbudget:`).
**Status:** values encrypted at rest with AES-256-GCM-SIV since this WP. Keys
(sha256 digests) stay plaintext by design — they were never secret (inventory A12)
and must stay byte-queryable.

---

## 1. Architecture (what an operator needs to know)

- Every VALUE is sealed before it reaches RocksDB:
  `value = nonce(12) ‖ AES-256-GCM-SIV(plaintext, AAD = full record key)`.
  Per-namespace data keys are derived from one 32-byte master key via
  `blake3::derive_key("citrate-gateway/store/ns/v1:<ns>", master)`.
  This is the citrate-comms `EncryptedStore` pattern (proven in prod at
  `comms.citrate.ai`), with the AAD strengthened from "CF name" to "full record
  key" so a ciphertext can't be transplanted between rows.
- A marker row `meta:enc` proves the store is encrypted **and under which key**:
  - wrong key at boot → the gateway **refuses to start** (`WrongKey`), it never
    looks like an empty store;
  - plaintext legacy store → refuses with `PlaintextStore` and points here;
  - fresh dir → initialized encrypted from the first row.
- Crash-atomicity (TD-22) is unchanged: encryption happens **before** the synced
  `WriteBatch`, so the single-commit-point guarantees hold. The TD-22 suites
  (`infer_wpf_durable_balances`, `infer_wpf2_batch_settlement`,
  `infer_wpe_model_budgets`) run against the encrypted store in CI.

## 2. Key provisioning on the droplet (sourcing chain + threat models)

The gateway is headless (no Secret Service/D-Bus), so the comms OS-keyring tier is
replaced by this chain — **first hit wins**, logged at boot as `key_source=`:

| Tier | Source | Threat model |
|---|---|---|
| 1 | `GATEWAY_STORE_KEY` env var — 64 hex chars (32 bytes) | Protects against off-box exfil of the DB dir (backups, snapshots, stolen volume, scp). Visible in `/proc/<pid>/environ` to root + service user → does NOT protect against live root compromise. Prefer injecting via systemd credentials (below), not a plaintext `Environment=` line in the unit. |
| 2 | Key file — path from `GATEWAY_STORE_KEY_FILE` (or `--store-key-file` on the admin CLI); must be `0600`, group/other-readable files are **refused** | Same as tier 1 **iff** the file lives on a different path than the DB (e.g. `/etc/citrate-gateway/store.key` vs `/var/lib/citrate-gateway/keystore`). A backup job that captures both defeats it. |
| 3 | Generate-on-first-run → written `0600` to the resolved key-file path, default `<keystore>.master.key` (sibling of the DB dir) | Bootstrap/dev tier ONLY. Key sits next to the data: defeats single-file/DB-dir-only leaks, not a parent-dir copy. Production must graduate to tier 1/2. |

**Recommended production setup (tier 1 via systemd credential):**

```bash
# on the droplet (root@<gateway-droplet>), one-time:
openssl rand -hex 32 > /root/gateway-store-key.hex     # or reuse the tier-3 generated file
systemd-creds encrypt --name=gateway-store-key /root/gateway-store-key.hex \
    /etc/citrate-gateway/gateway-store-key.cred
shred -u /root/gateway-store-key.hex
```

Unit drop-in (`systemctl edit citrate-inference-gateway-local-proxy.service`):

```ini
[Service]
LoadCredentialEncrypted=gateway-store-key:/etc/citrate-gateway/gateway-store-key.cred
# The credential materializes as a file — point the FILE tier at it:
Environment=GATEWAY_STORE_KEY_FILE=%d/gateway-store-key
```

(`%d` = `$CREDENTIALS_DIRECTORY`; the file is root-inaccessible ramfs scoped to the
service. If `systemd-creds` isn't available on the image, fall back to a `0600`
key file at `/etc/citrate-gateway/store.key` + `GATEWAY_STORE_KEY_FILE` — document
the deviation.)

**Back the key up off-box at provisioning time.** Losing it loses every balance
record — same custody tier as the operator signer (`.env.testnet` rules). There is
NO recovery path.

## 3. Migration window (plaintext → encrypted, one-shot)

Money data cannot be wiped-and-resynced; `migrate-encrypt` re-encrypts in place
via a staging dir + atomic rename. It is **idempotent** (second run: "ALREADY
encrypted — nothing to do") and refuses mixed/unknown states before writing
anything.

```bash
# 0) Preconditions: pick the key tier (above) FIRST, so the migration seals
#    under the key the service will boot with. Announce a maintenance window.

# 1) Stop the gateway (it holds the RocksDB LOCK; migration refuses while live):
systemctl stop citrate-inference-gateway-local-proxy.service   # and/or marketplace unit

# 2) Dry run — classify + count, writes nothing:
citrate-gateway-admin --keystore /var/lib/citrate-gateway/keystore \
    migrate-encrypt --dry-run
#    Expect: "DRY RUN: plaintext keystore, N rows" + per-namespace counts.
#    Any "unrecognized row" error → STOP, escalate; do not force.

# 3) Real run (sources the key via the chain; generates tier-3 if none set):
citrate-gateway-admin --keystore /var/lib/citrate-gateway/keystore migrate-encrypt
#    Prints the backup path: /var/lib/citrate-gateway/keystore.pre-encrypt-<ts>

# 4) Verify (see §5), then restart:
systemctl start citrate-inference-gateway-local-proxy.service
journalctl -u citrate-inference-gateway-local-proxy -n 20 | grep key_source
#    Expect: "money-store master key sourced" with the intended tier, and
#    "gateway listening". A WrongKey/PlaintextStore panic → §4 rollback.

# 5) After a soak (suggest 24h) + a confirmed off-box key backup, archive or
#    destroy the .pre-encrypt-<ts> dir — it still holds PLAINTEXT money records:
tar czf - keystore.pre-encrypt-<ts> | age -r <ops-recipient> > pre-encrypt.tgz.age  # optional archive
rm -rf /var/lib/citrate-gateway/keystore.pre-encrypt-<ts>
```

Notes:
- The tool opens the source **read-write** deliberately: RocksDB read-only opens
  skip WAL replay, and the freshest balance commits live in the WAL.
- Every row is copy-verified (decrypt-and-compare) **before** the rename swap.
- Crash mid-copy: only `<keystore>.migrating` exists → just rerun; it's rebuilt.
- Crash between the two renames (rare): `<keystore>` missing, both
  `<keystore>.pre-encrypt-<ts>` and a fully verified `<keystore>.migrating`
  present → `mv keystore.migrating keystore` and continue at step 4.

## 4. Rollback

The pre-migration copy IS the rollback:

```bash
systemctl stop citrate-inference-gateway-local-proxy.service
mv /var/lib/citrate-gateway/keystore /var/lib/citrate-gateway/keystore.enc-failed-$(date +%s)
mv /var/lib/citrate-gateway/keystore.pre-encrypt-<ts> /var/lib/citrate-gateway/keystore
# Roll the binary back to the pre-ENCRYPT-S1 build (the new binary refuses
# plaintext stores by design), then:
systemctl start citrate-inference-gateway-local-proxy.service
```

Rollback is only valid if NO traffic hit the encrypted store after migration
(otherwise the plaintext copy is stale money state — reconcile before serving).
That's why verification (§5) happens inside the window, before real traffic.

## 5. Verification (hexdump probe)

Prove there is no plaintext money data on disk. Balance records carry two
greppable plaintext markers pre-migration: the operator **label** strings and the
20-byte **deposit address**.

```bash
KS=/var/lib/citrate-gateway/keystore
# 1) Labels you know exist (from `citrate-gateway-admin list` pre-migration):
grep -r "chatbot-prod" $KS/ && echo "FAIL: plaintext label found" || echo "OK: no label"
# 2) Broad probe — human-readable runs in the SSTs/WAL should show no cgk_/label/
#    schema-value strings (row KEYS like 'bal:<hex>' remain visible by design):
for f in $KS/*.sst $KS/*.log; do hexdump -C "$f" | grep -E "cgk_|chatbot|explorer" ; done
# 3) Positive control — the same grep against the pre-encrypt backup MUST hit:
grep -rc "chatbot-prod" $KS.pre-encrypt-<ts>/ || echo "FAIL: probe is broken"
# 4) Functional: balances identical through the API —
citrate-gateway-admin --keystore $KS list          # records readable
#    and compare a known key's balance against the pre-migration note you took.
```

The same property is enforced in CI by
`keystore::tests::on_disk_bytes_hold_no_plaintext_money_markers` and
`migrate::tests::migrate_preserves_balances_and_leaves_only_ciphertext`.

## 6. Quick reference

| Thing | Value |
|---|---|
| Env: master key (hex 32B) | `GATEWAY_STORE_KEY` |
| Env: key-file path | `GATEWAY_STORE_KEY_FILE` |
| Default key file | `<keystore>.master.key` (tier 3 — bootstrap only) |
| Migration tool | `citrate-gateway-admin migrate-encrypt [--dry-run] [--store-key-file P]` |
| Backup dir | `<keystore>.pre-encrypt-<YYYYMMDD-HHMMSS>` |
| Staging dir (transient) | `<keystore>.migrating` |
| Boot log line | `money-store master key sourced key_source=env:…/file:…/generated:…` |
| Wrong key at boot | refuses to start (`WrongKey`) — fix the key, don't recreate the store |
| Plaintext store at boot | refuses to start (`PlaintextStore`) — run §3 |
