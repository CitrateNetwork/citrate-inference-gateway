//! Persistent API-key store (WP-2 of 2026-06-04 planset).
//!
//! Backs [`crate::local_proxy::LocalProxyAuthLayer`]. Distinct from
//! [`crate::auth::ApiKeyStore`] (which is in-memory + x402-coupled and stays
//! for the marketplace path); kept separate so the audited x402 code path
//! isn't refactored under this security fix.
//!
//! # Layout
//!
//! Single RocksDB column family, key-prefixed:
//!
//! ```text
//! record:<sha256_hex>            -> bincode KeyRecord
//! quota:<sha256_hex>:<yyyymmdd>  -> u64 LE  (request count for that UTC day)
//! bal:<sha256_hex>               -> bincode BalanceRecord   (money, WP-F)
//! batch:<batch_id>               -> bincode PersistedBatch  (WP-F F2)
//! batchset:<batch_id>            -> settled marker          (WP-F F2)
//! mbudget:<sha256_hex>:<model>   -> U256 BE                 (WP-E)
//! meta:enc                       -> encryption marker       (ENCRYPT-S1)
//! ```
//!
//! Per-second rate-limit windows are kept in memory only — restart resets
//! the in-flight burst counter, which is correct (the daily quota is what
//! survives restart, and that *is* persisted).
//!
//! # Encryption at rest (ENCRYPT-S1 / WP-2)
//!
//! Every VALUE is encrypted with **AES-256-GCM-SIV** before it reaches
//! RocksDB, following the proven citrate-comms `EncryptedStore` pattern
//! (nonce-misuse-resistant AEAD per FWA-C11-04; values stored as
//! `nonce(12) ‖ ciphertext+tag`). Adaptations for this store:
//!
//! - This DB uses key-prefix **namespaces** instead of column families, so
//!   the per-CF derived key becomes a per-namespace derived key
//!   (`blake3::derive_key("citrate-gateway/store/ns/v1:<ns>", master)`).
//! - The AAD is the **full record key** (not just the namespace) — stronger
//!   than the comms pattern, and it matters for money: a ciphertext
//!   transplanted from one row to another (e.g. copying a rich `bal:` value
//!   onto a poorer key's row in a stolen-write scenario) fails to decrypt.
//!
//! KEYS stay plaintext by design: they are already `sha256(bearer)` digests
//! (audit F-3, inventory A12) and must remain byte-queryable for the
//! `record:`/`bal:` lookups and prefix scans. The `meta:enc` marker lets
//! `open` distinguish an encrypted store from a legacy plaintext one and
//! reject a wrong master key at boot instead of on first read. The master
//! key is sourced by [`crate::keyvault`]; legacy plaintext stores are
//! migrated once via `citrate-gateway-admin migrate-encrypt`
//! ([`crate::migrate`]).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use chrono::{Datelike, NaiveTime, Utc};
use ethereum_types::{H160, U256};
use parking_lot::Mutex;
use rocksdb::{IteratorMode, Options, WriteBatch, WriteOptions, DB};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// SHA-256(`key_id`) as lowercase hex. Used for indexing — the plaintext
/// `cgk_…` token is **never** persisted.
pub fn hash_key_id(key_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(key_id.as_bytes());
    hex::encode(h.finalize())
}

// ── Value encryption at rest (ENCRYPT-S1 / WP-2) ────────────────────

/// Marker row proving this store is encrypted and under WHICH key: its value
/// is [`ENC_MARKER_PLAINTEXT`] sealed under the master key. Checked at
/// `open`: decrypt failure = wrong key; absence in a non-empty DB = legacy
/// plaintext store (refused — run `migrate-encrypt`).
pub(crate) const ENC_MARKER_KEY: &str = "meta:enc";
/// Known plaintext sealed into the marker row.
pub(crate) const ENC_MARKER_PLAINTEXT: &[u8] = b"citrate-gateway-store-enc-v1";
/// BLAKE3 KDF domain prefix for per-namespace data keys. Versioned so an
/// algorithm change bumps the domain (mirrors comms `store/cf/v2` rationale).
const KDF_DOMAIN_PREFIX: &str = "citrate-gateway/store/ns/v1:";

/// Why a value failed to seal/unseal.
#[derive(Debug, thiserror::Error)]
pub enum CryptError {
    /// OS RNG failure drawing a nonce.
    #[error("store rng failure")]
    Rng,
    /// AEAD failure — wrong master key or tampered/transplanted bytes.
    #[error("value decrypt failed (wrong master key or tampered bytes)")]
    Crypto,
    /// Stored value shorter than a nonce — not produced by this store.
    #[error("stored value is corrupt (shorter than a nonce)")]
    Corrupt,
}

/// The key-prefix namespace (bytes before the first `:`), e.g. `bal` for
/// `bal:<hash>`. Keys without a `:` map to themselves.
fn namespace_of(record_key: &[u8]) -> &[u8] {
    match record_key.iter().position(|b| *b == b':') {
        Some(i) => &record_key[..i],
        None => record_key,
    }
}

/// Per-namespace cipher: domain-separated keyed KDF over the master key. The
/// derived key is `Zeroizing` so its only residence in our memory is this
/// short-lived buffer (comms `EncryptedStore::cipher` pattern).
fn cipher_for(master: &[u8; 32], ns: &[u8]) -> Aes256GcmSiv {
    let domain = format!("{KDF_DOMAIN_PREFIX}{}", String::from_utf8_lossy(ns));
    let ns_key = Zeroizing::new(blake3::derive_key(&domain, master));
    Aes256GcmSiv::new_from_slice(ns_key.as_ref()).expect("32-byte derived key")
}

/// Seal `plaintext` for storage under `record_key`: fresh random 96-bit
/// nonce, AAD = the full record key, output `nonce(12) ‖ ciphertext+tag`.
pub(crate) fn seal_value(
    master: &[u8; 32],
    record_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptError> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| CryptError::Rng)?;
    let ct = cipher_for(master, namespace_of(record_key))
        .encrypt(
            &Nonce::from(nonce),
            Payload { msg: plaintext, aad: record_key },
        )
        .map_err(|_| CryptError::Crypto)?;
    let mut val = Vec::with_capacity(12 + ct.len());
    val.extend_from_slice(&nonce);
    val.extend_from_slice(&ct);
    Ok(val)
}

/// Unseal a stored value; the AAD binding means a value copied from another
/// row (even in the same namespace) fails authentication.
pub(crate) fn open_value(
    master: &[u8; 32],
    record_key: &[u8],
    raw: &[u8],
) -> Result<Vec<u8>, CryptError> {
    if raw.len() < 12 {
        return Err(CryptError::Corrupt);
    }
    let (nonce, ct) = raw.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().expect("split_at(12)");
    cipher_for(master, namespace_of(record_key))
        .decrypt(
            &Nonce::from(nonce),
            Payload { msg: ct, aad: record_key },
        )
        .map_err(|_| CryptError::Crypto)
}

/// Internal plumbing error for the sealed read/write helpers — converted
/// into each public error enum at the call boundary.
enum ValErr {
    Db(rocksdb::Error),
    Crypt(CryptError),
}

impl From<rocksdb::Error> for ValErr {
    fn from(e: rocksdb::Error) -> Self {
        ValErr::Db(e)
    }
}

impl From<CryptError> for ValErr {
    fn from(e: CryptError) -> Self {
        ValErr::Crypt(e)
    }
}

/// One API key's persisted state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Operator-supplied label, e.g. `"chatbot-prod"`.
    pub label: String,
    /// Unix seconds at mint.
    pub created_at: u64,
    /// `true` once revoked; revoked keys 401 even with quota left.
    pub revoked: bool,
    /// Max requests/second for this key. `0` disables the rate limit.
    pub quota_rps: u32,
    /// Max requests per UTC day for this key. `0` disables the quota.
    pub daily_quota: u64,
}

/// One balance-bearing API key's durable state (INFER-S4 / WP-F).
///
/// Stored under the `bal:<sha256_hex>` namespace, **additive** to the
/// `record:`/`quota:` schema so existing local-proxy DBs deserialize
/// unchanged (bincode is positional — folding new fields into [`KeyRecord`]
/// would break already-deployed records). This is the converged home for the
/// marketplace money store (TD-22 / TD-23): one durable store, balance in it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceRecord {
    /// Operator-supplied label.
    pub label: String,
    /// Unix seconds at mint.
    pub created_at: u64,
    /// `true` once revoked. Revoked keys cannot spend, but can still be refunded.
    pub revoked: bool,
    /// `KeyBacking` discriminant: 0 = Salt, 1 = Credits (mirrors `auth::KeyBacking`).
    pub backing: u8,
    /// Deposit EOA (20 bytes); zero for keys without an allocated top-up address.
    pub deposit_address: [u8; 20],
    /// Current balance in grains, big-endian 32 bytes.
    pub balance_be: [u8; 32],
}

/// Why a durable balance operation failed (INFER-S4 / WP-F).
#[derive(Debug, thiserror::Error)]
pub enum BalanceError {
    /// No balance record for this bearer.
    #[error("unknown key")]
    Unknown,
    /// Key is revoked — spending is blocked (refunds are still allowed).
    #[error("api key revoked")]
    Revoked,
    /// Balance was less than the requested debit; carries the current balance.
    #[error("insufficient balance")]
    Insufficient(U256),
    /// Underlying RocksDB error.
    #[error("keystore unavailable: {0}")]
    Store(#[from] rocksdb::Error),
    /// bincode round-trip failure.
    #[error("encode: {0}")]
    Encode(String),
    /// At-rest encryption failure (ENCRYPT-S1).
    #[error("store crypto: {0}")]
    Crypt(#[from] CryptError),
}

/// Why a per-model budget debit failed (INFER-S3 / WP-E).
#[derive(Debug, thiserror::Error)]
pub enum ModelBudgetError {
    /// The model's remaining budget was less than the requested debit; carries
    /// the remaining budget.
    #[error("model budget exceeded")]
    Exceeded(U256),
    /// Underlying RocksDB error.
    #[error("keystore unavailable: {0}")]
    Store(#[from] rocksdb::Error),
    /// On-disk budget value was malformed.
    #[error("encode: {0}")]
    Encode(String),
    /// At-rest encryption failure (ENCRYPT-S1).
    #[error("store crypto: {0}")]
    Crypt(#[from] CryptError),
}

/// Result of [`PersistentKeyStore::try_consume`] on success — what the
/// caller needs to log without leaking the bearer.
pub struct ConsumedKey {
    /// Stable, non-reversible identifier (sha256 of the bearer).
    pub hash: String,
    /// Operator-supplied label (e.g. `"chatbot-prod"`).
    pub label: String,
}

/// Why a key consumption attempt failed.
#[derive(Debug, thiserror::Error)]
pub enum ConsumeError {
    /// No record for this bearer (either never minted or wrong hash).
    #[error("unknown key")]
    Unknown,
    /// Key is revoked.
    #[error("api key revoked")]
    Revoked,
    /// `quota_rps` exceeded for this 1-second window.
    #[error("rate limited")]
    RateLimited {
        /// Seconds the client should wait before retrying.
        retry_after_secs: u64,
    },
    /// `daily_quota` exceeded for today's UTC day.
    #[error("daily quota exceeded")]
    DailyQuotaExceeded {
        /// Seconds until next UTC day rollover.
        retry_after_secs: u64,
    },
    /// Underlying RocksDB error — log + 500.
    #[error("keystore unavailable: {0}")]
    Store(#[from] rocksdb::Error),
    /// At-rest encryption failure (ENCRYPT-S1) — log + 500.
    #[error("store crypto: {0}")]
    Crypt(#[from] CryptError),
}

/// Why a mint / revoke / list operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No record for that key.
    #[error("unknown key")]
    Unknown,
    /// RocksDB I/O error.
    #[error("keystore unavailable: {0}")]
    Rocks(#[from] rocksdb::Error),
    /// Serialization round-trip failure (shouldn't happen with bincode).
    #[error("encode: {0}")]
    Encode(String),
    /// At-rest encryption failure (ENCRYPT-S1).
    #[error("store crypto: {0}")]
    Crypt(#[from] CryptError),
    /// The encryption marker exists but does not decrypt under the supplied
    /// master key. Fail closed at boot — every read would fail anyway, and a
    /// wrong-key boot must never look like an empty store.
    #[error(
        "wrong master key for this store — the encryption marker failed to decrypt \
         (check GATEWAY_STORE_KEY / the key file; see ENCRYPTED_MONEY_STORE runbook)"
    )]
    WrongKey,
    /// A non-empty store with no encryption marker: a legacy plaintext DB
    /// (pre-ENCRYPT-S1). Refused so plaintext and ciphertext rows can never
    /// mix — run the one-shot migration instead.
    #[error(
        "plaintext (pre-ENCRYPT-S1) store detected — run \
         `citrate-gateway-admin migrate-encrypt` during a maintenance window first \
         (see ENCRYPTED_MONEY_STORE runbook)"
    )]
    PlaintextStore,
}

impl From<ValErr> for StoreError {
    fn from(e: ValErr) -> Self {
        match e {
            ValErr::Db(e) => StoreError::Rocks(e),
            ValErr::Crypt(e) => StoreError::Crypt(e),
        }
    }
}

impl From<ValErr> for BalanceError {
    fn from(e: ValErr) -> Self {
        match e {
            ValErr::Db(e) => BalanceError::Store(e),
            ValErr::Crypt(e) => BalanceError::Crypt(e),
        }
    }
}

impl From<ValErr> for ConsumeError {
    fn from(e: ValErr) -> Self {
        match e {
            ValErr::Db(e) => ConsumeError::Store(e),
            ValErr::Crypt(e) => ConsumeError::Crypt(e),
        }
    }
}

impl From<ValErr> for ModelBudgetError {
    fn from(e: ValErr) -> Self {
        match e {
            ValErr::Db(e) => ModelBudgetError::Store(e),
            ValErr::Crypt(e) => ModelBudgetError::Crypt(e),
        }
    }
}

/// RocksDB-backed key store. Cheap to clone via [`Arc`]. All values are
/// AES-256-GCM-SIV-encrypted at rest (ENCRYPT-S1 / WP-2).
pub struct PersistentKeyStore {
    db: DB,
    /// 32-byte master key for the at-rest value encryption. `Zeroizing` so it
    /// is wiped when the store drops (comms `EncryptedStore` pattern).
    master: Zeroizing<[u8; 32]>,
    rate: Mutex<HashMap<String, RateWindow>>,
    /// Per-key serialization for the balance read-modify-write (WP-F). A debit
    /// must read, check, deduct, and durably commit as one critical section so
    /// concurrent debits cannot lose an update or overspend.
    bal_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

#[derive(Clone, Copy)]
struct RateWindow {
    window_start: u64,
    count: u32,
}

impl PersistentKeyStore {
    /// Open (or create) the keystore at `path`, encrypted under `master`
    /// (ENCRYPT-S1: there is deliberately NO plaintext constructor — the type
    /// system is the "values are encrypted at rest" guarantee).
    ///
    /// Marker protocol (`meta:enc`):
    /// - marker present + decrypts → normal open;
    /// - marker present + fails to decrypt → [`StoreError::WrongKey`];
    /// - marker absent + DB non-empty → [`StoreError::PlaintextStore`]
    ///   (legacy pre-ENCRYPT-S1 data; run `migrate-encrypt`);
    /// - fresh/empty DB → marker written (synced) and the store is encrypted
    ///   from its first row.
    ///
    /// The caller is responsible for ensuring the directory and its parent
    /// are owned by the service user with `0600` perms (see PLANSET
    /// security checklist). RocksDB itself doesn't enforce perms.
    pub fn open(path: impl AsRef<Path>, master: [u8; 32]) -> Result<Arc<Self>, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        let store = Self {
            db,
            master: Zeroizing::new(master),
            rate: Mutex::new(HashMap::new()),
            bal_locks: Mutex::new(HashMap::new()),
        };
        store.check_or_init_enc_marker()?;
        Ok(Arc::new(store))
    }

    /// Enforce the `meta:enc` marker protocol described on [`Self::open`].
    fn check_or_init_enc_marker(&self) -> Result<(), StoreError> {
        match self.db.get(ENC_MARKER_KEY.as_bytes())? {
            Some(raw) => {
                let pt = open_value(&self.master, ENC_MARKER_KEY.as_bytes(), &raw)
                    .map_err(|_| StoreError::WrongKey)?;
                if pt != ENC_MARKER_PLAINTEXT {
                    return Err(StoreError::WrongKey);
                }
                Ok(())
            }
            None => {
                if self.db.iterator(IteratorMode::Start).next().is_some() {
                    return Err(StoreError::PlaintextStore);
                }
                let sealed = seal_value(&self.master, ENC_MARKER_KEY.as_bytes(), ENC_MARKER_PLAINTEXT)?;
                // Synced: the marker must never be lost once rows exist.
                self.db.put_opt(ENC_MARKER_KEY.as_bytes(), sealed, &synced())?;
                Ok(())
            }
        }
    }

    // ── Sealed read/write plumbing (ENCRYPT-S1) ─────────────────────
    //
    // Every value round-trips through these helpers; no call site touches
    // `self.db.get`/`put` for data rows directly.

    /// Read + unseal the value at `key`.
    fn get_val(&self, key: &str) -> Result<Option<Vec<u8>>, ValErr> {
        match self.db.get(key.as_bytes())? {
            Some(raw) => Ok(Some(open_value(&self.master, key.as_bytes(), &raw)?)),
            None => Ok(None),
        }
    }

    /// Seal + write `plaintext` at `key` with the given write options.
    fn put_val(&self, key: &str, plaintext: &[u8], wo: &WriteOptions) -> Result<(), ValErr> {
        let sealed = seal_value(&self.master, key.as_bytes(), plaintext)?;
        self.db.put_opt(key.as_bytes(), sealed, wo)?;
        Ok(())
    }

    /// Seal a value destined for a [`WriteBatch`] entry at `key`.
    fn seal_for(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, ValErr> {
        Ok(seal_value(&self.master, key.as_bytes(), plaintext)?)
    }

    /// Migration hook: seal + write an arbitrary raw key/value pair
    /// (non-synced; `migrate-encrypt` flushes once at the end).
    pub(crate) fn raw_put_sealed(&self, key: &[u8], plaintext: &[u8]) -> Result<(), StoreError> {
        let sealed = seal_value(&self.master, key, plaintext)?;
        self.db.put(key, sealed)?;
        Ok(())
    }

    /// Migration hook: read + unseal an arbitrary raw key (verification pass).
    pub(crate) fn raw_get_unsealed(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        match self.db.get(key)? {
            Some(raw) => Ok(Some(open_value(&self.master, key, &raw)?)),
            None => Ok(None),
        }
    }

    /// Migration hook: flush memtables to SSTs before the atomic rename.
    pub(crate) fn flush(&self) -> Result<(), StoreError> {
        self.db.flush()?;
        Ok(())
    }

    // ── Durable balances (INFER-S4 / WP-F) ──────────────────────────

    /// Mint a fresh `cgk_<uuid>` balance key. Returns the plaintext token —
    /// print once and discard (not recoverable). The plaintext bearer is never
    /// persisted; the record is keyed by `sha256(bearer)`.
    pub fn create_balance_key(
        &self,
        label: impl Into<String>,
        balance: U256,
        deposit_address: H160,
        backing: u8,
    ) -> Result<String, StoreError> {
        let id = format!("cgk_{}", Uuid::new_v4().simple());
        let h = hash_key_id(&id);
        let mut balance_be = [0u8; 32];
        balance.to_big_endian(&mut balance_be);
        let rec = BalanceRecord {
            label: label.into(),
            created_at: now_secs(),
            revoked: false,
            backing,
            deposit_address: deposit_address.0,
            balance_be,
        };
        let bytes = bincode::serialize(&rec).map_err(|e| StoreError::Encode(e.to_string()))?;
        // Synced write: the record is durable before we hand the caller a token.
        self.put_val(&bal_key(&h), &bytes, &synced())?;
        Ok(id)
    }

    /// Fetch a balance record by plaintext bearer.
    pub fn get_balance_record(&self, key_id: &str) -> Result<Option<BalanceRecord>, StoreError> {
        let h = hash_key_id(key_id);
        match self.get_val(&bal_key(&h))? {
            Some(b) => Ok(Some(
                bincode::deserialize(&b).map_err(|e| StoreError::Encode(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Current balance in grains, if the key exists.
    pub fn get_balance(&self, key_id: &str) -> Result<Option<U256>, StoreError> {
        Ok(self
            .get_balance_record(key_id)?
            .map(|r| U256::from_big_endian(&r.balance_be)))
    }

    /// Debit `amount` from `key_id`. Returns the new balance. Atomic and
    /// crash-safe: the read-check-deduct runs under a per-key lock and the new
    /// balance is committed with a **synced** write, so a debit that returns
    /// `Ok` has survived to disk and applies exactly once across a restart.
    pub fn debit_balance(&self, key_id: &str, amount: U256) -> Result<U256, BalanceError> {
        let h = hash_key_id(key_id);
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();

        let mut rec = match self.get_val(&bal_key(&h))? {
            Some(b) => bincode::deserialize::<BalanceRecord>(&b)
                .map_err(|e| BalanceError::Encode(e.to_string()))?,
            None => return Err(BalanceError::Unknown),
        };
        if rec.revoked {
            return Err(BalanceError::Revoked);
        }
        let bal = U256::from_big_endian(&rec.balance_be);
        if bal < amount {
            return Err(BalanceError::Insufficient(bal));
        }
        let new = bal - amount;
        new.to_big_endian(&mut rec.balance_be);
        let bytes = bincode::serialize(&rec).map_err(|e| BalanceError::Encode(e.to_string()))?;
        self.put_val(&bal_key(&h), &bytes, &synced())?; // commit point
        Ok(new)
    }

    /// Credit `amount` to `key_id` (saturating). Intentionally bypasses the
    /// `revoked` flag — revocation stops future spending but must never trap
    /// already-debited buyer funds. Same per-key lock + synced commit.
    pub fn refund_balance(&self, key_id: &str, amount: U256) -> Result<U256, BalanceError> {
        let h = hash_key_id(key_id);
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();

        let mut rec = match self.get_val(&bal_key(&h))? {
            Some(b) => bincode::deserialize::<BalanceRecord>(&b)
                .map_err(|e| BalanceError::Encode(e.to_string()))?,
            None => return Err(BalanceError::Unknown),
        };
        let bal = U256::from_big_endian(&rec.balance_be);
        let new = bal.saturating_add(amount);
        new.to_big_endian(&mut rec.balance_be);
        let bytes = bincode::serialize(&rec).map_err(|e| BalanceError::Encode(e.to_string()))?;
        self.put_val(&bal_key(&h), &bytes, &synced())?;
        Ok(new)
    }

    // ── Durable in-flight batches (INFER-S4 / WP-F, slice F2) ───────

    /// Persist a batch snapshot (best-effort, non-synced). Progress durability
    /// for resume; money safety comes from the synced, atomic
    /// [`Self::settle_batch_refund`], not from per-transition writes.
    pub fn persist_batch(&self, batch_id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.put_val(&batch_key(batch_id), bytes, &WriteOptions::default())?;
        Ok(())
    }

    /// All persisted batch snapshots as `(batch_id, bytes)`, for boot recovery.
    pub fn load_batches(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let prefix = b"batch:";
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(prefix) {
            let (k, v) = item?;
            if !k.starts_with(prefix) {
                break;
            }
            let id = String::from_utf8_lossy(&k[prefix.len()..]).into_owned();
            let plain = open_value(&self.master, &k, &v)?;
            out.push((id, plain));
        }
        Ok(out)
    }

    /// Has this batch's refund already been settled? (Recovery idempotency.)
    pub fn batch_was_settled(&self, batch_id: &str) -> Result<bool, StoreError> {
        Ok(self.db.get(batch_settled_key(batch_id).as_bytes())?.is_some())
    }

    /// Mark a batch settled with no balance credit (x402-paid batches, or
    /// nothing owed). Atomic synced write of the terminal snapshot + marker so
    /// recovery skips it.
    pub fn mark_batch_settled(&self, batch_id: &str, batch_bytes: &[u8]) -> Result<(), StoreError> {
        let bk = batch_key(batch_id);
        let sk = batch_settled_key(batch_id);
        let mut wb = WriteBatch::default();
        wb.put(bk.as_bytes(), self.seal_for(&bk, batch_bytes)?);
        wb.put(sk.as_bytes(), self.seal_for(&sk, &[1u8])?);
        self.db.write_opt(wb, &synced())?;
        Ok(())
    }

    /// Settle a terminal batch's refund **atomically and exactly once**:
    /// credit the buyer's balance by `refund`, write the terminal batch
    /// snapshot, and stamp the "settled" marker — all in **one synced
    /// `WriteBatch`**. If the marker already exists (recovery replayed the
    /// settlement after a crash), this is a no-op credit: the snapshot is
    /// refreshed but the balance is never credited twice. Returns the post
    /// balance. Runs under the buyer's per-key lock so it can't race a debit.
    pub fn settle_batch_refund(
        &self,
        key_id: &str,
        refund: U256,
        batch_id: &str,
        batch_bytes: &[u8],
    ) -> Result<U256, BalanceError> {
        let h = hash_key_id(key_id);
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();

        let read_balance = || -> Result<(BalanceRecord, U256), BalanceError> {
            match self.get_val(&bal_key(&h))? {
                Some(b) => {
                    let rec: BalanceRecord = bincode::deserialize(&b)
                        .map_err(|e| BalanceError::Encode(e.to_string()))?;
                    let bal = U256::from_big_endian(&rec.balance_be);
                    Ok((rec, bal))
                }
                None => Err(BalanceError::Unknown),
            }
        };

        // Already settled — idempotent. Refresh the terminal snapshot, never
        // re-credit. (Presence check only — no decrypt needed on the marker.)
        if self.db.get(batch_settled_key(batch_id).as_bytes())?.is_some() {
            self.put_val(&batch_key(batch_id), batch_bytes, &WriteOptions::default())
                .map_err(BalanceError::from)?;
            let (_rec, bal) = read_balance()?;
            return Ok(bal);
        }

        let (mut rec, bal) = read_balance()?;
        let new = bal.saturating_add(refund);
        new.to_big_endian(&mut rec.balance_be);
        let bal_bytes =
            bincode::serialize(&rec).map_err(|e| BalanceError::Encode(e.to_string()))?;

        let bk = bal_key(&h);
        let bat = batch_key(batch_id);
        let set = batch_settled_key(batch_id);
        let mut wb = WriteBatch::default();
        wb.put(bk.as_bytes(), self.seal_for(&bk, &bal_bytes).map_err(BalanceError::from)?);
        wb.put(bat.as_bytes(), self.seal_for(&bat, batch_bytes).map_err(BalanceError::from)?);
        wb.put(set.as_bytes(), self.seal_for(&set, &[1u8]).map_err(BalanceError::from)?);
        self.db.write_opt(wb, &synced())?; // single atomic, durable commit
        Ok(new)
    }

    // ── Per-model budgets (INFER-S3 / WP-E) ─────────────────────────
    //
    // An orthogonal sub-ledger keyed `mbudget:<hash>:<model> → remaining grains`.
    // A model with NO entry is uncapped (debit is a no-op). Additive — no change
    // to `BalanceRecord` or the overall-balance debit path.

    /// Set (or replace) a key's remaining budget for `model`.
    pub fn set_model_budget(&self, key_id: &str, model: &str, amount: U256) -> Result<(), StoreError> {
        let h = hash_key_id(key_id);
        let mut be = [0u8; 32];
        amount.to_big_endian(&mut be);
        self.put_val(&mbudget_key(&h, model), &be, &synced())?;
        Ok(())
    }

    /// A key's remaining budget for `model`, if one is set (else uncapped).
    pub fn get_model_budget(&self, key_id: &str, model: &str) -> Result<Option<U256>, StoreError> {
        let h = hash_key_id(key_id);
        Ok(self.get_val(&mbudget_key(&h, model))?.and_then(parse_u256_be))
    }

    /// All `(model, remaining)` budgets set for a key (admin/inspect).
    pub fn get_model_budgets(&self, key_id: &str) -> Result<Vec<(String, U256)>, StoreError> {
        let h = hash_key_id(key_id);
        let prefix = mbudget_prefix(&h);
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(prefix.as_bytes()) {
            let (k, v) = item?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            // The model name is everything after the fixed-length prefix, so a
            // `:` inside a model name is unambiguous.
            let model = String::from_utf8_lossy(&k[prefix.len()..]).into_owned();
            let plain = open_value(&self.master, &k, &v)?;
            if let Some(amt) = parse_u256_be(plain) {
                out.push((model, amt));
            }
        }
        Ok(out)
    }

    /// Debit a model's budget. **No-op `Ok` if the model is uncapped** (no
    /// budget set). Atomic check-and-deduct under the per-key lock + synced
    /// write; `Err(Exceeded(remaining))` if the budget is insufficient.
    pub fn debit_model_budget(&self, key_id: &str, model: &str, amount: U256) -> Result<(), ModelBudgetError> {
        let h = hash_key_id(key_id);
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();
        let mk = mbudget_key(&h, model);
        let cur = match self.get_val(&mk)? {
            Some(b) => parse_u256_be(b).ok_or_else(|| ModelBudgetError::Encode("bad budget value".into()))?,
            None => return Ok(()), // uncapped
        };
        if cur < amount {
            return Err(ModelBudgetError::Exceeded(cur));
        }
        let mut be = [0u8; 32];
        (cur - amount).to_big_endian(&mut be);
        self.put_val(&mk, &be, &synced())?;
        Ok(())
    }

    /// Credit a model's budget back. **No-op if uncapped.** Same per-key lock +
    /// synced write. Intentionally never creates a budget where none existed.
    pub fn refund_model_budget(&self, key_id: &str, model: &str, amount: U256) -> Result<(), StoreError> {
        let h = hash_key_id(key_id);
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();
        let mk = mbudget_key(&h, model);
        let cur = match self.get_val(&mk)? {
            Some(b) => parse_u256_be(b).unwrap_or_default(),
            None => return Ok(()), // uncapped — nothing to credit
        };
        let mut be = [0u8; 32];
        cur.saturating_add(amount).to_big_endian(&mut be);
        self.put_val(&mk, &be, &synced())?;
        Ok(())
    }

    /// Per-key lock handle for the balance RMW. Cloned out of the map so the
    /// map mutex is held only briefly.
    fn lock_for(&self, hash: &str) -> Arc<Mutex<()>> {
        self.bal_locks.lock().entry(hash.to_owned()).or_default().clone()
    }

    /// Mint a fresh `cgk_<uuid>` token. Returns the plaintext token —
    /// callers must print it once and discard it (it isn't recoverable).
    pub fn create_key(
        &self,
        label: impl Into<String>,
        quota_rps: u32,
        daily_quota: u64,
    ) -> Result<String, StoreError> {
        let id = format!("cgk_{}", Uuid::new_v4().simple());
        let h = hash_key_id(&id);
        let rec = KeyRecord {
            label: label.into(),
            created_at: now_secs(),
            revoked: false,
            quota_rps,
            daily_quota,
        };
        let bytes = bincode::serialize(&rec).map_err(|e| StoreError::Encode(e.to_string()))?;
        self.put_val(&record_key(&h), &bytes, &WriteOptions::default())?;
        Ok(id)
    }

    /// Fetch a record by plaintext bearer.
    pub fn get_record(&self, key_id: &str) -> Result<Option<KeyRecord>, StoreError> {
        let h = hash_key_id(key_id);
        let raw = self.get_val(&record_key(&h))?;
        match raw {
            Some(b) => Ok(Some(
                bincode::deserialize(&b).map_err(|e| StoreError::Encode(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Mark a key revoked. Takes effect on the next request. Handles both the
    /// quota-keyed (`record:`, local-proxy) and balance-keyed (`bal:`, WP-F
    /// marketplace) namespaces.
    pub fn revoke(&self, key_id: &str) -> Result<(), StoreError> {
        let h = hash_key_id(key_id);
        if let Some(b) = self.get_val(&record_key(&h))? {
            let mut rec: KeyRecord =
                bincode::deserialize(&b).map_err(|e| StoreError::Encode(e.to_string()))?;
            rec.revoked = true;
            let bytes = bincode::serialize(&rec).map_err(|e| StoreError::Encode(e.to_string()))?;
            self.put_val(&record_key(&h), &bytes, &WriteOptions::default())?;
            return Ok(());
        }
        // Balance key — revoke under the per-key lock so it can't race a debit.
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();
        if let Some(b) = self.get_val(&bal_key(&h))? {
            let mut rec: BalanceRecord =
                bincode::deserialize(&b).map_err(|e| StoreError::Encode(e.to_string()))?;
            rec.revoked = true;
            let bytes = bincode::serialize(&rec).map_err(|e| StoreError::Encode(e.to_string()))?;
            self.put_val(&bal_key(&h), &bytes, &synced())?;
            return Ok(());
        }
        Err(StoreError::Unknown)
    }

    /// List all records as `(hash, record)`. The plaintext bearer isn't
    /// recoverable, so the admin CLI shows the hash prefix instead.
    pub fn list(&self) -> Result<Vec<(String, KeyRecord)>, StoreError> {
        let prefix = b"record:";
        let mut out = Vec::new();
        for item in self.db.prefix_iterator(prefix) {
            let (k, v) = item?;
            if !k.starts_with(prefix) {
                break;
            }
            let hash = String::from_utf8_lossy(&k[prefix.len()..]).into_owned();
            let plain = open_value(&self.master, &k, &v)?;
            if let Ok(r) = bincode::deserialize::<KeyRecord>(&plain) {
                out.push((hash, r));
            }
        }
        Ok(out)
    }

    /// Authenticate + meter one request. Returns Ok on success after
    /// debiting both the per-second window and the daily quota; returns
    /// the specific [`ConsumeError`] so the proxy can map it to
    /// 401 vs 429 with the right `Retry-After`.
    pub fn try_consume(&self, key_id: &str) -> Result<ConsumedKey, ConsumeError> {
        let h = hash_key_id(key_id);
        let raw = self.get_val(&record_key(&h))?;
        let record: KeyRecord = match raw {
            Some(b) => bincode::deserialize(&b).map_err(|_| ConsumeError::Unknown)?,
            None => return Err(ConsumeError::Unknown),
        };
        if record.revoked {
            return Err(ConsumeError::Revoked);
        }

        if record.quota_rps > 0 {
            let now = now_secs();
            let mut lock = self.rate.lock();
            let w = lock.entry(h.clone()).or_insert(RateWindow {
                window_start: now,
                count: 0,
            });
            if w.window_start != now {
                w.window_start = now;
                w.count = 0;
            }
            if w.count >= record.quota_rps {
                return Err(ConsumeError::RateLimited {
                    retry_after_secs: 1,
                });
            }
            w.count += 1;
        }

        if record.daily_quota > 0 {
            // FUA-GATEWAY-03: the read-compare-write below must be atomic per
            // key — two concurrent requests could both read N and both write
            // N+1, drifting past the cap. Reuse the per-key balance lock so
            // the daily counter has the same single-writer guarantee money
            // does.
            let keylock = self.lock_for(&h);
            let _guard = keylock.lock();
            let day = today_yyyymmdd();
            let day_key = quota_key(&h, &day);
            let cur = self
                .get_val(&day_key)?
                .and_then(|b| {
                    if b.len() == 8 {
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(&b);
                        Some(u64::from_le_bytes(buf))
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if cur >= record.daily_quota {
                return Err(ConsumeError::DailyQuotaExceeded {
                    retry_after_secs: seconds_until_next_utc_day(),
                });
            }
            let next = cur + 1;
            self.put_val(&day_key, &next.to_le_bytes(), &WriteOptions::default())?;
        }

        Ok(ConsumedKey {
            hash: h,
            label: record.label,
        })
    }
}

fn record_key(hash: &str) -> String {
    format!("record:{}", hash)
}

fn bal_key(hash: &str) -> String {
    format!("bal:{}", hash)
}

fn mbudget_prefix(hash: &str) -> String {
    format!("mbudget:{}:", hash)
}

fn mbudget_key(hash: &str, model: &str) -> String {
    format!("mbudget:{}:{}", hash, model)
}

/// Decode a 32-byte big-endian U256 budget value; `None` if malformed.
fn parse_u256_be(b: impl AsRef<[u8]>) -> Option<U256> {
    let b = b.as_ref();
    if b.len() == 32 {
        Some(U256::from_big_endian(b))
    } else {
        None
    }
}

fn batch_key(id: &str) -> String {
    format!("batch:{}", id)
}

/// Distinct prefix (NOT `batch:`) so the recovery scan never confuses the
/// settled marker for a batch snapshot.
fn batch_settled_key(id: &str) -> String {
    format!("batchset:{}", id)
}

/// Write options that fsync the WAL before returning — used for every balance
/// mutation so an acknowledged debit/refund is durable (WP-F crash-atomicity).
fn synced() -> WriteOptions {
    let mut w = WriteOptions::default();
    w.set_sync(true);
    w
}

fn quota_key(hash: &str, day: &str) -> String {
    format!("quota:{}:{}", hash, day)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn today_yyyymmdd() -> String {
    let d = Utc::now().date_naive();
    format!("{:04}{:02}{:02}", d.year(), d.month(), d.day())
}

fn seconds_until_next_utc_day() -> u64 {
    let now = Utc::now();
    let next = (now.date_naive() + chrono::Duration::days(1))
        .and_time(NaiveTime::default())
        .and_utc();
    (next.timestamp() - now.timestamp()).max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Test master key for the at-rest encryption (ENCRYPT-S1).
    pub(crate) const TEST_MASTER: [u8; 32] = [7u8; 32];

    /// Shorthand: open an encrypted store under [`TEST_MASTER`].
    fn open(path: &Path) -> Arc<PersistentKeyStore> {
        PersistentKeyStore::open(path, TEST_MASTER).unwrap()
    }

    #[test]
    fn create_get_list_revoke_roundtrip() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());

        let id = store.create_key("chatbot", 5, 10_000).unwrap();
        assert!(id.starts_with("cgk_"));

        let r = store.get_record(&id).unwrap().unwrap();
        assert_eq!(r.label, "chatbot");
        assert_eq!(r.quota_rps, 5);
        assert_eq!(r.daily_quota, 10_000);
        assert!(!r.revoked);

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);

        store.revoke(&id).unwrap();
        let r = store.get_record(&id).unwrap().unwrap();
        assert!(r.revoked);
    }

    #[test]
    fn unknown_get_is_none_revoke_is_err() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        assert!(store.get_record("cgk_nope").unwrap().is_none());
        assert!(matches!(
            store.revoke("cgk_nope"),
            Err(StoreError::Unknown)
        ));
    }

    /// Plaintext bearer must not appear in the on-disk schema —
    /// only `sha256(bearer)` does. (Mirrors auth.rs::store_holds_hashed_key_not_plaintext.)
    #[test]
    fn storage_never_holds_plaintext_bearer() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        let id = store.create_key("ci", 0, 0).unwrap();

        // The plaintext id MUST NOT be a key in the DB.
        let plaintext_record_key = format!("record:{}", id);
        assert!(store
            .db
            .get(plaintext_record_key.as_bytes())
            .unwrap()
            .is_none());

        // But the hashed key MUST be.
        let h = hash_key_id(&id);
        assert!(store
            .db
            .get(record_key(&h).as_bytes())
            .unwrap()
            .is_some());
    }

    #[test]
    fn restart_preserves_records_and_daily_quota() {
        let dir = tempdir().unwrap();
        let id;
        {
            let store = open(dir.path());
            id = store.create_key("explorer", 0, 10).unwrap();
            // burn 3 daily ticks
            for _ in 0..3 {
                store.try_consume(&id).unwrap();
            }
        }
        // "restart" — drop and reopen
        let store = open(dir.path());
        let r = store.get_record(&id).unwrap().unwrap();
        assert_eq!(r.label, "explorer");

        // Daily quota counter survived: 7 more should succeed, the 11th fails.
        for _ in 0..7 {
            store.try_consume(&id).unwrap();
        }
        assert!(matches!(
            store.try_consume(&id),
            Err(ConsumeError::DailyQuotaExceeded { .. })
        ));
    }

    #[test]
    fn revoked_key_returns_revoked() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        let id = store.create_key("rev", 0, 0).unwrap();
        store.revoke(&id).unwrap();
        assert!(matches!(store.try_consume(&id), Err(ConsumeError::Revoked)));
    }

    #[test]
    fn unknown_key_returns_unknown() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        assert!(matches!(
            store.try_consume("cgk_does_not_exist"),
            Err(ConsumeError::Unknown)
        ));
    }

    #[test]
    fn rate_limit_caps_per_second() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        let id = store.create_key("rl", 3, 0).unwrap();
        // 3 succeed in the same second
        store.try_consume(&id).unwrap();
        store.try_consume(&id).unwrap();
        store.try_consume(&id).unwrap();
        // 4th in the same second is rate limited
        assert!(matches!(
            store.try_consume(&id),
            Err(ConsumeError::RateLimited { .. })
        ));
    }

    /// WP-F: a balance key's on-disk schema holds only `sha256(bearer)` —
    /// never the plaintext `cgk_` token (audit F-3, balance namespace).
    #[test]
    fn balance_store_never_holds_plaintext_bearer() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        let id = store
            .create_balance_key("buyer", U256::from(100u64), H160::zero(), 0)
            .unwrap();

        // The plaintext id MUST NOT be a key in the DB (under bal: or record:).
        assert!(store.db.get(bal_key(&id).as_bytes()).unwrap().is_none());
        assert!(store.db.get(format!("bal:{id}").as_bytes()).unwrap().is_none());
        // The hashed key MUST be.
        let h = hash_key_id(&id);
        assert!(store.db.get(bal_key(&h).as_bytes()).unwrap().is_some());
    }

    /// WP-F additive schema: quota keys (`record:`) and balance keys (`bal:`)
    /// coexist in one store without colliding — a balance key is invisible to
    /// the quota path and vice-versa, and both survive a restart. This is why
    /// adding balances did NOT require migrating existing local-proxy records.
    #[test]
    fn quota_and_balance_namespaces_coexist_across_restart() {
        let dir = tempdir().unwrap();
        let (quota_id, bal_id);
        {
            let store = open(dir.path());
            quota_id = store.create_key("proxy", 0, 5).unwrap();
            bal_id = store
                .create_balance_key("buyer", U256::from(42u64), H160::zero(), 0)
                .unwrap();
            // A quota key has no balance; a balance key has no quota record.
            assert!(store.get_balance(&quota_id).unwrap().is_none());
            assert!(store.get_record(&bal_id).unwrap().is_none());
        }
        // restart
        let store = open(dir.path());
        assert_eq!(store.get_record(&quota_id).unwrap().unwrap().daily_quota, 5);
        assert_eq!(
            store.get_balance(&bal_id).unwrap().unwrap(),
            U256::from(42u64)
        );
    }

    #[test]
    fn zero_quota_is_unlimited() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        let id = store.create_key("uncapped", 0, 0).unwrap();
        // Burst far past anything we'd actually configure — should be fine.
        for _ in 0..200 {
            store.try_consume(&id).unwrap();
        }
    }

    /// FUA-GATEWAY-03: the daily-quota counter must be atomic per key.
    /// Pre-fix the read-compare-write raced — concurrent consumers could
    /// both read N and both write N+1, drifting past the cap. With the
    /// per-key lock, exactly `daily_quota` consumes succeed no matter how
    /// many race.
    #[test]
    fn daily_quota_is_atomic_under_concurrency() {
        let dir = tempdir().unwrap();
        let store = open(dir.path());
        // quota_rps=0 disables the per-second window so only the daily
        // path is exercised.
        let id = store.create_key("racy", 0, 16).unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let id = id.clone();
            handles.push(std::thread::spawn(move || {
                let mut ok = 0u64;
                for _ in 0..8 {
                    if store.try_consume(&id).is_ok() {
                        ok += 1;
                    }
                }
                ok
            }));
        }
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 16, "exactly daily_quota consumes may succeed");
    }

    // ── ENCRYPT-S1 / WP-2: at-rest value encryption ─────────────────

    /// Roundtrip across reopen under the SAME master key: money survives.
    #[test]
    fn encrypted_store_roundtrips_across_reopen() {
        let dir = tempdir().unwrap();
        let id;
        {
            let store = open(dir.path());
            id = store
                .create_balance_key("buyer", U256::from(1234u64), H160::zero(), 0)
                .unwrap();
        }
        let store = open(dir.path());
        assert_eq!(store.get_balance(&id).unwrap().unwrap(), U256::from(1234u64));
    }

    /// A wrong master key is rejected AT OPEN (marker check) — never a
    /// silent empty-looking store, never a partial read.
    #[test]
    fn wrong_master_key_is_rejected_at_open() {
        let dir = tempdir().unwrap();
        {
            let store = open(dir.path());
            store
                .create_balance_key("buyer", U256::from(9u64), H160::zero(), 0)
                .unwrap();
        }
        let err = PersistentKeyStore::open(dir.path(), [9u8; 32]).err().expect("must fail");
        assert!(matches!(err, StoreError::WrongKey), "got: {err}");
    }

    /// A legacy plaintext DB (rows, no `meta:enc` marker) is refused with the
    /// migration pointer — plaintext and ciphertext rows must never mix.
    #[test]
    fn plaintext_store_is_refused_at_open() {
        let dir = tempdir().unwrap();
        {
            // Craft a pre-ENCRYPT-S1 store: a raw plaintext row, no marker.
            let mut opts = Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, dir.path()).unwrap();
            db.put(b"record:deadbeef", b"plaintext-record").unwrap();
        }
        let err = PersistentKeyStore::open(dir.path(), TEST_MASTER).err().expect("must fail");
        assert!(matches!(err, StoreError::PlaintextStore), "got: {err}");
    }

    /// Hexdump-probe property: the distinctive plaintext markers of a money
    /// record (label bytes, deposit address bytes) must not appear anywhere
    /// in the on-disk files (SSTs, WAL, …). Mirrors the comms
    /// `on_disk_bytes_are_not_plaintext` red test.
    #[test]
    fn on_disk_bytes_hold_no_plaintext_money_markers() {
        let dir = tempdir().unwrap();
        let label = "PROBE-LABEL-DO-NOT-LEAK";
        let deposit = H160::from_slice(&[0xAB; 20]);
        {
            let store = open(dir.path());
            store
                .create_balance_key(label, U256::from(777_777u64), deposit, 1)
                .unwrap();
            store.flush().unwrap();
        }
        let mut hits = Vec::new();
        for f in walk(dir.path()) {
            if let Ok(bytes) = std::fs::read(&f) {
                if bytes.windows(label.len()).any(|w| w == label.as_bytes())
                    || bytes.windows(20).any(|w| w == deposit.as_bytes())
                {
                    hits.push(f);
                }
            }
        }
        assert!(hits.is_empty(), "plaintext money markers leaked to disk: {hits:?}");
    }

    /// AAD binding (stronger than the comms per-CF pattern): a ciphertext
    /// transplanted onto another row's key fails authentication instead of
    /// decrypting as that row's value.
    #[test]
    fn transplanted_ciphertext_fails_aad_binding() {
        let sealed = seal_value(&TEST_MASTER, b"bal:rich", b"lots-of-money").unwrap();
        // Same namespace, different row — must NOT decrypt.
        let err = open_value(&TEST_MASTER, b"bal:poor", &sealed).unwrap_err();
        assert!(matches!(err, CryptError::Crypto));
        // Original row still decrypts.
        assert_eq!(
            open_value(&TEST_MASTER, b"bal:rich", &sealed).unwrap(),
            b"lots-of-money"
        );
    }

    /// Recursively list files under `dir` (probe helper).
    pub(crate) fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    out.extend(walk(&p));
                } else {
                    out.push(p);
                }
            }
        }
        out
    }
}
