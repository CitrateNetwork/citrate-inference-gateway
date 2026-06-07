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
//! ```
//!
//! Per-second rate-limit windows are kept in memory only — restart resets
//! the in-flight burst counter, which is correct (the daily quota is what
//! survives restart, and that *is* persisted).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use chrono::{Datelike, NaiveTime, Utc};
use ethereum_types::{H160, U256};
use parking_lot::Mutex;
use rocksdb::{Options, WriteBatch, WriteOptions, DB};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// SHA-256(`key_id`) as lowercase hex. Used for indexing — the plaintext
/// `cgk_…` token is **never** persisted.
pub fn hash_key_id(key_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(key_id.as_bytes());
    hex::encode(h.finalize())
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
}

/// RocksDB-backed key store. Cheap to clone via [`Arc`].
pub struct PersistentKeyStore {
    db: DB,
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
    /// Open (or create) the keystore at `path`.
    ///
    /// The caller is responsible for ensuring the directory and its parent
    /// are owned by the service user with `0600` perms (see PLANSET
    /// security checklist). RocksDB itself doesn't enforce perms.
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<Self>, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Arc::new(Self {
            db,
            rate: Mutex::new(HashMap::new()),
            bal_locks: Mutex::new(HashMap::new()),
        }))
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
        self.db.put_opt(bal_key(&h).as_bytes(), bytes, &synced())?;
        Ok(id)
    }

    /// Fetch a balance record by plaintext bearer.
    pub fn get_balance_record(&self, key_id: &str) -> Result<Option<BalanceRecord>, StoreError> {
        let h = hash_key_id(key_id);
        match self.db.get(bal_key(&h).as_bytes())? {
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

        let mut rec = match self.db.get(bal_key(&h).as_bytes())? {
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
        self.db.put_opt(bal_key(&h).as_bytes(), bytes, &synced())?; // commit point
        Ok(new)
    }

    /// Credit `amount` to `key_id` (saturating). Intentionally bypasses the
    /// `revoked` flag — revocation stops future spending but must never trap
    /// already-debited buyer funds. Same per-key lock + synced commit.
    pub fn refund_balance(&self, key_id: &str, amount: U256) -> Result<U256, BalanceError> {
        let h = hash_key_id(key_id);
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();

        let mut rec = match self.db.get(bal_key(&h).as_bytes())? {
            Some(b) => bincode::deserialize::<BalanceRecord>(&b)
                .map_err(|e| BalanceError::Encode(e.to_string()))?,
            None => return Err(BalanceError::Unknown),
        };
        let bal = U256::from_big_endian(&rec.balance_be);
        let new = bal.saturating_add(amount);
        new.to_big_endian(&mut rec.balance_be);
        let bytes = bincode::serialize(&rec).map_err(|e| BalanceError::Encode(e.to_string()))?;
        self.db.put_opt(bal_key(&h).as_bytes(), bytes, &synced())?;
        Ok(new)
    }

    // ── Durable in-flight batches (INFER-S4 / WP-F, slice F2) ───────

    /// Persist a batch snapshot (best-effort, non-synced). Progress durability
    /// for resume; money safety comes from the synced, atomic
    /// [`Self::settle_batch_refund`], not from per-transition writes.
    pub fn persist_batch(&self, batch_id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.db.put(batch_key(batch_id).as_bytes(), bytes)?;
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
            out.push((id, v.to_vec()));
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
        let mut wb = WriteBatch::default();
        wb.put(batch_key(batch_id).as_bytes(), batch_bytes);
        wb.put(batch_settled_key(batch_id).as_bytes(), [1u8]);
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
            match self.db.get(bal_key(&h).as_bytes())? {
                Some(b) => {
                    let rec: BalanceRecord = bincode::deserialize(&b)
                        .map_err(|e| BalanceError::Encode(e.to_string()))?;
                    let bal = U256::from_big_endian(&rec.balance_be);
                    Ok((rec, bal))
                }
                None => Err(BalanceError::Unknown),
            }
        };

        // Already settled — idempotent. Refresh the terminal snapshot, never re-credit.
        if self.db.get(batch_settled_key(batch_id).as_bytes())?.is_some() {
            self.db.put(batch_key(batch_id).as_bytes(), batch_bytes)?;
            let (_rec, bal) = read_balance()?;
            return Ok(bal);
        }

        let (mut rec, bal) = read_balance()?;
        let new = bal.saturating_add(refund);
        new.to_big_endian(&mut rec.balance_be);
        let bal_bytes =
            bincode::serialize(&rec).map_err(|e| BalanceError::Encode(e.to_string()))?;

        let mut wb = WriteBatch::default();
        wb.put(bal_key(&h).as_bytes(), &bal_bytes);
        wb.put(batch_key(batch_id).as_bytes(), batch_bytes);
        wb.put(batch_settled_key(batch_id).as_bytes(), [1u8]);
        self.db.write_opt(wb, &synced())?; // single atomic, durable commit
        Ok(new)
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
        self.db.put(record_key(&h).as_bytes(), bytes)?;
        Ok(id)
    }

    /// Fetch a record by plaintext bearer.
    pub fn get_record(&self, key_id: &str) -> Result<Option<KeyRecord>, StoreError> {
        let h = hash_key_id(key_id);
        let raw = self.db.get(record_key(&h).as_bytes())?;
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
        if let Some(b) = self.db.get(record_key(&h).as_bytes())? {
            let mut rec: KeyRecord =
                bincode::deserialize(&b).map_err(|e| StoreError::Encode(e.to_string()))?;
            rec.revoked = true;
            let bytes = bincode::serialize(&rec).map_err(|e| StoreError::Encode(e.to_string()))?;
            self.db.put(record_key(&h).as_bytes(), bytes)?;
            return Ok(());
        }
        // Balance key — revoke under the per-key lock so it can't race a debit.
        let keylock = self.lock_for(&h);
        let _guard = keylock.lock();
        if let Some(b) = self.db.get(bal_key(&h).as_bytes())? {
            let mut rec: BalanceRecord =
                bincode::deserialize(&b).map_err(|e| StoreError::Encode(e.to_string()))?;
            rec.revoked = true;
            let bytes = bincode::serialize(&rec).map_err(|e| StoreError::Encode(e.to_string()))?;
            self.db.put_opt(bal_key(&h).as_bytes(), bytes, &synced())?;
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
            if let Ok(r) = bincode::deserialize::<KeyRecord>(&v) {
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
        let raw = self.db.get(record_key(&h).as_bytes())?;
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
            let day = today_yyyymmdd();
            let day_key = quota_key(&h, &day);
            let cur = self
                .db
                .get(day_key.as_bytes())?
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
            self.db.put(day_key.as_bytes(), next.to_le_bytes())?;
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

    #[test]
    fn create_get_list_revoke_roundtrip() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path()).unwrap();

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
        let store = PersistentKeyStore::open(dir.path()).unwrap();
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
        let store = PersistentKeyStore::open(dir.path()).unwrap();
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
            let store = PersistentKeyStore::open(dir.path()).unwrap();
            id = store.create_key("explorer", 0, 10).unwrap();
            // burn 3 daily ticks
            for _ in 0..3 {
                store.try_consume(&id).unwrap();
            }
        }
        // "restart" — drop and reopen
        let store = PersistentKeyStore::open(dir.path()).unwrap();
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
        let store = PersistentKeyStore::open(dir.path()).unwrap();
        let id = store.create_key("rev", 0, 0).unwrap();
        store.revoke(&id).unwrap();
        assert!(matches!(store.try_consume(&id), Err(ConsumeError::Revoked)));
    }

    #[test]
    fn unknown_key_returns_unknown() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path()).unwrap();
        assert!(matches!(
            store.try_consume("cgk_does_not_exist"),
            Err(ConsumeError::Unknown)
        ));
    }

    #[test]
    fn rate_limit_caps_per_second() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path()).unwrap();
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
        let store = PersistentKeyStore::open(dir.path()).unwrap();
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
            let store = PersistentKeyStore::open(dir.path()).unwrap();
            quota_id = store.create_key("proxy", 0, 5).unwrap();
            bal_id = store
                .create_balance_key("buyer", U256::from(42u64), H160::zero(), 0)
                .unwrap();
            // A quota key has no balance; a balance key has no quota record.
            assert!(store.get_balance(&quota_id).unwrap().is_none());
            assert!(store.get_record(&bal_id).unwrap().is_none());
        }
        // restart
        let store = PersistentKeyStore::open(dir.path()).unwrap();
        assert_eq!(store.get_record(&quota_id).unwrap().unwrap().daily_quota, 5);
        assert_eq!(
            store.get_balance(&bal_id).unwrap().unwrap(),
            U256::from(42u64)
        );
    }

    #[test]
    fn zero_quota_is_unlimited() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path()).unwrap();
        let id = store.create_key("uncapped", 0, 0).unwrap();
        // Burst far past anything we'd actually configure — should be fine.
        for _ in 0..200 {
            store.try_consume(&id).unwrap();
        }
    }
}
