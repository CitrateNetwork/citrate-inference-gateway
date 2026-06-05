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
use parking_lot::Mutex;
use rocksdb::{Options, DB};
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
        }))
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

    /// Mark a key revoked. Takes effect on the next request.
    pub fn revoke(&self, key_id: &str) -> Result<(), StoreError> {
        let h = hash_key_id(key_id);
        let raw = self.db.get(record_key(&h).as_bytes())?;
        let mut rec: KeyRecord = match raw {
            Some(b) => bincode::deserialize(&b).map_err(|e| StoreError::Encode(e.to_string()))?,
            None => return Err(StoreError::Unknown),
        };
        rec.revoked = true;
        let bytes = bincode::serialize(&rec).map_err(|e| StoreError::Encode(e.to_string()))?;
        self.db.put(record_key(&h).as_bytes(), bytes)?;
        Ok(())
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
