//! INFER WP-B — persistent RocksDB backend for [`super::ApiKeyStore`].
//!
//! The keystore is a single RocksDB database holding one record per
//! API key. Records are keyed by `sha256(key_id)` (the same hash the
//! in-memory mirror uses — audit F-3), so **no plaintext bearer token
//! ever touches disk**. A RocksDB snapshot leak yields only hashes and
//! balances, never replayable key material.
//!
//! ## Atomicity / durability
//!
//! Each `put` is a single `DB::put` with `WriteOptions::set_sync(true)`,
//! so the write is fsync'd to the WAL before it returns. The caller
//! (`ApiKeyStore`) holds the in-memory write lock across the persist,
//! which serialises mutations: a committed debit lands in the WAL
//! exactly once and a crash-reload replays it exactly once. RocksDB's
//! own WAL recovery guarantees the last fsync'd value is what a fresh
//! `open` sees.
//!
//! ## At-rest hardening
//!
//! The DB directory is created `0700` and every file RocksDB writes is
//! chmod'd to `0600` (best-effort, Unix only) after `open`/`put` so a
//! co-tenant user can't read balances or hashes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rocksdb::{Options, WriteOptions, DB};

use super::ApiKeyRecord;

/// Errors from the persistent keystore backend.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// Underlying RocksDB error (open / read / write).
    #[error("rocksdb: {0}")]
    Rocks(#[from] rocksdb::Error),
    /// Record (de)serialization failed.
    #[error("codec: {0}")]
    Codec(#[from] bincode::Error),
    /// Filesystem error preparing the keystore directory / perms.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// RocksDB-backed persistent key→record store.
#[derive(Debug)]
pub struct RocksKeystore {
    db: DB,
    path: PathBuf,
}

impl RocksKeystore {
    /// Open or create the database at `path`. The parent directory is
    /// created `0700` if missing.
    pub fn open(path: &Path) -> Result<Self, KeystoreError> {
        // Create the dir with locked-down perms BEFORE RocksDB writes
        // any files into it, so the SST/WAL files inherit a private
        // directory.
        if !path.exists() {
            std::fs::create_dir_all(path)?;
        }
        Self::lock_down_dir(path)?;

        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        let store = Self {
            db,
            path: path.to_path_buf(),
        };
        store.lock_down_files()?;
        Ok(store)
    }

    /// Persist a single record under `sha256(key_id)` (passed in as the
    /// already-hashed hex string). Fsync'd to the WAL before returning.
    pub fn put(&self, key_hash: &str, record: &ApiKeyRecord) -> Result<(), KeystoreError> {
        let bytes = bincode::serialize(record)?;
        let mut wopts = WriteOptions::default();
        // Durability: block until the WAL entry is fsync'd. This is the
        // "committed exactly once, survives crash" guarantee for WP-B.
        wopts.set_sync(true);
        self.db.put_opt(key_hash.as_bytes(), &bytes, &wopts)?;
        // New SST/WAL files may have been created; re-tighten perms.
        let _ = self.lock_down_files();
        Ok(())
    }

    /// Load every persisted record into a `key_hash → record` map for
    /// the in-memory mirror on boot.
    pub fn load_all(&self) -> Result<HashMap<String, ApiKeyRecord>, KeystoreError> {
        let mut out = HashMap::new();
        for item in self.db.iterator(rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            let key_hash = String::from_utf8_lossy(&k).into_owned();
            let record: ApiKeyRecord = bincode::deserialize(&v)?;
            out.insert(key_hash, record);
        }
        Ok(out)
    }

    #[cfg(unix)]
    fn lock_down_dir(path: &Path) -> Result<(), KeystoreError> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, perms)?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn lock_down_dir(_path: &Path) -> Result<(), KeystoreError> {
        Ok(())
    }

    #[cfg(unix)]
    fn lock_down_files(&self) -> Result<(), KeystoreError> {
        use std::os::unix::fs::PermissionsExt;
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let perms = std::fs::Permissions::from_mode(0o600);
                // Best-effort: a transient RocksDB temp file may vanish
                // between read_dir and set_permissions.
                let _ = std::fs::set_permissions(entry.path(), perms);
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn lock_down_files(&self) -> Result<(), KeystoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H160, U256};

    fn sample_record() -> ApiKeyRecord {
        ApiKeyRecord {
            label: "unit".into(),
            balance_grains: U256::from(123u64),
            deposit_address: H160::from([0xab; 20]),
            revoked: false,
            backing: super::super::KeyBacking::Salt,
            created_at: 42,
        }
    }

    #[test]
    fn put_then_load_all_roundtrips_the_record() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = RocksKeystore::open(dir.path()).expect("open");
        let h = "deadbeef".to_string();
        store.put(&h, &sample_record()).expect("put");

        let all = store.load_all().expect("load");
        let r = all.get(&h).expect("present");
        assert_eq!(r.label, "unit");
        assert_eq!(r.balance_grains, U256::from(123u64));
        assert_eq!(r.created_at, 42);
    }

    #[test]
    fn reopen_sees_prior_writes() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        {
            let store = RocksKeystore::open(dir.path()).expect("open");
            store.put("k1", &sample_record()).expect("put");
        }
        let reopened = RocksKeystore::open(dir.path()).expect("reopen");
        let all = reopened.load_all().expect("load");
        assert!(all.contains_key("k1"));
    }

    /// The on-disk key is the sha256 hex we pass in — never the
    /// plaintext token (audit F-3). load_all preserves that key.
    #[test]
    fn keys_on_disk_are_the_hashed_form_we_supply() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = RocksKeystore::open(dir.path()).expect("open");
        let hashed = "a".repeat(64); // sha256 hex shape
        store.put(&hashed, &sample_record()).expect("put");
        let all = store.load_all().expect("load");
        assert_eq!(all.len(), 1);
        assert!(all.contains_key(&hashed));
    }
}
