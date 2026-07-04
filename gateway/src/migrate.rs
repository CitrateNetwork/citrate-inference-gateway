//! `migrate` — one-shot plaintext→encrypted store migration (ENCRYPT-S1 / WP-2).
//!
//! The pre-ENCRYPT-S1 money store is plaintext RocksDB, and money data cannot
//! be wiped-and-resynced (unlike chain state), so it is migrated in place:
//!
//! 1. Open the source DB **read-write** (never `open_for_read_only` — RocksDB
//!    read-only opens skip WAL replay, and the freshest balance commits live
//!    in the WAL; a read-only scan of a crash-stopped gateway would migrate
//!    STALE balances). The RocksDB `LOCK` file also makes this refuse to run
//!    while the gateway service still holds the DB — stop it first.
//! 2. Refuse anything that isn't a clean known state: already-encrypted under
//!    a different key, unknown key namespaces, or values that don't parse as
//!    the expected schema (mixed/corrupt stores never get half-migrated).
//! 3. Copy every row into a fresh encrypted staging dir (`<path>.migrating`),
//!    verify EVERY row decrypts back to the source bytes, then swap:
//!    `<path>` → `<path>.pre-encrypt-<ts>` (rollback copy),
//!    `<path>.migrating` → `<path>`.
//!
//! Idempotent: a second run sees the encryption marker and exits cleanly
//! with [`SourceState::AlreadyEncrypted`]. A crash mid-copy leaves only the
//! staging dir, which the next run deletes and rebuilds. A crash between the
//! two renames is the only manual case (both `<path>.pre-encrypt-<ts>` and a
//! verified `<path>.migrating` exist, `<path>` missing) — finish by renaming
//! the staging dir into place (runbook §rollback).
//!
//! `--dry-run` opens the source, classifies + counts rows, and writes
//! NOTHING (no staging dir, no generated key).

use std::path::{Path, PathBuf};

use rocksdb::{IteratorMode, Options, DB};

use crate::keystore::{self, PersistentKeyStore, StoreError};

/// What the source DB turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceState {
    /// Marker present and it decrypts under the supplied key — nothing to do.
    AlreadyEncrypted,
    /// No marker, rows parse as the known plaintext schema — migratable.
    Plaintext,
}

/// Outcome of a (dry-)run.
#[derive(Debug)]
pub struct MigrateReport {
    /// Source classification.
    pub state: SourceState,
    /// Total data rows seen (excluding the `meta:enc` marker).
    pub entries: usize,
    /// Row counts per key namespace, e.g. `("bal", 3)`.
    pub per_namespace: Vec<(String, usize)>,
    /// `true` if nothing was written.
    pub dry_run: bool,
    /// Where the plaintext pre-migration copy went (real runs only).
    pub backup: Option<PathBuf>,
}

/// Why the migration refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// Source DB directory does not exist.
    #[error("no keystore at {0} — nothing to migrate")]
    Missing(PathBuf),
    /// RocksDB error (including "LOCK held" when the gateway is still running).
    #[error("rocksdb: {0} (is the gateway service stopped?)")]
    Db(String),
    /// Store is already encrypted, but not under the supplied key.
    #[error(
        "store is already encrypted under a DIFFERENT master key — refusing; \
         locate the original key (env {env}, key file) before touching this store",
        env = crate::keyvault::ENV_STORE_KEY
    )]
    WrongKey,
    /// A real (non-dry) run needs the master key.
    #[error("a master key is required for a real migration run")]
    KeyRequired,
    /// A row that doesn't belong to the known plaintext schema — mixed or
    /// corrupt store; never half-migrate it.
    #[error(
        "unrecognized row {0:?} — refusing to migrate a mixed/unknown-schema store \
         (expected only record:/quota:/bal:/batch:/batchset:/mbudget: rows)"
    )]
    Unrecognized(String),
    /// Filesystem step failed.
    #[error("io at {0}: {1}")]
    Io(PathBuf, String),
    /// Encrypted staging store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Post-copy verification mismatch — staging dir is left for forensics,
    /// source untouched.
    #[error("verify failed at row {0:?}: migrated value does not round-trip")]
    Verify(String),
}

/// Classify a plaintext row; `Err` on anything outside the known schema.
fn check_known_row(key: &[u8], value: &[u8]) -> Result<&'static str, MigrateError> {
    let printable = || String::from_utf8_lossy(key).into_owned();
    let ns = match key.iter().position(|b| *b == b':') {
        Some(i) => &key[..i],
        None => return Err(MigrateError::Unrecognized(printable())),
    };
    match ns {
        b"record" => {
            bincode::deserialize::<keystore::KeyRecord>(value)
                .map_err(|_| MigrateError::Unrecognized(printable()))?;
            Ok("record")
        }
        b"bal" => {
            bincode::deserialize::<keystore::BalanceRecord>(value)
                .map_err(|_| MigrateError::Unrecognized(printable()))?;
            Ok("bal")
        }
        b"quota" if value.len() == 8 => Ok("quota"),
        b"mbudget" if value.len() == 32 => Ok("mbudget"),
        b"batchset" if value.len() == 1 => Ok("batchset"),
        // Batch snapshots are opaque here (bincode of batch::PersistedBatch,
        // private to batch.rs); the namespace itself is the check.
        b"batch" => Ok("batch"),
        _ => Err(MigrateError::Unrecognized(printable())),
    }
}

/// Run the migration (or, with `dry_run`, just classify + count).
///
/// `master` may be `None` only for a dry run (a plaintext dry run never needs
/// the key; an encrypted store without a key reports `AlreadyEncrypted`
/// without verifying WHICH key).
pub fn migrate_encrypt(
    path: &Path,
    master: Option<[u8; 32]>,
    dry_run: bool,
) -> Result<MigrateReport, MigrateError> {
    if !path.exists() {
        return Err(MigrateError::Missing(path.to_path_buf()));
    }
    if master.is_none() && !dry_run {
        return Err(MigrateError::KeyRequired);
    }

    // (1) Open read-write for WAL replay; also acquires the LOCK so a live
    // gateway makes this fail instead of racing it.
    let opts = Options::default();
    let src = DB::open(&opts, path).map_err(|e| MigrateError::Db(e.to_string()))?;

    // (2) Already encrypted? Verify the key if we have one — idempotent exit.
    if let Some(raw) = src
        .get(keystore::ENC_MARKER_KEY.as_bytes())
        .map_err(|e| MigrateError::Db(e.to_string()))?
    {
        if let Some(master) = &master {
            let ok = keystore::open_value(master, keystore::ENC_MARKER_KEY.as_bytes(), &raw)
                .map(|pt| pt == keystore::ENC_MARKER_PLAINTEXT)
                .unwrap_or(false);
            if !ok {
                return Err(MigrateError::WrongKey);
            }
        }
        return Ok(MigrateReport {
            state: SourceState::AlreadyEncrypted,
            entries: 0,
            per_namespace: Vec::new(),
            dry_run,
            backup: None,
        });
    }

    // (3) Scan + classify every plaintext row. Any surprise aborts before a
    // single byte is written.
    let mut rows: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut counts: Vec<(String, usize)> = Vec::new();
    for item in src.iterator(IteratorMode::Start) {
        let (k, v) = item.map_err(|e| MigrateError::Db(e.to_string()))?;
        let ns = check_known_row(&k, &v)?;
        match counts.iter_mut().find(|(n, _)| n == ns) {
            Some((_, c)) => *c += 1,
            None => counts.push((ns.to_string(), 1)),
        }
        rows.push((k.to_vec(), v.to_vec()));
    }
    let entries = rows.len();

    if dry_run {
        return Ok(MigrateReport {
            state: SourceState::Plaintext,
            entries,
            per_namespace: counts,
            dry_run: true,
            backup: None,
        });
    }
    let master = master.expect("checked above");

    // (4) Copy into a fresh encrypted staging dir. A leftover from a crashed
    // run is stale by definition — rebuild it from scratch.
    let staging = sibling(path, ".migrating");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|e| MigrateError::Io(staging.clone(), e.to_string()))?;
    }
    {
        let enc = PersistentKeyStore::open(&staging, master)?;
        for (k, v) in &rows {
            enc.raw_put_sealed(k, v)?;
        }
        // (5) Verify EVERY row decrypts back to the exact source bytes
        // before anything irreversible happens.
        for (k, v) in &rows {
            let got = enc.raw_get_unsealed(k)?;
            if got.as_deref() != Some(v.as_slice()) {
                return Err(MigrateError::Verify(String::from_utf8_lossy(k).into_owned()));
            }
        }
        enc.flush()?;
    } // staging DB closed
    drop(src); // release the source LOCK before the rename

    // (6) Swap. The backup rename and the staging rename are two separate
    // atomic renames; a crash exactly between them is recoverable by hand
    // (runbook §rollback) and loses nothing.
    let backup = sibling(path, &format!(".pre-encrypt-{}", timestamp()));
    std::fs::rename(path, &backup).map_err(|e| MigrateError::Io(backup.clone(), e.to_string()))?;
    std::fs::rename(&staging, path)
        .map_err(|e| MigrateError::Io(staging.clone(), e.to_string()))?;

    Ok(MigrateReport {
        state: SourceState::Plaintext,
        entries,
        per_namespace: counts,
        dry_run: false,
        backup: Some(backup),
    })
}

/// `<path><suffix>` as a sibling path (keeps the parent directory).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

/// Filesystem-safe UTC timestamp for the backup dir name.
fn timestamp() -> String {
    chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H160, U256};
    use keystore::{hash_key_id, BalanceRecord, KeyRecord};

    const MASTER: [u8; 32] = [42u8; 32];

    /// Build a realistic pre-ENCRYPT-S1 plaintext fixture DB: a quota key
    /// record, a money balance record, a daily-quota counter, and a
    /// per-model budget. Returns the two bearer tokens.
    fn plaintext_fixture(path: &Path) -> (String, String) {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path).unwrap();

        let quota_id = "cgk_fixture_quota".to_string();
        let rec = KeyRecord {
            label: "PROBE-LABEL-DO-NOT-LEAK".into(),
            created_at: 1,
            revoked: false,
            quota_rps: 5,
            daily_quota: 100,
        };
        db.put(
            format!("record:{}", hash_key_id(&quota_id)).as_bytes(),
            bincode::serialize(&rec).unwrap(),
        )
        .unwrap();
        db.put(
            format!("quota:{}:20260701", hash_key_id(&quota_id)).as_bytes(),
            3u64.to_le_bytes(),
        )
        .unwrap();

        let bal_id = "cgk_fixture_money".to_string();
        let mut balance_be = [0u8; 32];
        U256::from(555_000u64).to_big_endian(&mut balance_be);
        let bal = BalanceRecord {
            label: "MONEY-LABEL-DO-NOT-LEAK".into(),
            created_at: 2,
            revoked: false,
            backing: 0,
            deposit_address: H160::from_slice(&[0xAB; 20]).0,
            balance_be,
        };
        db.put(
            format!("bal:{}", hash_key_id(&bal_id)).as_bytes(),
            bincode::serialize(&bal).unwrap(),
        )
        .unwrap();

        let mut budget_be = [0u8; 32];
        U256::from(9_000u64).to_big_endian(&mut budget_be);
        db.put(
            format!("mbudget:{}:llama-3.1-8b", hash_key_id(&bal_id)).as_bytes(),
            budget_be,
        )
        .unwrap();

        (quota_id, bal_id)
    }

    #[test]
    fn dry_run_reports_counts_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("keystore");
        plaintext_fixture(&db_path);

        let report = migrate_encrypt(&db_path, None, true).unwrap();
        assert_eq!(report.state, SourceState::Plaintext);
        assert_eq!(report.entries, 4);
        assert!(report.dry_run && report.backup.is_none());

        // Nothing written: no staging, no backup, source still plaintext
        // (openable as encrypted → PlaintextStore refusal).
        assert!(!sibling(&db_path, ".migrating").exists());
        let err = PersistentKeyStore::open(&db_path, MASTER).err().expect("must fail");
        assert!(matches!(err, StoreError::PlaintextStore));
    }

    #[test]
    fn migrate_preserves_balances_and_leaves_only_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("keystore");
        let (quota_id, bal_id) = plaintext_fixture(&db_path);

        let report = migrate_encrypt(&db_path, Some(MASTER), false).unwrap();
        assert_eq!(report.state, SourceState::Plaintext);
        assert_eq!(report.entries, 4);
        let backup = report.backup.clone().unwrap();
        assert!(backup.exists(), "pre-migration rollback copy exists");

        // Balances + records + budgets are byte-equal through the real API.
        let store = PersistentKeyStore::open(&db_path, MASTER).unwrap();
        assert_eq!(
            store.get_balance(&bal_id).unwrap().unwrap(),
            U256::from(555_000u64)
        );
        let rec = store.get_record(&quota_id).unwrap().unwrap();
        assert_eq!(rec.label, "PROBE-LABEL-DO-NOT-LEAK");
        assert_eq!(
            store
                .get_model_budget(&bal_id, "llama-3.1-8b")
                .unwrap()
                .unwrap(),
            U256::from(9_000u64)
        );
        drop(store);

        // Hexdump probe: the plaintext markers are gone from the migrated
        // dir…
        let leak = |root: &Path| {
            walk(root).into_iter().any(|f| {
                std::fs::read(&f)
                    .map(|b| {
                        b.windows(23).any(|w| w == b"MONEY-LABEL-DO-NOT-LEAK".as_slice())
                            || b.windows(20).any(|w| w == [0xABu8; 20])
                    })
                    .unwrap_or(false)
            })
        };
        assert!(!leak(&db_path), "migrated store still leaks plaintext");
        // …and (sanity of the probe itself) present in the plaintext backup.
        assert!(leak(&backup), "probe should find plaintext in the backup copy");
    }

    #[test]
    fn second_run_is_an_idempotent_noop() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("keystore");
        plaintext_fixture(&db_path);

        migrate_encrypt(&db_path, Some(MASTER), false).unwrap();
        let again = migrate_encrypt(&db_path, Some(MASTER), false).unwrap();
        assert_eq!(again.state, SourceState::AlreadyEncrypted);
        assert!(again.backup.is_none(), "no second backup, nothing rewritten");
    }

    #[test]
    fn encrypted_under_a_different_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("keystore");
        plaintext_fixture(&db_path);
        migrate_encrypt(&db_path, Some(MASTER), false).unwrap();

        let err = migrate_encrypt(&db_path, Some([1u8; 32]), false).unwrap_err();
        assert!(matches!(err, MigrateError::WrongKey));
    }

    #[test]
    fn unknown_namespace_refuses_the_whole_migration() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("keystore");
        plaintext_fixture(&db_path);
        {
            let db = DB::open(&Options::default(), &db_path).unwrap();
            db.put(b"mystery:row", b"???").unwrap();
        }
        let err = migrate_encrypt(&db_path, Some(MASTER), true).unwrap_err();
        assert!(matches!(err, MigrateError::Unrecognized(_)));
        assert!(!sibling(&db_path, ".migrating").exists());
    }

    #[test]
    fn missing_key_on_a_real_run_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("keystore");
        plaintext_fixture(&db_path);
        let err = migrate_encrypt(&db_path, None, false).unwrap_err();
        assert!(matches!(err, MigrateError::KeyRequired));
    }

    /// Recursively list files (probe helper — mirrors keystore::tests::walk,
    /// duplicated because that one is `cfg(test)` within its own module).
    fn walk(dir: &Path) -> Vec<PathBuf> {
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
