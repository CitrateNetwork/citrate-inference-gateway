//! INFER WP-B — persistent RocksDB keystore.
//!
//! Asserts the persistence + atomicity contract:
//!
//!   * create → persist → reload (a FRESH `ApiKeyStore` opened on the
//!     same path) returns the key with its balance,
//!   * debit then "crash" (drop the store) → reload shows the debit
//!     applied EXACTLY ONCE,
//!   * revoke persists across reload,
//!   * the plaintext `cgk_` token is NEVER on disk — only `sha256(id)`.
//!
//! Each test uses a `tempfile::TempDir` for the RocksDB directory.

use ethereum_types::{H160, U256};
use tempfile::TempDir;

use citrate_gateway::auth::{create_key, ApiKeyStore};

/// Reading the bytes of every file under `dir` (recursively).
fn read_all_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in walk(dir) {
        if let Ok(bytes) = std::fs::read(&entry) {
            out.extend_from_slice(&bytes);
        }
    }
    out
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                files.extend(walk(&p));
            } else {
                files.push(p);
            }
        }
    }
    files
}

#[tokio::test]
async fn create_persists_and_reloads_with_balance() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("keystore");

    let key_id = {
        let store = ApiKeyStore::open_rocksdb(&path).expect("open");
        let initial = U256::from(500u64);
        let id = create_key(&store, "pilot", initial, H160::from([0xde; 20])).await;
        // Sanity in the live store.
        let r = store.get(&id).await.expect("present");
        assert_eq!(r.balance_grains, U256::from(500u64));
        id
        // store dropped here — simulates process exit.
    };

    // Fresh instance, same path: record must reload.
    let reopened = ApiKeyStore::open_rocksdb(&path).expect("reopen");
    let r = reopened.get(&key_id).await.expect("reloaded");
    assert_eq!(r.label, "pilot");
    assert_eq!(r.balance_grains, U256::from(500u64));
    assert!(!r.revoked);
}

#[tokio::test]
async fn debit_then_crash_reload_applies_exactly_once() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("keystore");

    let key_id = {
        let store = ApiKeyStore::open_rocksdb(&path).expect("open");
        let id = create_key(&store, "pilot", U256::from(100u64), H160::zero()).await;
        let new_bal = store.debit(&id, U256::from(30u64)).await.expect("debit");
        assert_eq!(new_bal, U256::from(70u64));
        id
        // "crash": drop without any graceful flush beyond the WAL fsync
        // each debit already did.
    };

    let reopened = ApiKeyStore::open_rocksdb(&path).expect("reopen");
    let r = reopened.get(&key_id).await.expect("reloaded");
    assert_eq!(
        r.balance_grains,
        U256::from(70u64),
        "debit must be applied exactly once after crash-reload (not 0, not 100)"
    );
}

#[tokio::test]
async fn multiple_debits_persist_cumulatively_once_each() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("keystore");

    let key_id = {
        let store = ApiKeyStore::open_rocksdb(&path).expect("open");
        let id = create_key(&store, "pilot", U256::from(100u64), H160::zero()).await;
        for _ in 0..5 {
            store.debit(&id, U256::from(10u64)).await.expect("debit");
        }
        id
    };

    let reopened = ApiKeyStore::open_rocksdb(&path).expect("reopen");
    let r = reopened.get(&key_id).await.expect("reloaded");
    assert_eq!(
        r.balance_grains,
        U256::from(50u64),
        "five 10-grain debits should leave 50 after reload"
    );
}

#[tokio::test]
async fn revoke_persists_across_reload() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("keystore");

    let key_id = {
        let store = ApiKeyStore::open_rocksdb(&path).expect("open");
        let id = create_key(&store, "pilot", U256::from(100u64), H160::zero()).await;
        store.revoke(&id).await.expect("revoke");
        id
    };

    let reopened = ApiKeyStore::open_rocksdb(&path).expect("reopen");
    let r = reopened.get(&key_id).await.expect("reloaded");
    assert!(r.revoked, "revocation must survive a restart");
}

#[tokio::test]
async fn refund_persists_across_reload() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("keystore");

    let key_id = {
        let store = ApiKeyStore::open_rocksdb(&path).expect("open");
        let id = create_key(&store, "pilot", U256::from(100u64), H160::zero()).await;
        store.debit(&id, U256::from(40u64)).await.expect("debit");
        store.refund(&id, U256::from(10u64)).await.expect("refund");
        id
    };

    let reopened = ApiKeyStore::open_rocksdb(&path).expect("reopen");
    let r = reopened.get(&key_id).await.expect("reloaded");
    assert_eq!(r.balance_grains, U256::from(70u64));
}

#[tokio::test]
async fn plaintext_key_is_never_written_to_disk() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("keystore");

    let key_id = {
        let store = ApiKeyStore::open_rocksdb(&path).expect("open");
        create_key(&store, "secret", U256::from(100u64), H160::zero()).await
        // drop & flush so all SST/WAL bytes are on disk.
    };

    // Scan every on-disk byte for the plaintext cgk_ token.
    let bytes = read_all_bytes(&path);
    let needle = key_id.as_bytes();
    let found = bytes
        .windows(needle.len())
        .any(|w| w == needle);
    assert!(
        !found,
        "plaintext cgk_ token must NEVER appear on disk (audit F-3) — only sha256(id)"
    );
    assert!(!bytes.is_empty(), "expected the keystore to have written data");
}

#[cfg(unix)]
#[tokio::test]
async fn keystore_dir_is_locked_down_0700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("keystore");
    let store = ApiKeyStore::open_rocksdb(&path).expect("open");
    let _ = create_key(&store, "p", U256::from(1u64), H160::zero()).await;

    let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "keystore dir must be 0700, got {:o}", mode);
}
