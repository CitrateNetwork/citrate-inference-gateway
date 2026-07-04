//! INFER-S4 / WP-F (slice F1) — durable, crash-atomic balances.
//!
//! Spec-first: these exercise the durable balance API on `PersistentKeyStore`
//! that converges the marketplace money store onto RocksDB (TD-22 / TD-23).
//! They FAIL to compile/pass until WP-F lands, then prove balances survive a
//! restart and apply debits/refunds exactly once.
//!
//! Sprint: .agentile/sprints/active/INFER-S4-WPF-durable-balances.md
//! BDD: .agentile/features/infer-s4-wpf-durable-balances.feature

use std::sync::Arc;
use std::thread;

use citrate_gateway::keystore::{BalanceError, PersistentKeyStore};

/// Test master key for the at-rest store encryption (ENCRYPT-S1) — the
/// TD-22 durability guarantees are proven UNDER encryption.
const TEST_MASTER: [u8; 32] = [7u8; 32];
use ethereum_types::{H160, U256};

/// KeyBacking::Salt as the persisted u8 discriminant.
const BACKING_SALT: u8 = 0;

fn salt(n: u64) -> U256 {
    U256::from(n)
}

/// The headline property (TD-22): a committed debit survives a restart and is
/// applied exactly once — never lost (back to 100), never doubled (down to 40).
#[test]
fn debit_then_crash_reload_applies_exactly_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id;
    {
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("open");
        id = store
            .create_balance_key("buyer", salt(100), H160::zero(), BACKING_SALT)
            .expect("create");
        let bal = store.debit_balance(&id, salt(30)).expect("debit");
        assert_eq!(bal, salt(70), "in-process balance after debit");
    } // drop == process crash / restart

    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("reopen");
    let bal = store.get_balance(&id).expect("get").expect("present");
    assert_eq!(bal, salt(70), "exactly once: not 100 (lost), not 40 (doubled)");
}

/// A sequence of committed debits and refunds reconciles exactly across restart.
#[test]
fn balance_consistent_across_restart_with_refunds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id;
    {
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("open");
        id = store
            .create_balance_key("buyer", salt(100), H160::zero(), BACKING_SALT)
            .expect("create");
        store.debit_balance(&id, salt(30)).expect("debit");
        store.refund_balance(&id, salt(10)).expect("refund");
        store.debit_balance(&id, salt(5)).expect("debit");
        // 100 - 30 + 10 - 5 = 75
    }
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("reopen");
    assert_eq!(store.get_balance(&id).expect("get").expect("present"), salt(75));
}

/// An over-balance debit is refused and persists nothing (bounds preserved).
#[test]
fn insufficient_debit_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("open");
    let id = store
        .create_balance_key("buyer", salt(100), H160::zero(), BACKING_SALT)
        .expect("create");

    match store.debit_balance(&id, salt(150)) {
        Err(BalanceError::Insufficient(have)) => assert_eq!(have, salt(100)),
        other => panic!("expected Insufficient(100), got {other:?}"),
    }
    assert_eq!(store.get_balance(&id).expect("get").expect("present"), salt(100));

    // and across restart
    drop(store);
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("reopen");
    assert_eq!(store.get_balance(&id).expect("get").expect("present"), salt(100));
}

/// Refunds must credit even a revoked key (revocation stops spend, never traps
/// already-debited funds) — and the credit is durable.
#[test]
fn refund_credits_revoked_key_durably() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id;
    {
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("open");
        id = store
            .create_balance_key("buyer", salt(100), H160::zero(), BACKING_SALT)
            .expect("create");
        store.debit_balance(&id, salt(40)).expect("debit"); // -> 60
        store.revoke(&id).expect("revoke");

        // spending is blocked once revoked
        assert!(matches!(store.debit_balance(&id, salt(1)), Err(BalanceError::Revoked)));
        // but refunds still land
        store.refund_balance(&id, salt(40)).expect("refund"); // -> 100
    }
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("reopen");
    assert_eq!(store.get_balance(&id).expect("get").expect("present"), salt(100));
}

/// Concurrent debits of one funded key never overspend and never lose/double a
/// debit — the durable read-modify-write is atomic per key.
#[test]
fn concurrent_debits_never_overspend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("open");
    let id = store
        .create_balance_key("buyer", salt(1000), H160::zero(), BACKING_SALT)
        .expect("create");

    let threads: Vec<_> = (0..50)
        .map(|_| {
            let store = Arc::clone(&store);
            let id = id.clone();
            thread::spawn(move || store.debit_balance(&id, salt(30)).is_ok())
        })
        .collect();

    let successes = threads
        .into_iter()
        .map(|t| t.join().expect("join"))
        .filter(|&ok| ok)
        .count();
    // 1000 / 30 = 33 debits can succeed; the rest hit Insufficient.
    assert_eq!(successes, 33, "exactly floor(1000/30) debits should commit");

    let expected = salt(1000) - salt(30) * U256::from(successes as u64);
    assert_eq!(store.get_balance(&id).expect("get").expect("present"), expected);

    // and the durable value matches across restart
    drop(store);
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("reopen");
    assert_eq!(store.get_balance(&id).expect("get").expect("present"), expected);
}
