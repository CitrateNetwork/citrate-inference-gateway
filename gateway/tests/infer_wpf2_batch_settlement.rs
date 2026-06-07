//! INFER-S4 / WP-F (slice F2) — durable batch + crash-safe exactly-once settlement.
//!
//! The money-critical core: when a batch reaches terminal, the buyer's refund
//! (errored + unprocessed slot quotes) and the "this batch is settled" marker
//! must commit atomically and apply EXACTLY ONCE across any crash — never
//! zero (buyer loses funds) and never twice (gateway loses funds).
//!
//! Sprint: .agentile/sprints/active/INFER-S4-WPF-durable-balances.md (F2)

use citrate_gateway::batch::BatchStore;
use citrate_gateway::keystore::PersistentKeyStore;
use ethereum_types::{H160, U256};

const BACKING_SALT: u8 = 0;

fn salt(n: u64) -> U256 {
    U256::from(n)
}

/// A batch's refund settles exactly once even if recovery replays it after a
/// crash: the second settle is a no-op (idempotent), so the buyer is credited
/// once and only once.
#[test]
fn batch_refund_settles_exactly_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let id;
    {
        let store = PersistentKeyStore::open(dir.path()).expect("open");
        // Buyer funded 100, batch debited the whole 100 up front (balance 0).
        id = store
            .create_balance_key("buyer", salt(0), H160::zero(), BACKING_SALT)
            .expect("create");

        // Batch is terminal: 40 grains owed back to the buyer (errored slots).
        let batch_bytes = br#"{"id":"batch_x","refund_settled":true}"#;
        let bal = store
            .settle_batch_refund(&id, salt(40), "batch_x", batch_bytes)
            .expect("settle");
        assert_eq!(bal, salt(40), "credited the refund once");

        // Recovery replays the same settlement (crash between credit + ack):
        // it must be a no-op, not a second credit.
        let bal2 = store
            .settle_batch_refund(&id, salt(40), "batch_x", batch_bytes)
            .expect("settle replay");
        assert_eq!(bal2, salt(40), "replay must NOT double-credit");
    }

    // And the credit + the settled marker survived the crash atomically.
    let store = PersistentKeyStore::open(dir.path()).expect("reopen");
    assert_eq!(store.get_balance(&id).expect("get").expect("present"), salt(40));
    assert!(store.batch_was_settled("batch_x").expect("settled flag"));
}

/// Persisted batch records are enumerable for the boot-recovery pass.
#[test]
fn batches_persist_and_enumerate_for_recovery() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = PersistentKeyStore::open(dir.path()).expect("open");
        store.persist_batch("batch_a", br#"{"id":"batch_a"}"#).expect("persist a");
        store.persist_batch("batch_b", br#"{"id":"batch_b"}"#).expect("persist b");
    }
    let store = PersistentKeyStore::open(dir.path()).expect("reopen");
    let mut ids: Vec<String> = store
        .load_batches()
        .expect("load")
        .into_iter()
        .map(|(id, _bytes)| id)
        .collect();
    ids.sort();
    assert_eq!(ids, vec!["batch_a".to_string(), "batch_b".to_string()]);
}

/// An unsettled batch is reported as not-settled; settlement flips it.
#[test]
fn batch_settled_flag_tracks_settlement() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path()).expect("open");
    let id = store
        .create_balance_key("buyer", salt(10), H160::zero(), BACKING_SALT)
        .expect("create");

    assert!(!store.batch_was_settled("batch_y").expect("flag"));
    store
        .settle_batch_refund(&id, salt(5), "batch_y", br#"{}"#)
        .expect("settle");
    assert!(store.batch_was_settled("batch_y").expect("flag"));
}

/// Boot recovery (the chaos gate): a batch persisted mid-flight — 1 completed
/// slot, 2 interrupted — is reconciled on restart so the buyer is refunded the
/// 2 un-completed slots' quotes EXACTLY ONCE, and a second recovery pass (a
/// crash during recovery) does not double-refund.
#[tokio::test]
async fn recovery_refunds_uncompleted_slots_exactly_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path()).expect("open");
    // Buyer funded 100, the whole 100 debited up front at submit (balance 0).
    let key = store
        .create_balance_key("buyer", salt(0), H160::zero(), BACKING_SALT)
        .expect("create");

    // A mid-flight batch: slot0 Done (30), slot1 Dispatched (40), slot2 Pending (30).
    let batch_json = format!(
        r#"{{"id":"batch_r","status":"running","paid_escrow_grains":"100",
            "released_grains":"0","refunded_grains":"0","payer_api_key_id":"{key}",
            "created_at":0,"refund_settled":false,"slots":[
            {{"state":"done","request":{{"model":"m","messages":[],"max_tokens":null,"stream":false}},"quoted_cost_grains":"30","error":null}},
            {{"state":"dispatched","request":{{"model":"m","messages":[],"max_tokens":null,"stream":false}},"quoted_cost_grains":"40","error":null}},
            {{"state":"pending","request":{{"model":"m","messages":[],"max_tokens":null,"stream":false}},"quoted_cost_grains":"30","error":null}}]}}"#
    );
    store.persist_batch("batch_r", batch_json.as_bytes()).expect("persist");

    let batches = BatchStore::with_persistence(store.clone());
    let (rehydrated, settled) = batches.recover().await;
    assert_eq!((rehydrated, settled), (1, 1), "one batch reconciled");

    // Refunded slot1 (40) + slot2 (30) = 70; slot0 (30) released to providers.
    assert_eq!(store.get_balance(&key).expect("get").expect("present"), salt(70));
    assert!(store.batch_was_settled("batch_r").expect("flag"));

    // A crash during recovery replays it — must NOT double-refund.
    let (_r2, s2) = batches.recover().await;
    assert_eq!(s2, 0, "already-settled batch is not re-settled");
    assert_eq!(store.get_balance(&key).expect("get").expect("present"), salt(70));
}
