//! INFER-S3 / WP-E — per-model budgets (durable sub-ledger).
//!
//! Spec-first: the per-model budget is an orthogonal `mbudget:` sub-ledger on
//! the durable store — a model with no budget is uncapped; a capped model
//! exhausts independently of other models and of the overall balance, refunds
//! attribute to the right bucket, and never overspends under concurrency.
//!
//! Sprint: .agentile/sprints/active/INFER-S3-WPE-per-model-budgets.md

use std::sync::Arc;
use std::thread;

use citrate_gateway::keystore::{ModelBudgetError, PersistentKeyStore};
use ethereum_types::{H160, U256};

const BACKING_SALT: u8 = 0;
fn salt(n: u64) -> U256 {
    U256::from(n)
}

fn key(store: &PersistentKeyStore) -> String {
    store
        .create_balance_key("buyer", salt(1_000_000), H160::zero(), BACKING_SALT)
        .expect("create")
}

/// A capped model exhausts independently: llama 402s once its budget is spent,
/// while an uncapped model (mistral) keeps working.
#[test]
fn model_budget_exhausts_independently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path()).expect("open");
    let k = key(&store);

    store.set_model_budget(&k, "llama-3.1-8b", salt(5)).expect("set");

    // Spend the llama budget down to 0.
    store.debit_model_budget(&k, "llama-3.1-8b", salt(3)).expect("debit 3");
    store.debit_model_budget(&k, "llama-3.1-8b", salt(2)).expect("debit 2");

    // Further llama spend is refused; the remaining budget is reported.
    match store.debit_model_budget(&k, "llama-3.1-8b", salt(1)) {
        Err(ModelBudgetError::Exceeded(remaining)) => assert_eq!(remaining, salt(0)),
        other => panic!("expected Exceeded(0), got {other:?}"),
    }

    // An uncapped model is unaffected (no budget set → no-op Ok).
    store.debit_model_budget(&k, "mistral-7b", salt(1000)).expect("uncapped ok");
}

/// A refund credits the model bucket it was debited from — not the overall, not
/// another model.
#[test]
fn refund_attributes_to_the_right_model_bucket() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path()).expect("open");
    let k = key(&store);
    store.set_model_budget(&k, "llama-3.1-8b", salt(5)).expect("set llama");
    store.set_model_budget(&k, "mistral-7b", salt(5)).expect("set mistral");

    store.debit_model_budget(&k, "llama-3.1-8b", salt(4)).expect("debit"); // llama -> 1
    store.refund_model_budget(&k, "llama-3.1-8b", salt(4)).expect("refund"); // llama -> 5

    assert_eq!(store.get_model_budget(&k, "llama-3.1-8b").expect("get").expect("set"), salt(5));
    // mistral untouched
    assert_eq!(store.get_model_budget(&k, "mistral-7b").expect("get").expect("set"), salt(5));
}

/// An uncapped model debit is a no-op and never creates a budget.
#[test]
fn uncapped_model_is_passthrough() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path()).expect("open");
    let k = key(&store);
    store.debit_model_budget(&k, "gpt-whatever", salt(10)).expect("uncapped ok");
    assert!(store.get_model_budget(&k, "gpt-whatever").expect("get").is_none());
    // refund on an uncapped model is also a harmless no-op
    store.refund_model_budget(&k, "gpt-whatever", salt(10)).expect("refund ok");
}

/// Budgets are durable across a restart.
#[test]
fn model_budget_survives_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let k;
    {
        let store = PersistentKeyStore::open(dir.path()).expect("open");
        k = key(&store);
        store.set_model_budget(&k, "llama-3.1-8b", salt(5)).expect("set");
        store.debit_model_budget(&k, "llama-3.1-8b", salt(3)).expect("debit"); // -> 2
    }
    let store = PersistentKeyStore::open(dir.path()).expect("reopen");
    assert_eq!(store.get_model_budget(&k, "llama-3.1-8b").expect("get").expect("set"), salt(2));
}

/// Concurrent debits of one model budget never overspend.
#[test]
fn concurrent_model_debits_never_overspend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path()).expect("open");
    let k = key(&store);
    store.set_model_budget(&k, "llama-3.1-8b", salt(300)).expect("set");

    let threads: Vec<_> = (0..50)
        .map(|_| {
            let store = Arc::clone(&store);
            let k = k.clone();
            thread::spawn(move || store.debit_model_budget(&k, "llama-3.1-8b", salt(10)).is_ok())
        })
        .collect();
    let ok = threads.into_iter().map(|t| t.join().expect("join")).filter(|&b| b).count();
    assert_eq!(ok, 30, "exactly floor(300/10) debits commit");
    assert_eq!(store.get_model_budget(&k, "llama-3.1-8b").expect("get").expect("set"), salt(0));
}

/// `get_model_budgets` enumerates all capped models for a key.
#[test]
fn list_model_budgets_enumerates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path()).expect("open");
    let k = key(&store);
    store.set_model_budget(&k, "llama-3.1-8b", salt(5)).expect("a");
    store.set_model_budget(&k, "mistral-7b", salt(9)).expect("b");
    let mut got = store.get_model_budgets(&k).expect("list");
    got.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(got, vec![("llama-3.1-8b".to_string(), salt(5)), ("mistral-7b".to_string(), salt(9))]);
}
