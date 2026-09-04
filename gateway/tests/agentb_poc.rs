//! Tripwire for IGW-B-002 (x402 batch refund never paid).
//!
//! History: the blind leg of the 2026-09-02 federation graded audit dropped a
//! PoC here (`poc_igw_b_002_x402_batch_refund_is_never_paid`) proving the hole:
//! a batch paid for with x402 (no API key) that fails reported a non-zero
//! `refunded_grains` to the buyer, but `settle_batch` / `recover` only ever
//! credited an API-key payer — the `(None, refund>0)` arm fell to
//! `_ => mark_batch_settled(...)`, so the advertised refund was a phantom.
//!
//! This is the TRIPWIRE the finding asks for: the cross-product
//!   {api-key payer, x402 payer} × {all-done, partial, all-errored}
//! asserting that whenever `refunded_grains > 0` the run ends with a REAL
//! credit — a balance delta for a key payer, a recorded durable obligation
//! (the honest-accounting close; on-chain reversal is IGW-B-017) for an x402
//! payer — and that NO path reaches `mark_batch_settled` with `refund > 0`
//! left unhandled.
//!
//! It drives `BatchStore::recover()` (public, deterministic, no network),
//! which shares the exact `match (payer, refund>0)` logic that both the
//! settle and recovery call sites use — so one fix covers both. RED on the
//! pre-fix arm (x402 refund → no obligation recorded); GREEN after.

use citrate_gateway::batch::BatchStore;
use citrate_gateway::keystore::PersistentKeyStore;
use ethereum_types::{H160, U256};

const TEST_MASTER: [u8; 32] = [7u8; 32];
const BACKING_SALT: u8 = 0;

fn salt(n: u64) -> U256 {
    U256::from(n)
}

/// Which payer settled the batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Payer {
    /// Funded API key — refunds credit the key's balance.
    ApiKey,
    /// x402 (keyless) — refunds have no balance to credit.
    X402,
}

/// How the batch's slots finished.
#[derive(Clone, Copy, Debug)]
enum Outcome {
    /// Every slot Done — refund is 0.
    AllDone,
    /// Some Done, some interrupted — partial refund.
    Partial,
    /// Every slot errored/interrupted — full refund.
    AllErrored,
}

const PAYER_ADDR_HEX: &str = "0x00000000000000000000000000000000000000b1";

fn payer_addr() -> H160 {
    let mut b = [0u8; 20];
    b[19] = 0xb1;
    H160::from(b)
}

/// Build a mid-flight persisted batch JSON: 3 slots of 30/40/30 grains, with
/// the given per-slot states, owned by the given payer.
fn persisted_batch(batch_id: &str, payer: Payer, key_id: Option<&str>, outcome: Outcome) -> String {
    // (state, quote) per slot. Non-"done" states refund their quote on
    // recovery; "done" releases it.
    let slot_states: [&str; 3] = match outcome {
        Outcome::AllDone => ["done", "done", "done"],
        Outcome::Partial => ["done", "dispatched", "pending"],
        Outcome::AllErrored => ["errored", "errored", "pending"],
    };
    let quotes = [30u64, 40, 30];
    let slots: Vec<String> = slot_states
        .iter()
        .zip(quotes.iter())
        .map(|(st, q)| {
            format!(
                r#"{{"state":"{st}","request":{{"model":"m","messages":[],"max_tokens":null,"stream":false}},"quoted_cost_grains":"{q}","error":null}}"#
            )
        })
        .collect();

    let (payer_api_key_id, x402_payer) = match payer {
        Payer::ApiKey => (
            format!("\"{}\"", key_id.expect("api-key payer needs a key id")),
            "null".to_string(),
        ),
        Payer::X402 => ("null".to_string(), format!("\"{PAYER_ADDR_HEX}\"")),
    };

    format!(
        r#"{{"id":"{batch_id}","status":"running","paid_escrow_grains":"100",
            "released_grains":"0","refunded_grains":"0",
            "payer_api_key_id":{payer_api_key_id},"x402_payer":{x402_payer},
            "created_at":0,"refund_settled":false,"slots":[{}]}}"#,
        slots.join(",")
    )
}

fn expected_refund(outcome: Outcome) -> U256 {
    match outcome {
        Outcome::AllDone => salt(0),
        Outcome::Partial => salt(70),     // 40 + 30 (non-done)
        Outcome::AllErrored => salt(100), // 30 + 40 + 30
    }
}

/// Run one cell of the cross-product through recovery and assert the money
/// invariant: refunded_grains > 0 ⇒ a real credit exists, and no batch with a
/// refund owed is marked settled with the obligation swallowed.
async fn assert_cell(payer: Payer, outcome: Outcome) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("open");

    let batch_id = format!("batch_{payer:?}_{outcome:?}");
    let key_id = match payer {
        Payer::ApiKey => Some(
            store
                .create_balance_key("buyer", salt(0), H160::zero(), BACKING_SALT)
                .expect("create key"),
        ),
        Payer::X402 => None,
    };

    let json = persisted_batch(&batch_id, payer, key_id.as_deref(), outcome);
    store
        .persist_batch(&batch_id, json.as_bytes())
        .expect("persist");

    let batches = BatchStore::with_persistence(store.clone());
    let (rehydrated, settled) = batches.recover().await;
    assert_eq!(
        (rehydrated, settled),
        (1, 1),
        "{payer:?}/{outcome:?}: reconciled"
    );

    let refund = expected_refund(outcome);
    assert!(
        store.batch_was_settled(&batch_id).expect("flag"),
        "{payer:?}/{outcome:?}: batch must be terminal after recovery"
    );

    if refund.is_zero() {
        // Nothing owed: no obligation, no credit.
        assert!(
            store.refund_owed(&batch_id).expect("owed").is_none(),
            "{payer:?}/{outcome:?}: zero refund must record no obligation"
        );
        return;
    }

    // A refund IS owed — it must have landed as a REAL credit, not a phantom.
    match payer {
        Payer::ApiKey => {
            let bal = store
                .get_balance(key_id.as_deref().unwrap())
                .expect("get")
                .expect("present");
            assert_eq!(
                bal, refund,
                "{payer:?}/{outcome:?}: api-key refund must credit the balance"
            );
            // The api-key path owes nothing to the x402 obligation ledger.
            assert!(
                store.refund_owed(&batch_id).expect("owed").is_none(),
                "{payer:?}/{outcome:?}: api-key refund must not leak into the x402 ledger"
            );
        }
        Payer::X402 => {
            // THE IGW-B-002 invariant: an x402 refund must be recorded as a
            // durable, named obligation — never silently marked settled.
            let owed = store
                .refund_owed(&batch_id)
                .expect("owed")
                .unwrap_or_else(|| {
                    panic!(
                        "{payer:?}/{outcome:?}: x402 refund of {refund} grains was reported but \
                         NO obligation was recorded — phantom refund (IGW-B-002)"
                    )
                });
            assert_eq!(
                owed.refund_grains,
                refund.to_string(),
                "{payer:?}/{outcome:?}: obligation amount must equal the reported refund"
            );
            assert_eq!(
                owed.payer.as_deref(),
                Some(PAYER_ADDR_HEX),
                "{payer:?}/{outcome:?}: obligation must name the x402 payer"
            );
            assert_eq!(owed.batch_id, batch_id);
        }
    }
}

// ── Tripwire ─────────────────────────────────────────────────────

#[tokio::test]
async fn tripwire_igw_b_002_refund_is_always_real_credit() {
    for payer in [Payer::ApiKey, Payer::X402] {
        for outcome in [Outcome::AllDone, Outcome::Partial, Outcome::AllErrored] {
            assert_cell(payer, outcome).await;
        }
    }
}

/// Focused restatement of the original PoC scenario: an x402 batch that fails
/// entirely reports a non-zero refund — and that refund must now be a recorded
/// obligation, not a phantom. This is the exact case the blind-leg PoC proved
/// was swallowed.
#[tokio::test]
async fn tripwire_igw_b_002_x402_all_errored_records_obligation() {
    assert_cell(Payer::X402, Outcome::AllErrored).await;

    // And the obligation is enumerable for reconciliation tooling.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).expect("open");
    let json = persisted_batch("batch_recon", Payer::X402, None, Outcome::AllErrored);
    store
        .persist_batch("batch_recon", json.as_bytes())
        .expect("persist");
    let batches = BatchStore::with_persistence(store.clone());
    let _ = batches.recover().await;

    let owed = store.load_refunds_owed().expect("load owed");
    assert_eq!(
        owed.len(),
        1,
        "the outstanding obligation must be enumerable"
    );
    assert_eq!(owed[0].refund_grains, salt(100).to_string());
    assert_eq!(owed[0].payer.as_deref(), Some(PAYER_ADDR_HEX));
    let _ = payer_addr(); // documents the address the hex encodes
}
