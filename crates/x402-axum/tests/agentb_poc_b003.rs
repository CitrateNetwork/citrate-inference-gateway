//! Tripwire for IGW-B-003.
//!
//! An unpaid request can mint a challenge without authentication. The ledger
//! must not evict an older live challenge when a bounded ledger is full:
//! hardware-wallet and human approval flows can legitimately outlast newer
//! unpaid requests. The parent evicts the soonest-to-expire entry, which is
//! the honest challenge in this setup.

use ethereum_types::H256;
use x402_axum::NonceLedger;

const CAP: usize = 8;

fn nonce(byte: u8) -> H256 {
    H256::from([byte; 32])
}

#[test]
fn flood_cannot_evict_an_existing_live_challenge() {
    let ledger = NonceLedger::new(CAP);
    let honest = nonce(0xee);

    // The honest payer receives a challenge first and has until 1300 to
    // approve it. Each attacker challenge is newer and expires later.
    ledger.record(honest, 1_300, 1_000);
    for byte in 0..(CAP as u8 - 1) {
        ledger.record(nonce(byte), 1_301 + u64::from(byte), 1_000);
    }
    assert_eq!(ledger.outstanding(), CAP);

    // Simulate a sustained unauthenticated unpaid flood. All entries remain
    // live, so the parent eviction branch is exercised rather than pruning.
    for byte in 1u8..=32 {
        ledger.record(nonce(byte.wrapping_add(32)), 1_400 + u64::from(byte), 1_001);
    }

    assert_eq!(
        ledger.consume(&honest, 1_299),
        Ok(()),
        "an unpaid flood must not invalidate an older live payer challenge"
    );
    assert_ne!(
        ledger.consume(&honest, 1_299),
        Ok(()),
        "the challenge remains single-use"
    );
}
