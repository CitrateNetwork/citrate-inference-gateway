//! Server-issued challenge-nonce ledger.
//!
//! Closes CITRATE_INFERENCE_GATEWAY-2026-05-31-001: pre-fix, `run_paid_path`
//! accepted any well-formed payment payload regardless of whether its nonce
//! came from a challenge this gateway minted. The on-chain
//! `WrappedSALT._authorizationStates` map prevents the same nonce settling
//! twice, but nothing bound the *gateway's* paid path to its own issued
//! challenges — a payer could self-mint nonces and pre-sign payloads at will.
//!
//! Post-fix every nonce minted by `make_challenge` is recorded here with the
//! challenge's expiry, and `run_paid_path` consumes it (present + unexpired,
//! removed on first use) before any chain work. Unknown, expired, or reused
//! nonces are rejected with a fresh challenge.
//!
//! Single-instance scope: the ledger is in-memory, so a multi-instance
//! deployment needs sticky routing or a shared store. Today's topology is a
//! single gateway process (see `GATEWAY_DEPLOY_HANDOFF.md`); revisit when
//! that changes.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use ethereum_types::H256;

/// Upper bound on outstanding (unconsumed, unexpired) challenges.
pub const DEFAULT_MAX_OUTSTANDING: usize = 100_000;

/// Why a nonce was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceLedgerError {
    /// Never issued by this gateway, or already consumed by a prior payment.
    Unknown,
    /// Issued, but its challenge TTL has elapsed.
    Expired,
    /// The payment reused a valid nonce for a different method/path/body.
    RequestMismatch,
}

/// Thread-safe ledger of issued challenge nonces → expiry (unix seconds).
pub struct NonceLedger {
    inner: Mutex<LedgerState>,
    max_outstanding: usize,
}

#[derive(Clone, Copy)]
struct LedgerEntry {
    expires_at: u64,
    sequence: u64,
    request_commitment: H256,
}

struct LedgerState {
    entries: HashMap<H256, LedgerEntry>,
    insertion_order: BTreeMap<u64, H256>,
    next_sequence: u64,
}

impl NonceLedger {
    /// An empty ledger that holds at most `max_outstanding` unexpired nonces.
    pub fn new(max_outstanding: usize) -> Self {
        Self {
            inner: Mutex::new(LedgerState {
                entries: HashMap::new(),
                insertion_order: BTreeMap::new(),
                next_sequence: 0,
            }),
            max_outstanding,
        }
    }

    /// Record a freshly minted challenge nonce. Prunes expired entries; if
    /// the ledger is still full, evicts the newest live entry. Preserving
    /// older challenges prevents an unpaid challenge flood from invalidating
    /// a payer's already-issued approval window.
    pub fn record(&self, nonce: H256, expires_at: u64, now: u64) {
        self.record_bound(nonce, H256::zero(), expires_at, now);
    }

    /// Record a challenge nonce bound to one exact request commitment.
    pub fn record_bound(&self, nonce: H256, request_commitment: H256, expires_at: u64, now: u64) {
        if self.max_outstanding == 0 {
            return;
        }

        let mut state = self.inner.lock().expect("nonce ledger poisoned");

        // A repeated nonce is not expected from the challenge generator, but
        // removing it first keeps the two indexes consistent if that ever
        // occurs.
        if let Some(previous) = state.entries.remove(&nonce) {
            state.insertion_order.remove(&previous.sequence);
        }

        if state.entries.len() >= self.max_outstanding {
            let expired_sequences: Vec<_> = state
                .entries
                .values()
                .filter_map(|entry| (entry.expires_at <= now).then_some(entry.sequence))
                .collect();
            for sequence in expired_sequences {
                state.insertion_order.remove(&sequence);
            }
            state.entries.retain(|_, entry| entry.expires_at > now);
        }

        while state.entries.len() >= self.max_outstanding {
            let Some((&sequence, &candidate)) = state.insertion_order.iter().next_back() else {
                break;
            };
            state.insertion_order.remove(&sequence);
            state.entries.remove(&candidate);
        }

        let sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.entries.insert(
            nonce,
            LedgerEntry {
                expires_at,
                sequence,
                request_commitment,
            },
        );
        state.insertion_order.insert(sequence, nonce);
    }

    /// Consume an issued nonce: present + unexpired → removed and Ok.
    /// Removal happens on first use, so a second payment with the same
    /// nonce — even before the first settles — sees `Unknown`.
    pub fn consume(&self, nonce: &H256, now: u64) -> Result<(), NonceLedgerError> {
        self.consume_bound(nonce, &H256::zero(), now)
    }

    /// Consume an issued nonce only when it is still live and is being used
    /// for the exact request that minted it. A commitment mismatch leaves the
    /// nonce available for the legitimate retry.
    pub fn consume_bound(
        &self,
        nonce: &H256,
        request_commitment: &H256,
        now: u64,
    ) -> Result<(), NonceLedgerError> {
        let mut state = self.inner.lock().expect("nonce ledger poisoned");
        match state.entries.get(nonce).copied() {
            None => Err(NonceLedgerError::Unknown),
            Some(entry) if entry.expires_at <= now => {
                state.entries.remove(nonce);
                state.insertion_order.remove(&entry.sequence);
                Err(NonceLedgerError::Expired)
            }
            Some(entry) if entry.request_commitment != *request_commitment => {
                Err(NonceLedgerError::RequestMismatch)
            }
            Some(entry) => {
                state.entries.remove(nonce);
                state.insertion_order.remove(&entry.sequence);
                Ok(())
            }
        }
    }

    /// Outstanding (recorded, not yet consumed) nonce count.
    pub fn outstanding(&self) -> usize {
        self.inner
            .lock()
            .expect("nonce ledger poisoned")
            .entries
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(b: u8) -> H256 {
        H256::from([b; 32])
    }

    #[test]
    fn issued_nonce_consumes_exactly_once() {
        let ledger = NonceLedger::new(8);
        ledger.record(n(1), 1_000, 500);
        assert_eq!(ledger.consume(&n(1), 600), Ok(()));
        // Second use — replay — is Unknown (removed on first consume).
        assert_eq!(ledger.consume(&n(1), 600), Err(NonceLedgerError::Unknown));
    }

    #[test]
    fn never_issued_nonce_is_unknown() {
        let ledger = NonceLedger::new(8);
        assert_eq!(ledger.consume(&n(9), 0), Err(NonceLedgerError::Unknown));
    }

    #[test]
    fn expired_nonce_is_refused() {
        let ledger = NonceLedger::new(8);
        ledger.record(n(2), 1_000, 500);
        assert_eq!(ledger.consume(&n(2), 1_000), Err(NonceLedgerError::Expired));
    }

    #[test]
    fn request_mismatch_does_not_consume_live_nonce() {
        let ledger = NonceLedger::new(8);
        ledger.record_bound(n(3), n(4), 1_000, 500);
        assert_eq!(
            ledger.consume_bound(&n(3), &n(5), 600),
            Err(NonceLedgerError::RequestMismatch)
        );
        assert_eq!(ledger.consume_bound(&n(3), &n(4), 600), Ok(()));
    }

    #[test]
    fn full_ledger_prunes_expired_then_evicts_newest() {
        let ledger = NonceLedger::new(2);
        ledger.record(n(1), 100, 0); // will be expired by now=200
        ledger.record(n(2), 1_000, 0);
        // Full; n(1) expired → pruned, mint succeeds.
        ledger.record(n(3), 2_000, 200);
        assert_eq!(ledger.outstanding(), 2);
        assert_eq!(ledger.consume(&n(1), 200), Err(NonceLedgerError::Unknown));
        // Full with nothing expired → newest entry (n(3)) evicted, preserving
        // the older live challenge n(2).
        ledger.record(n(4), 3_000, 200);
        assert_eq!(ledger.consume(&n(2), 200), Ok(()));
        assert_eq!(ledger.consume(&n(3), 200), Err(NonceLedgerError::Unknown));
        assert_eq!(ledger.consume(&n(4), 200), Ok(()));
    }
}
