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

use std::collections::HashMap;
use std::sync::Mutex;

use ethereum_types::H256;

/// Upper bound on outstanding (unconsumed, unexpired) challenges. At the
/// default 300 s TTL this allows ~330 challenge mints per second sustained
/// before eviction kicks in — far above any legitimate load.
pub const DEFAULT_MAX_OUTSTANDING: usize = 100_000;

/// Why a nonce was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceLedgerError {
    /// Never issued by this gateway, or already consumed by a prior payment.
    Unknown,
    /// Issued, but its challenge TTL has elapsed.
    Expired,
}

/// Thread-safe ledger of issued challenge nonces → expiry (unix seconds).
pub struct NonceLedger {
    inner: Mutex<HashMap<H256, u64>>,
    max_outstanding: usize,
}

impl NonceLedger {
    pub fn new(max_outstanding: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_outstanding,
        }
    }

    /// Record a freshly minted challenge nonce. Prunes expired entries; if
    /// the ledger is still full, evicts the soonest-to-expire entry so a
    /// mint can never fail (the evicted challenge simply re-challenges).
    pub fn record(&self, nonce: H256, expires_at: u64, now: u64) {
        let mut map = self.inner.lock().expect("nonce ledger poisoned");
        if map.len() >= self.max_outstanding {
            map.retain(|_, exp| *exp > now);
        }
        if map.len() >= self.max_outstanding {
            if let Some(soonest) = map.iter().min_by_key(|(_, exp)| **exp).map(|(n, _)| *n) {
                map.remove(&soonest);
            }
        }
        map.insert(nonce, expires_at);
    }

    /// Consume an issued nonce: present + unexpired → removed and Ok.
    /// Removal happens on first use, so a second payment with the same
    /// nonce — even before the first settles — sees `Unknown`.
    pub fn consume(&self, nonce: &H256, now: u64) -> Result<(), NonceLedgerError> {
        let mut map = self.inner.lock().expect("nonce ledger poisoned");
        match map.remove(nonce) {
            None => Err(NonceLedgerError::Unknown),
            Some(expires_at) if expires_at <= now => Err(NonceLedgerError::Expired),
            Some(_) => Ok(()),
        }
    }

    /// Outstanding (recorded, not yet consumed) nonce count.
    pub fn outstanding(&self) -> usize {
        self.inner.lock().expect("nonce ledger poisoned").len()
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
    fn full_ledger_prunes_expired_then_evicts_soonest() {
        let ledger = NonceLedger::new(2);
        ledger.record(n(1), 100, 0); // will be expired by now=200
        ledger.record(n(2), 1_000, 0);
        // Full; n(1) expired → pruned, mint succeeds.
        ledger.record(n(3), 2_000, 200);
        assert_eq!(ledger.outstanding(), 2);
        assert_eq!(ledger.consume(&n(1), 200), Err(NonceLedgerError::Unknown));
        // Full with nothing expired → soonest expiry (n(2)) evicted.
        ledger.record(n(4), 3_000, 200);
        assert_eq!(ledger.consume(&n(2), 200), Err(NonceLedgerError::Unknown));
        assert_eq!(ledger.consume(&n(3), 200), Ok(()));
        assert_eq!(ledger.consume(&n(4), 200), Ok(()));
    }
}
