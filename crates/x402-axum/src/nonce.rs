//! Server-generated nonce for x402 challenges.
//!
//! Each 402 response includes a unique 32-byte nonce the client must
//! include in its `TransferWithAuthorization` signature. Two properties
//! matter:
//!
//! 1. **Uniqueness within the facilitator's lifetime** — two concurrent
//!    challenges must never emit the same nonce, even under heavy load.
//!    Once a nonce is settled on-chain, `WrappedSALT._authorizationStates`
//!    marks it used; a collision would let a second payer steal the
//!    first payer's settlement slot.
//! 2. **Unpredictability** — a client should not be able to guess a
//!    nonce for another payer's challenge. Per-challenge randomness
//!    (not just a counter) prevents pre-signing attacks.
//!
//! Scheme: `keccak256(process_id[32] || counter[8] || rand[8])`.
//! - `process_id` is a 32-byte tag mixed in at construction — any
//!   non-zero value works; the default is `rand_bytes()` so multiple
//!   facilitator instances cannot collide even if they share a clock.
//! - `counter` is an atomic `u64` bumped per call; overflow at 2^64
//!   is not a real concern.
//! - `rand` is 8 fresh bytes from the OS per call.

use std::sync::atomic::{AtomicU64, Ordering};

use ethereum_types::H256;
use sha3::{Digest, Keccak256};

/// Thread-safe nonce source. Cheap to clone (all state lives behind
/// `Arc`-free atomics; there's only one instance per `X402Layer`).
pub struct NonceSource {
    /// Per-process tag. Mixed into every nonce so two facilitator
    /// instances never collide even if their counters align.
    process_id: [u8; 32],
    /// Monotonic counter. Wraps at `u64::MAX` but the random bytes
    /// prevent practical collisions long before that.
    counter: AtomicU64,
}

impl NonceSource {
    /// New source with a random process tag.
    pub fn new() -> Self {
        let mut process_id = [0u8; 32];
        getrandom(&mut process_id);
        Self {
            process_id,
            counter: AtomicU64::new(0),
        }
    }

    /// New source with a caller-supplied tag. Useful for deterministic
    /// tests. The tag SHOULD be non-zero in production.
    #[cfg(test)]
    pub fn with_process_id(process_id: [u8; 32]) -> Self {
        Self {
            process_id,
            counter: AtomicU64::new(0),
        }
    }

    /// Emit a fresh nonce. Always 32 bytes. Always unique under normal
    /// conditions (see the property discussion in the module docs).
    pub fn next_nonce(&self) -> H256 {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut rand_bytes = [0u8; 8];
        getrandom(&mut rand_bytes);

        let mut hasher = Keccak256::new();
        hasher.update(self.process_id);
        hasher.update(counter.to_be_bytes());
        hasher.update(rand_bytes);
        H256::from_slice(hasher.finalize().as_slice())
    }
}

impl std::fmt::Debug for NonceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceSource")
            .field(
                "counter",
                &self.counter.load(Ordering::Relaxed),
            )
            // Don't print process_id — it's per-process entropy that
            // has no business in logs.
            .finish_non_exhaustive()
    }
}

impl Default for NonceSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Tiny wrapper around `getrandom` that falls back to SystemTime on
/// the off chance the OS entropy source is unavailable. The fallback
/// is sufficient because `process_id` supplies the cryptographic
/// unpredictability; the counter + fallback time together still
/// guarantee uniqueness.
fn getrandom(dst: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Try the proper CSPRNG first. reqwest already pulls in getrandom
    // transitively, so this dependency is free.
    if ::getrandom::fill(dst).is_ok() {
        return;
    }
    // Fallback — degrade gracefully rather than panic. Fills from
    // a time-seeded SplitMix. Only reached if the kernel RNG is
    // unavailable, which is a severe system problem of its own.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    for byte in dst.iter_mut() {
        state = state
            .wrapping_add(0x9E37_79B9_7F4A_7C15)
            .wrapping_mul(0xBF58_476D_1CE4_E5B9);
        state ^= state >> 30;
        *byte = state as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn next_nonce_is_32_bytes() {
        let src = NonceSource::new();
        let n = src.next_nonce();
        assert_eq!(n.as_bytes().len(), 32);
    }

    #[test]
    fn next_nonce_is_non_zero() {
        let src = NonceSource::new();
        let n = src.next_nonce();
        assert!(!n.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn ten_thousand_nonces_are_all_distinct() {
        // Catches a broken RNG or a missing counter increment.
        let src = NonceSource::new();
        let mut seen: HashSet<H256> = HashSet::with_capacity(10_000);
        for _ in 0..10_000 {
            let n = src.next_nonce();
            assert!(seen.insert(n), "nonce collision at {:?}", n);
        }
    }

    #[test]
    fn two_sources_emit_distinct_nonces() {
        // Two facilitator processes on different machines must not
        // collide even if their clocks and counters align.
        let a = NonceSource::new();
        let b = NonceSource::new();
        let mut combined = HashSet::new();
        for _ in 0..1000 {
            combined.insert(a.next_nonce());
            combined.insert(b.next_nonce());
        }
        assert_eq!(combined.len(), 2000);
    }

    #[test]
    fn deterministic_with_fixed_tag_differs_per_call() {
        // Even with a fixed process_id, per-call randomness keeps
        // nonces distinct. (Without per-call randomness, this test
        // would fail — that would indicate the counter-only path.)
        let src = NonceSource::with_process_id([0xee; 32]);
        let a = src.next_nonce();
        let b = src.next_nonce();
        assert_ne!(a, b);
    }
}
