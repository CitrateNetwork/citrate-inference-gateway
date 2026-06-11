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
//!   non-zero value works; the default is OS entropy so multiple
//!   facilitator instances cannot collide even if they share a clock.
//! - `counter` is an atomic `u64` bumped per call; overflow at 2^64
//!   is not a real concern.
//! - `rand` is 8 fresh bytes from the OS per call.
//!
//! # Entropy policy (2026-05-31 audit -003, SECREM-02 6.4a)
//!
//! This module FAILS CLOSED on entropy. Pre-fix, a `getrandom` failure
//! silently degraded to a **time-seeded SplitMix64** — a payment nonce an
//! attacker who can estimate the boot/request time could reconstruct and
//! pre-sign against. A predictable payment nonce is strictly worse than a
//! 500, so now:
//!
//! - [`NonceSource::next_nonce`] returns `Err(NonceEntropyError)` when the
//!   OS RNG fails — the caller refuses to issue the challenge (the layer
//!   maps this to a 500 at challenge time).
//! - Construction ([`NonceSource::new`]) panics if the OS RNG cannot seed
//!   the process tag — boot-time fail-closed.
//! - Every entropy failure is logged at `error` level (telemetry).

use std::sync::atomic::{AtomicU64, Ordering};

use ethereum_types::H256;
use sha3::{Digest, Keccak256};

/// OS entropy was unavailable — the nonce source refuses to emit a
/// predictable nonce (2026-05-31 audit -003: no silent fallback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceEntropyError;

impl std::fmt::Display for NonceEntropyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OS entropy unavailable: refusing to mint a predictable payment nonce"
        )
    }
}

impl std::error::Error for NonceEntropyError {}

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
    ///
    /// # Panics
    /// Panics if the OS entropy source is unavailable at construction —
    /// a facilitator without a CSPRNG must not boot (audit -003,
    /// fail-closed; the pre-fix behavior silently fell back to a
    /// time-seeded PRNG).
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            panic!("NonceSource: {e} — refusing to start the x402 challenge path")
        })
    }

    /// Fallible constructor — returns an error instead of panicking when
    /// the OS entropy source is unavailable.
    pub fn try_new() -> Result<Self, NonceEntropyError> {
        let mut process_id = [0u8; 32];
        fill_random(&mut process_id)?;
        Ok(Self {
            process_id,
            counter: AtomicU64::new(0),
        })
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
    ///
    /// Fails closed: if the OS RNG cannot supply the per-call random
    /// bytes, returns [`NonceEntropyError`] — the caller must refuse to
    /// issue the challenge rather than mint a predictable nonce
    /// (audit -003).
    pub fn next_nonce(&self) -> Result<H256, NonceEntropyError> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut rand_bytes = [0u8; 8];
        fill_random(&mut rand_bytes)?;

        let mut hasher = Keccak256::new();
        hasher.update(self.process_id);
        hasher.update(counter.to_be_bytes());
        hasher.update(rand_bytes);
        Ok(H256::from_slice(hasher.finalize().as_slice()))
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

#[cfg(test)]
thread_local! {
    /// Test-only switch simulating an OS entropy outage on the current
    /// thread. Thread-local so parallel tests don't poison each other.
    static FAIL_ENTROPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Fill `dst` from the OS CSPRNG, or fail CLOSED.
///
/// 2026-05-31 audit -003: the previous implementation fell back to a
/// `SystemTime`-seeded SplitMix64 when `getrandom` failed — a silently
/// predictable payment nonce. There is no fallback anymore: a kernel-RNG
/// failure is surfaced as an error (and logged) so the challenge path
/// returns a 500 instead of a guessable nonce.
fn fill_random(dst: &mut [u8]) -> Result<(), NonceEntropyError> {
    #[cfg(test)]
    {
        if FAIL_ENTROPY.with(|f| f.get()) {
            tracing::error!(
                "x402 nonce entropy FAILURE (test-injected): refusing to mint a nonce"
            );
            return Err(NonceEntropyError);
        }
    }
    ::getrandom::fill(dst).map_err(|e| {
        // Telemetry: a dead kernel RNG is a severe host problem AND a
        // payment-security event — make it loud.
        tracing::error!(
            error = %e,
            "x402 nonce entropy FAILURE: getrandom failed; refusing to mint \
             a predictable payment nonce (2026-05-31 audit -003, fail-closed)"
        );
        NonceEntropyError
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn next_nonce_is_32_bytes() {
        let src = NonceSource::new();
        let n = src.next_nonce().expect("entropy available");
        assert_eq!(n.as_bytes().len(), 32);
    }

    #[test]
    fn next_nonce_is_non_zero() {
        let src = NonceSource::new();
        let n = src.next_nonce().expect("entropy available");
        assert!(!n.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn ten_thousand_nonces_are_all_distinct() {
        // Catches a broken RNG or a missing counter increment.
        let src = NonceSource::new();
        let mut seen: HashSet<H256> = HashSet::with_capacity(10_000);
        for _ in 0..10_000 {
            let n = src.next_nonce().expect("entropy available");
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
            combined.insert(a.next_nonce().expect("entropy"));
            combined.insert(b.next_nonce().expect("entropy"));
        }
        assert_eq!(combined.len(), 2000);
    }

    #[test]
    fn deterministic_with_fixed_tag_differs_per_call() {
        // Even with a fixed process_id, per-call randomness keeps
        // nonces distinct. (Without per-call randomness, this test
        // would fail — that would indicate the counter-only path.)
        let src = NonceSource::with_process_id([0xee; 32]);
        let a = src.next_nonce().expect("entropy");
        let b = src.next_nonce().expect("entropy");
        assert_ne!(a, b);
    }

    /// 2026-05-31 audit -003 (SECREM-02 6.4a): when the OS RNG fails,
    /// `next_nonce` must return an error — NOT fall back to a
    /// time-seeded PRNG. Pre-fix this returned a SplitMix64-derived
    /// "nonce" an attacker could reconstruct from a clock estimate.
    #[test]
    fn entropy_failure_fails_closed_no_fallback() {
        let src = NonceSource::with_process_id([0xee; 32]);
        FAIL_ENTROPY.with(|f| f.set(true));
        let r = src.next_nonce();
        FAIL_ENTROPY.with(|f| f.set(false));
        assert_eq!(r, Err(NonceEntropyError), "must refuse, never degrade");
    }

    /// Companion: construction also fails closed during an entropy
    /// outage — a facilitator without a CSPRNG must not boot.
    #[test]
    fn construction_fails_closed_without_entropy() {
        FAIL_ENTROPY.with(|f| f.set(true));
        let r = NonceSource::try_new();
        FAIL_ENTROPY.with(|f| f.set(false));
        assert!(r.is_err(), "try_new must refuse without entropy");
    }
}
