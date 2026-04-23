//! Server-side challenge assembly — WP-02.2.
//!
//! Glues the pieces together: pricing → nonce generation → digest
//! computation → JSON response body. The `X402Layer` calls into this
//! module for every unpaid request.

use std::time::{SystemTime, UNIX_EPOCH};

use ethereum_types::{H160, H256, U256};

use crate::digest::{eip712_digest, transfer_with_authorization_struct_hash, wsalt_domain_separator};
use crate::error::X402Error;
use crate::types::PaymentChallenge;

/// Inputs needed to build a challenge. Most come from the
/// `X402Config` owned by the layer; `amount_wei` and `payer` are
/// per-request.
#[derive(Debug, Clone)]
pub struct ChallengeInputs {
    /// Chain ID.
    pub chain_id: u64,
    /// `X402Facilitator` address.
    pub facilitator: H160,
    /// `WrappedSALT` address — the `verifyingContract` in the EIP-712
    /// domain separator.
    pub wsalt: H160,
    /// Treasury address (destination of net value after fees).
    pub recipient: H160,
    /// Wei the client must authorize.
    pub amount_wei: U256,
    /// Payer address — the authorization's `from`.
    pub payer: H160,
    /// Fresh server-generated nonce.
    pub nonce: H256,
    /// Current unix timestamp in seconds. Parameterized so tests
    /// don't depend on wall-clock.
    pub now_unix: u64,
    /// Challenge lifetime in seconds. Typically 300.
    pub ttl_secs: u64,
}

/// Output of [`build_challenge`]: the public JSON body AND the
/// machine-usable digest the server stashes internally to match
/// against the retry's `X-PAYMENT` header.
#[derive(Debug, Clone)]
pub struct BuiltChallenge {
    /// The structured challenge to serialize into the 402 body.
    pub challenge: PaymentChallenge,
    /// Server-side copy of the digest the client is expected to sign.
    /// Not sent in the response; it's already derivable from the
    /// other fields. Retained for the eventual replay-check at
    /// verify time (WP-02.3).
    pub digest: H256,
}

/// Construct a [`BuiltChallenge`] from inputs. Pure function: no I/O,
/// no time peeking, no randomness — all inputs flow in.
pub fn build_challenge(inputs: ChallengeInputs) -> Result<BuiltChallenge, X402Error> {
    if inputs.amount_wei.is_zero() {
        return Err(X402Error::Internal(
            "challenge amount must be > 0".into(),
        ));
    }
    if inputs.ttl_secs == 0 {
        return Err(X402Error::Internal("ttl must be > 0".into()));
    }

    let valid_after = U256::from(inputs.now_unix);
    let valid_before = U256::from(inputs.now_unix.saturating_add(inputs.ttl_secs));

    let domain_separator = wsalt_domain_separator(inputs.chain_id, inputs.wsalt);
    let struct_hash = transfer_with_authorization_struct_hash(
        inputs.payer,
        inputs.recipient,
        inputs.amount_wei,
        valid_after,
        valid_before,
        inputs.nonce,
    );
    let digest = eip712_digest(domain_separator, struct_hash);

    let challenge = PaymentChallenge {
        version: 1,
        facilitator: hex_addr(inputs.facilitator),
        token: hex_addr(inputs.wsalt),
        chain_id: inputs.chain_id,
        amount: inputs.amount_wei.to_string(),
        nonce: hex_bytes32(inputs.nonce),
        valid_after: inputs.now_unix,
        valid_before: inputs.now_unix.saturating_add(inputs.ttl_secs),
        recipient: hex_addr(inputs.recipient),
        digest: hex_bytes32(digest),
    };

    Ok(BuiltChallenge { challenge, digest })
}

/// Convenience: unix-seconds `now`. Factored out so `build_challenge`
/// stays pure + testable. Production callers use this; tests pass
/// their own values.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_addr(addr: H160) -> String {
    format!("0x{}", hex::encode(addr.as_bytes()))
}

fn hex_bytes32(h: H256) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> ChallengeInputs {
        ChallengeInputs {
            chain_id: 40204,
            facilitator: H160::from([0xa1; 20]),
            wsalt: H160::from([0xa2; 20]),
            recipient: H160::from([0xa3; 20]),
            amount_wei: U256::from(1_000_000_000_000_000_000u128), // 1 SALT
            payer: H160::from([0xb1; 20]),
            nonce: H256::from([0x42; 32]),
            now_unix: 1_714_000_000,
            ttl_secs: 300,
        }
    }

    #[test]
    fn challenge_has_every_required_field() {
        // Per x402_payment.feature scenario #1.
        let BuiltChallenge { challenge, .. } = build_challenge(sample_inputs()).expect("ok");
        assert_eq!(challenge.version, 1);
        assert_eq!(challenge.chain_id, 40204);
        assert_eq!(challenge.amount, "1000000000000000000");
        assert!(challenge.facilitator.starts_with("0x"));
        assert!(challenge.token.starts_with("0x"));
        assert!(challenge.recipient.starts_with("0x"));
        assert!(challenge.nonce.starts_with("0x"));
        assert!(challenge.digest.starts_with("0x"));
        // Addresses are 20 bytes = 42 chars with 0x prefix.
        assert_eq!(challenge.facilitator.len(), 42);
        assert_eq!(challenge.token.len(), 42);
        assert_eq!(challenge.recipient.len(), 42);
        // bytes32 are 32 bytes = 66 chars with 0x prefix.
        assert_eq!(challenge.nonce.len(), 66);
        assert_eq!(challenge.digest.len(), 66);
    }

    #[test]
    fn valid_before_is_valid_after_plus_ttl() {
        // Gherkin: "valid_before = valid_after + 300s (5 min)"
        let inputs = sample_inputs();
        let BuiltChallenge { challenge, .. } = build_challenge(inputs.clone()).expect("ok");
        assert_eq!(challenge.valid_after, inputs.now_unix);
        assert_eq!(challenge.valid_before, inputs.now_unix + 300);
    }

    #[test]
    fn zero_amount_rejected() {
        let mut inputs = sample_inputs();
        inputs.amount_wei = U256::zero();
        let err = build_challenge(inputs).expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(m) if m.contains("amount")));
    }

    #[test]
    fn zero_ttl_rejected() {
        let mut inputs = sample_inputs();
        inputs.ttl_secs = 0;
        let err = build_challenge(inputs).expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(m) if m.contains("ttl")));
    }

    #[test]
    fn digest_is_deterministic_for_same_inputs() {
        // Same inputs → same digest. This is what the client signs;
        // non-determinism here would break verification.
        let a = build_challenge(sample_inputs()).expect("a");
        let b = build_challenge(sample_inputs()).expect("b");
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.challenge.digest, b.challenge.digest);
    }

    #[test]
    fn digest_varies_per_nonce() {
        let mut inputs = sample_inputs();
        let d1 = build_challenge(inputs.clone()).expect("d1").digest;
        inputs.nonce = H256::from([0x99; 32]);
        let d2 = build_challenge(inputs).expect("d2").digest;
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_varies_per_chain() {
        let mut inputs = sample_inputs();
        let d1 = build_challenge(inputs.clone()).expect("d1").digest;
        inputs.chain_id = 1; // Ethereum mainnet
        let d2 = build_challenge(inputs).expect("d2").digest;
        assert_ne!(d1, d2);
    }

    #[test]
    fn amount_serializes_as_decimal_string() {
        // JSON can't represent u256 natively — we emit decimal
        // strings to avoid precision loss for amounts > 2^53.
        let mut inputs = sample_inputs();
        inputs.amount_wei = U256::from_dec_str("123456789012345678901234").expect("parse");
        let c = build_challenge(inputs).expect("ok").challenge;
        assert_eq!(c.amount, "123456789012345678901234");
    }

    #[test]
    fn challenge_body_is_valid_json() {
        let c = build_challenge(sample_inputs()).expect("ok").challenge;
        let json = serde_json::to_string(&c).expect("serialize");
        // Round-trip via serde to confirm shape.
        let parsed: PaymentChallenge = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(parsed.version, c.version);
        assert_eq!(parsed.nonce, c.nonce);
        assert_eq!(parsed.digest, c.digest);
    }

    #[test]
    fn now_unix_secs_is_near_current_time() {
        // Sanity check the clock helper doesn't return absurd values.
        let n = now_unix_secs();
        assert!(n > 1_700_000_000); // after 2023-11
        assert!(n < 4_000_000_000); // before 2096
    }
}
