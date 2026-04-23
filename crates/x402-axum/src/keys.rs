//! Shared secp256k1 key helpers used by both the server (operator
//! wallet for settlement tx signing) and the client (payer wallet
//! for `transferWithAuthorization` signing).
//!
//! Kept isolated so that the only place k256 wallet derivation
//! happens is here — one definition, one set of tests. Drift
//! between how the layer derives an operator address and how the
//! client derives a payer address would be a silent auth bug.

use ethereum_types::H160;
use sha3::{Digest, Keccak256};

use crate::error::X402Error;

/// Derive the Ethereum address for a secp256k1 private key.
/// Returns `None` if the bytes are not a valid scalar in the
/// secp256k1 group order.
pub fn derive_secp256k1_address(secret: &[u8; 32]) -> Option<H160> {
    let signing_key = k256::ecdsa::SigningKey::from_bytes(secret.into()).ok()?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    if pubkey_bytes.len() != 65 {
        return None;
    }
    let mut h = Keccak256::new();
    h.update(&pubkey_bytes[1..]);
    let hash = h.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Some(H160::from(addr))
}

/// ECDSA-sign a prehashed 32-byte digest with a secp256k1 key.
/// Returns `(v, r, s)` where:
/// - `v` is 27 or 28 (compatible with pre-EIP-155 and
///   EIP-3009 signatures — the facilitator precompile accepts
///   27/28 per `x402.rs:229-232`)
/// - `r`, `s` are 32 bytes each
pub fn sign_digest_secp256k1(
    secret: &[u8; 32],
    digest: &[u8; 32],
) -> Result<(u8, [u8; 32], [u8; 32]), X402Error> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    let signing_key = SigningKey::from_bytes(secret.into())
        .map_err(|e| X402Error::Internal(format!("invalid secret: {}", e)))?;
    let (sig, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = signing_key
        .sign_prehash(digest)
        .map_err(|e| X402Error::Internal(format!("sign failed: {}", e)))?;

    let sig_bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);
    // EIP-3009 signatures use the pre-EIP-155 convention: v = 27 + recovery.
    let v = 27 + u8::from(recovery_id);
    Ok((v, r, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic known-valid scalar. Same as sign_tx::tests.
    fn any_secret() -> [u8; 32] {
        [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ]
    }

    #[test]
    fn address_derivation_is_deterministic() {
        let a = derive_secp256k1_address(&any_secret()).expect("ok");
        let b = derive_secp256k1_address(&any_secret()).expect("ok");
        assert_eq!(a, b);
        assert_ne!(a, H160::zero());
    }

    #[test]
    fn all_zero_secret_rejected() {
        assert!(derive_secp256k1_address(&[0u8; 32]).is_none());
    }

    #[test]
    fn different_secrets_produce_different_addresses() {
        let a = derive_secp256k1_address(&any_secret()).expect("ok");
        let mut other = any_secret();
        other[0] ^= 0xff;
        let b = derive_secp256k1_address(&other).expect("ok");
        assert_ne!(a, b);
    }

    #[test]
    fn sign_digest_is_deterministic() {
        // k256 uses RFC 6979 deterministic nonces — signing the
        // same digest twice must produce the same (v, r, s).
        let digest = [0xcd; 32];
        let (v1, r1, s1) = sign_digest_secp256k1(&any_secret(), &digest).expect("ok");
        let (v2, r2, s2) = sign_digest_secp256k1(&any_secret(), &digest).expect("ok");
        assert_eq!(v1, v2);
        assert_eq!(r1, r2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn sign_digest_v_is_27_or_28() {
        let digest = [0xcd; 32];
        let (v, _, _) = sign_digest_secp256k1(&any_secret(), &digest).expect("ok");
        assert!(v == 27 || v == 28, "got v = {}", v);
    }

    #[test]
    fn sign_digest_rejects_all_zero_secret() {
        let digest = [0xcd; 32];
        let err = sign_digest_secp256k1(&[0u8; 32], &digest).expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(_)));
    }
}
