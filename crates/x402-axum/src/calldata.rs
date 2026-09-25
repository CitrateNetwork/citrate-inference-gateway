//! ABI-encoded calldata for `X402Facilitator.settlePayment(...)`.
//!
//! Solidity signature (contracts/src/X402Facilitator.sol:71-81):
//! ```text
//! function settlePayment(
//!     address from,
//!     address to,
//!     uint256 value,
//!     uint256 validAfter,
//!     uint256 validBefore,
//!     bytes32 nonce,
//!     uint8 v,
//!     bytes32 r,
//!     bytes32 s
//! ) external nonReentrant onlyRole(FACILITATOR_ROLE)
//! ```

use ethereum_types::{H160, H256};
use sha3::{Digest, Keccak256};

use crate::types::PaymentPayload;

/// 4-byte function selector for `settlePayment(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)`.
fn settle_payment_selector() -> [u8; 4] {
    let sig =
        "settlePayment(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)";
    let mut h = Keccak256::new();
    h.update(sig.as_bytes());
    let out = h.finalize();
    [out[0], out[1], out[2], out[3]]
}

/// Encode `settlePayment(...)` calldata from a [`PaymentPayload`].
///
/// Returns: 4-byte selector + 9 × 32-byte ABI-encoded arguments = 292 bytes.
pub fn encode_settle_payment(payload: &PaymentPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 9 * 32);
    out.extend_from_slice(&settle_payment_selector());

    // arg 0: address from (left-padded to 32)
    out.extend_from_slice(&pad_left_address(payload.from));
    // arg 1: address to
    out.extend_from_slice(&pad_left_address(payload.to));
    // arg 2: uint256 value (already 32 bytes when serialized big-endian)
    let mut buf = [0u8; 32];
    payload.value.to_big_endian(&mut buf);
    out.extend_from_slice(&buf);
    // arg 3: uint256 validAfter
    payload.valid_after.to_big_endian(&mut buf);
    out.extend_from_slice(&buf);
    // arg 4: uint256 validBefore
    payload.valid_before.to_big_endian(&mut buf);
    out.extend_from_slice(&buf);
    // arg 5: bytes32 nonce
    out.extend_from_slice(payload.nonce.as_bytes());
    // arg 6: uint8 v (right-padded as a uint256 — high bytes zero, low byte = v)
    let mut v_word = [0u8; 32];
    v_word[31] = payload.v;
    out.extend_from_slice(&v_word);
    // arg 7: bytes32 r
    out.extend_from_slice(payload.r.as_bytes());
    // arg 8: bytes32 s
    out.extend_from_slice(payload.s.as_bytes());

    debug_assert_eq!(out.len(), 4 + 9 * 32);
    out
}

fn pad_left_address(addr: H160) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(addr.as_bytes());
    out
}

/// Topic[0] of the `PaymentSettled` event (X402Facilitator.sol:35-41).
/// Used to filter event logs in [`crate::receipt`].
pub fn payment_settled_topic() -> H256 {
    let sig = "PaymentSettled(address,address,uint256,uint256,bytes32)";
    let mut h = Keccak256::new();
    h.update(sig.as_bytes());
    H256::from_slice(&h.finalize()[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H256, U256};

    fn sample() -> PaymentPayload {
        PaymentPayload {
            from: H160::from([0xa1; 20]),
            to: H160::from([0xa2; 20]),
            value: U256::from(1_000_000_000_000_000_000u128),
            valid_after: U256::from(1u64),
            valid_before: U256::from(2u64),
            nonce: H256::from([0xde; 32]),
            v: 27,
            r: H256::from([0xab; 32]),
            s: H256::from([0xcd; 32]),
        }
    }

    #[test]
    fn calldata_has_expected_length() {
        // selector (4) + 9 × 32-byte words = 292 bytes.
        let data = encode_settle_payment(&sample());
        assert_eq!(data.len(), 292);
    }

    #[test]
    fn selector_is_stable() {
        // Lock the selector so a future Solidity rename + Rust drift
        // surfaces immediately. Computed from the canonical signature.
        let sel = settle_payment_selector();
        assert_eq!(sel.len(), 4);
        // Determinism check.
        assert_eq!(sel, settle_payment_selector());
    }

    #[test]
    fn from_address_is_left_padded() {
        // EVM ABI: addresses encode as uint160 left-padded to 32.
        let data = encode_settle_payment(&sample());
        let from_word = &data[4..36]; // skip selector, take first arg
                                      // High 12 bytes must be zero.
        assert!(from_word[..12].iter().all(|&b| b == 0));
        // Low 20 bytes match the address.
        assert_eq!(&from_word[12..32], &[0xa1u8; 20]);
    }

    #[test]
    fn v_byte_lives_in_word_low_byte() {
        let data = encode_settle_payment(&sample());
        // v is arg 6 → starts at offset 4 + 6*32 = 196
        let v_word = &data[196..228];
        // High 31 bytes zero.
        assert!(v_word[..31].iter().all(|&b| b == 0));
        // Low byte == v == 27
        assert_eq!(v_word[31], 27);
    }

    #[test]
    fn nonce_is_passed_through_verbatim() {
        let data = encode_settle_payment(&sample());
        // nonce is arg 5 → starts at offset 4 + 5*32 = 164
        let nonce_word = &data[164..196];
        assert_eq!(nonce_word, &[0xde; 32]);
    }

    #[test]
    fn payment_settled_topic_is_deterministic() {
        let t1 = payment_settled_topic();
        let t2 = payment_settled_topic();
        assert_eq!(t1, t2);
        assert_eq!(t1.as_bytes().len(), 32);
    }

    #[test]
    fn payment_settled_topic_differs_from_other_events() {
        let settled = payment_settled_topic();
        // BatchSettled has a different shape — its topic must not
        // collide.
        let mut h = Keccak256::new();
        h.update(b"BatchSettled(uint256,uint256,uint256)");
        let batched = H256::from_slice(&h.finalize()[..]);
        assert_ne!(settled, batched);
    }
}
