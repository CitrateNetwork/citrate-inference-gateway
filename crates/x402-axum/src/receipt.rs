//! Extract `PaymentSettled(address,address,uint256,uint256,bytes32)`
//! from a transaction receipt.
//!
//! The event is declared at `X402Facilitator.sol:35-41` with:
//!
//! - `from` (indexed) → topic[1]
//! - `to` (indexed)   → topic[2]
//! - `value` (non-indexed)
//! - `fee` (non-indexed)
//! - `nonce` (non-indexed)
//!
//! data section is `abi.encode(value, fee, nonce)` = 96 bytes.

use ethereum_types::{H160, H256, U256};

use crate::calldata::payment_settled_topic;
use crate::chain::TxReceipt;

/// Parsed fields from a single `PaymentSettled` log.
#[derive(Debug, Clone)]
pub struct PaymentSettledEvent {
    /// Payer address (topic[1]).
    pub from: H160,
    /// Recipient address (topic[2]).
    pub to: H160,
    /// Net value to recipient, in wei (first 32 bytes of data).
    pub value: U256,
    /// Facilitator fee in wei (bytes 32..64 of data).
    pub fee: U256,
    /// Nonce that was settled (bytes 64..96 of data).
    pub nonce: H256,
}

/// Scan a receipt for the first `PaymentSettled` log whose topic[0]
/// matches the canonical event signature. Returns `None` if the
/// receipt has no such log (indicates the tx succeeded but didn't
/// emit — contract bug or wrong receipt).
pub fn find_payment_settled(receipt: &TxReceipt, facilitator: H160) -> Option<PaymentSettledEvent> {
    let expected_topic0 = payment_settled_topic();
    for log in &receipt.logs {
        if log.address != facilitator {
            continue;
        }
        if log.topics.len() < 3 {
            continue;
        }
        if log.topics[0] != expected_topic0 {
            continue;
        }
        // topic[1] = from, topic[2] = to (both indexed addresses,
        // left-padded to 32 bytes).
        let from = H160::from_slice(&log.topics[1].as_bytes()[12..32]);
        let to = H160::from_slice(&log.topics[2].as_bytes()[12..32]);

        // Non-indexed args live in data, ABI-encoded, 32 bytes each.
        if log.data.len() < 96 {
            continue;
        }
        let value = U256::from_big_endian(&log.data[0..32]);
        let fee = U256::from_big_endian(&log.data[32..64]);
        let nonce = H256::from_slice(&log.data[64..96]);

        return Some(PaymentSettledEvent {
            from,
            to,
            value,
            fee,
            nonce,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::RawLog;

    fn padded_addr(addr: H160) -> H256 {
        let mut out = [0u8; 32];
        out[12..32].copy_from_slice(addr.as_bytes());
        H256::from(out)
    }

    fn sample_log(facilitator: H160) -> RawLog {
        let from = H160::from([0xa1; 20]);
        let to = H160::from([0xa2; 20]);
        let value: U256 = U256::from(995_000_000_000_000_000u128); // 0.995 SALT
        let fee: U256 = U256::from(5_000_000_000_000_000u128); // 0.005 SALT
        let nonce = H256::from([0xde; 32]);

        let mut data = Vec::with_capacity(96);
        let mut buf = [0u8; 32];
        value.to_big_endian(&mut buf);
        data.extend_from_slice(&buf);
        fee.to_big_endian(&mut buf);
        data.extend_from_slice(&buf);
        data.extend_from_slice(nonce.as_bytes());

        RawLog {
            address: facilitator,
            topics: vec![payment_settled_topic(), padded_addr(from), padded_addr(to)],
            data,
        }
    }

    #[test]
    fn finds_settled_event() {
        let fac = H160::from([0xfa; 20]);
        let receipt = TxReceipt {
            status: true,
            block_number: 42,
            logs: vec![sample_log(fac)],
        };
        let ev = find_payment_settled(&receipt, fac).expect("found");
        assert_eq!(ev.from, H160::from([0xa1; 20]));
        assert_eq!(ev.to, H160::from([0xa2; 20]));
        assert_eq!(ev.value, U256::from(995_000_000_000_000_000u128));
        assert_eq!(ev.fee, U256::from(5_000_000_000_000_000u128));
        assert_eq!(ev.nonce, H256::from([0xde; 32]));
    }

    #[test]
    fn ignores_logs_from_other_addresses() {
        let fac = H160::from([0xfa; 20]);
        let wrong = H160::from([0xdd; 20]);
        let receipt = TxReceipt {
            status: true,
            block_number: 42,
            logs: vec![sample_log(wrong)],
        };
        assert!(find_payment_settled(&receipt, fac).is_none());
    }

    #[test]
    fn ignores_wrong_topic0() {
        let fac = H160::from([0xfa; 20]);
        let mut log = sample_log(fac);
        log.topics[0] = H256::from([0xff; 32]);
        let receipt = TxReceipt {
            status: true,
            block_number: 1,
            logs: vec![log],
        };
        assert!(find_payment_settled(&receipt, fac).is_none());
    }

    #[test]
    fn returns_none_on_empty_logs() {
        let receipt = TxReceipt {
            status: true,
            block_number: 1,
            logs: vec![],
        };
        assert!(find_payment_settled(&receipt, H160::zero()).is_none());
    }

    #[test]
    fn ignores_truncated_data() {
        let fac = H160::from([0xfa; 20]);
        let mut log = sample_log(fac);
        log.data.truncate(40); // cut data below 96 bytes
        let receipt = TxReceipt {
            status: true,
            block_number: 1,
            logs: vec![log],
        };
        assert!(find_payment_settled(&receipt, fac).is_none());
    }
}
