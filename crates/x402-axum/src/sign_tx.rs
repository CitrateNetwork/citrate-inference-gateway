//! Build + sign a legacy EVM transaction (EIP-155) for the operator
//! wallet's settlement calls.
//!
//! This is a miniature of `citrate_wallet_core::TransactionBuilder`
//! focused on the operator-signs-a-contract-call flow:
//! - `to` is always set (settlement is a contract call, not a deploy)
//! - `value` is always 0 (settlement carries no native-token value)
//! - `data` is the encoded `settlePayment(...)` calldata
//! - signing uses secp256k1 ECDSA with EIP-155 chain binding
//!
//! We replicate the RLP logic locally instead of depending on
//! `citrate-wallet-core`'s internal types so this crate stays
//! narrowly scoped to x402 HTTP concerns.

use ethereum_types::{H160, U256};
use sha3::{Digest, Keccak256};

use crate::error::X402Error;

/// Fields needed to build a legacy tx.
pub struct SettlementTx<'a> {
    /// Chain ID for EIP-155.
    pub chain_id: u64,
    /// Operator's current tx nonce.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price_wei: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// `to` — the X402Facilitator contract.
    pub to: H160,
    /// ABI-encoded calldata (from [`crate::calldata::encode_settle_payment`]).
    pub data: &'a [u8],
}

/// Output of [`sign_settlement_tx`] — the raw signed RLP bytes
/// suitable for `eth_sendRawTransaction`.
#[derive(Debug, Clone)]
pub struct SignedSettlement {
    /// RLP-encoded signed tx, ready for the wire.
    pub raw: Vec<u8>,
}

/// Build and sign a settlement tx. The private key is consumed only
/// within this function and zeroed on drop by k256's own `SigningKey`.
pub fn sign_settlement_tx(
    tx: SettlementTx<'_>,
    operator_secret: &[u8; 32],
) -> Result<SignedSettlement, X402Error> {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    let signing_key = SigningKey::from_bytes(operator_secret.into())
        .map_err(|e| X402Error::Internal(format!("invalid operator secret: {}", e)))?;

    // EIP-155 signing message: RLP([nonce, gasPrice, gasLimit, to,
    // value, data, chainId, 0, 0]).
    let signable = encode_unsigned_rlp(&tx);
    let sighash = Keccak256::digest(&signable);

    let (sig, recovery_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = signing_key
        .sign_prehash(sighash.as_slice())
        .map_err(|e| X402Error::Internal(format!("sign failed: {}", e)))?;

    // v per EIP-155: chainId * 2 + 35 + recoveryByte.
    let v: u64 = tx.chain_id * 2 + 35 + u8::from(recovery_id) as u64;

    let sig_bytes = sig.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..];

    let raw = encode_signed_rlp(&tx, v, r, s);
    Ok(SignedSettlement { raw })
}

fn encode_unsigned_rlp(tx: &SettlementTx<'_>) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(9);
    append_u64(&mut stream, tx.nonce);
    append_u64(&mut stream, tx.gas_price_wei);
    append_u64(&mut stream, tx.gas_limit);
    stream.append(&tx.to.as_bytes());
    // value = 0 — encoded as empty bytes per RLP convention.
    append_u256(&mut stream, U256::zero());
    stream.append(&tx.data);
    append_u64(&mut stream, tx.chain_id);
    // Two empty fields per EIP-155.
    stream.append(&Vec::<u8>::new().as_slice());
    stream.append(&Vec::<u8>::new().as_slice());
    stream.out().to_vec()
}

fn encode_signed_rlp(tx: &SettlementTx<'_>, v: u64, r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(9);
    append_u64(&mut stream, tx.nonce);
    append_u64(&mut stream, tx.gas_price_wei);
    append_u64(&mut stream, tx.gas_limit);
    stream.append(&tx.to.as_bytes());
    append_u256(&mut stream, U256::zero());
    stream.append(&tx.data);
    append_u64(&mut stream, v);
    // r, s — strip leading zeros per RLP uint convention.
    stream.append(&strip_leading_zeros(r));
    stream.append(&strip_leading_zeros(s));
    stream.out().to_vec()
}

fn append_u64(stream: &mut rlp::RlpStream, v: u64) {
    if v == 0 {
        stream.append(&Vec::<u8>::new().as_slice());
    } else {
        let bytes = v.to_be_bytes();
        let mut i = 0;
        while i < 8 && bytes[i] == 0 {
            i += 1;
        }
        stream.append(&&bytes[i..]);
    }
}

fn append_u256(stream: &mut rlp::RlpStream, v: U256) {
    if v.is_zero() {
        stream.append(&Vec::<u8>::new().as_slice());
        return;
    }
    let mut buf = [0u8; 32];
    v.to_big_endian(&mut buf);
    let mut i = 0;
    while i < 32 && buf[i] == 0 {
        i += 1;
    }
    stream.append(&&buf[i..]);
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    &bytes[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_secret() -> [u8; 32] {
        // A deterministic, well-known test scalar so this test never
        // needs randomness. Known to be valid (below curve order).
        [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ]
    }

    #[test]
    fn signed_tx_produces_rlp_bytes() {
        let tx = SettlementTx {
            chain_id: 40204,
            nonce: 0,
            gas_price_wei: 1_000_000_000,
            gas_limit: 200_000,
            to: H160::from([0x42; 20]),
            data: &[0xde, 0xad, 0xbe, 0xef],
        };
        let signed = sign_settlement_tx(tx, &any_secret()).expect("sign");
        assert!(!signed.raw.is_empty());
        // RLP list starts with 0xc0-0xf7 (short list) or 0xf8-0xff
        // (long list with length-of-length prefix). Either way the
        // first nibble is 'c' or 'f'.
        assert!(signed.raw[0] >= 0xc0, "not an RLP list");
    }

    #[test]
    fn invalid_secret_surfaces_as_internal_error() {
        // All-zeros is not a valid secp256k1 scalar.
        let tx = SettlementTx {
            chain_id: 40204,
            nonce: 0,
            gas_price_wei: 1,
            gas_limit: 21_000,
            to: H160::zero(),
            data: &[],
        };
        let err = sign_settlement_tx(tx, &[0u8; 32]).expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(_)));
    }

    #[test]
    fn same_inputs_produce_same_signature() {
        // ECDSA with k256 uses deterministic nonces (RFC 6979), so
        // signing the same payload twice must yield identical bytes.
        // If this ever flips, we've either switched RNGs or changed
        // the tx structure — either is a regression worth catching.
        let data = [0xaa; 8];
        let mk = || SettlementTx {
            chain_id: 40204,
            nonce: 42,
            gas_price_wei: 1_000_000_000,
            gas_limit: 300_000,
            to: H160::from([0x11; 20]),
            data: &data,
        };
        let a = sign_settlement_tx(mk(), &any_secret()).expect("a");
        let b = sign_settlement_tx(mk(), &any_secret()).expect("b");
        assert_eq!(a.raw, b.raw);
    }

    #[test]
    fn different_nonces_produce_different_raw() {
        let data = [0xaa; 8];
        let mk = |n: u64| SettlementTx {
            chain_id: 40204,
            nonce: n,
            gas_price_wei: 1_000_000_000,
            gas_limit: 300_000,
            to: H160::from([0x11; 20]),
            data: &data,
        };
        let a = sign_settlement_tx(mk(0), &any_secret()).expect("a");
        let b = sign_settlement_tx(mk(1), &any_secret()).expect("b");
        assert_ne!(a.raw, b.raw);
    }
}
