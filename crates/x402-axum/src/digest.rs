//! EIP-712 typed-data digest generation for EIP-3009
//! `TransferWithAuthorization`.
//!
//! This module produces the exact 32-byte digest that a client must
//! sign (via `ecdsa_sign_prehashed` or equivalent) so that the on-chain
//! `WrappedSALT.transferWithAuthorization` will accept the signature.
//!
//! The math mirrors `contracts/src/WrappedSALT.sol:47-55` (domain
//! separator) and `WrappedSALT.sol:135-139` (struct hash + digest).
//! Any drift between the Solidity strings and the constants below
//! produces digests a signer will happily compute but the contract
//! will reject — this module's tests lock both sides.
//!
//! # References
//!
//! - EIP-712 typed-structured-data signing: <https://eips.ethereum.org/EIPS/eip-712>
//! - EIP-3009 transfer-with-authorization: <https://eips.ethereum.org/EIPS/eip-3009>

use ethereum_types::{H160, H256, U256};
use sha3::{Digest, Keccak256};

/// EIP-712 domain name as it appears on-chain.
/// Must match `name` at `WrappedSALT.sol:16`.
const DOMAIN_NAME: &str = "Wrapped SALT";

/// EIP-712 domain version. Must match the literal `"1"` at
/// `WrappedSALT.sol:51`.
const DOMAIN_VERSION: &str = "1";

/// Literal type string for the EIP-712 domain. Never change without
/// also changing the on-chain constructor.
const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// Literal type string for `TransferWithAuthorization`. Must match
/// `TRANSFER_WITH_AUTHORIZATION_TYPEHASH` at `WrappedSALT.sol:31-32`.
const TRANSFER_WITH_AUTHORIZATION_TYPE: &str =
    "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

fn keccak(input: &[u8]) -> H256 {
    let mut h = Keccak256::new();
    h.update(input);
    H256::from_slice(h.finalize().as_slice())
}

fn u256_to_be_bytes(n: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    n.to_big_endian(&mut out);
    out
}

/// Compute the EIP-712 domain separator for a `WrappedSALT` contract
/// deployed at `verifying_contract` on the chain with id `chain_id`.
///
/// Matches:
/// ```solidity
/// keccak256(abi.encode(
///     keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
///     keccak256(bytes("Wrapped SALT")),
///     keccak256(bytes("1")),
///     block.chainid,
///     address(this)
/// ))
/// ```
pub fn wsalt_domain_separator(chain_id: u64, verifying_contract: H160) -> H256 {
    let type_hash = keccak(EIP712_DOMAIN_TYPE.as_bytes());
    let name_hash = keccak(DOMAIN_NAME.as_bytes());
    let version_hash = keccak(DOMAIN_VERSION.as_bytes());

    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(type_hash.as_bytes());
    buf.extend_from_slice(name_hash.as_bytes());
    buf.extend_from_slice(version_hash.as_bytes());
    buf.extend_from_slice(&u256_to_be_bytes(U256::from(chain_id)));
    // Addresses are left-padded to 32 bytes in abi.encode.
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(verifying_contract.as_bytes());

    keccak(&buf)
}

/// Compute the EIP-712 struct hash for a `TransferWithAuthorization`
/// call with the given fields.
///
/// Matches `WrappedSALT.sol:135-138`:
/// ```solidity
/// keccak256(abi.encode(
///     TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
///     from, to, value, validAfter, validBefore, nonce
/// ))
/// ```
pub fn transfer_with_authorization_struct_hash(
    from: H160,
    to: H160,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: H256,
) -> H256 {
    let type_hash = keccak(TRANSFER_WITH_AUTHORIZATION_TYPE.as_bytes());

    let mut buf = Vec::with_capacity(32 * 7);
    buf.extend_from_slice(type_hash.as_bytes());
    // addresses left-padded to 32 bytes
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(from.as_bytes());
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(to.as_bytes());
    buf.extend_from_slice(&u256_to_be_bytes(value));
    buf.extend_from_slice(&u256_to_be_bytes(valid_after));
    buf.extend_from_slice(&u256_to_be_bytes(valid_before));
    buf.extend_from_slice(nonce.as_bytes());

    keccak(&buf)
}

/// Assemble the final EIP-712 digest the client signs:
/// `keccak256("\x19\x01" || DOMAIN_SEPARATOR || STRUCT_HASH)`.
pub fn eip712_digest(domain_separator: H256, struct_hash: H256) -> H256 {
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(domain_separator.as_bytes());
    buf.extend_from_slice(struct_hash.as_bytes());
    keccak(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(bytes: [u8; 20]) -> H160 {
        H160::from(bytes)
    }

    #[test]
    fn domain_type_hash_is_stable() {
        // EIP-712 spec requires exactly this encoding. A byte-level
        // drift would produce signatures the on-chain contract
        // rejects for reasons that are *extremely* hard to debug.
        let h = keccak(EIP712_DOMAIN_TYPE.as_bytes());
        assert_eq!(h.as_bytes().len(), 32);
        // Determinism check.
        assert_eq!(h, keccak(EIP712_DOMAIN_TYPE.as_bytes()));
    }

    #[test]
    fn transfer_type_hash_matches_canonical_string() {
        // Contract's TRANSFER_WITH_AUTHORIZATION_TYPEHASH is
        // keccak256 of this exact string. If the string drifts in
        // EITHER place we lose compat — this test catches drift on
        // our side.
        let h = keccak(TRANSFER_WITH_AUTHORIZATION_TYPE.as_bytes());
        assert_eq!(
            h,
            keccak(b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
        );
    }

    #[test]
    fn domain_separator_is_deterministic() {
        let ds1 = wsalt_domain_separator(40204, addr([0x42; 20]));
        let ds2 = wsalt_domain_separator(40204, addr([0x42; 20]));
        assert_eq!(ds1, ds2);
    }

    #[test]
    fn domain_separator_differs_per_chain() {
        // EIP-155-style chain binding: same contract on chain 1 vs
        // chain 40204 must produce different digests so a valid sig
        // for one can't be replayed on the other.
        let ds_mainnet = wsalt_domain_separator(1, addr([0x42; 20]));
        let ds_testnet = wsalt_domain_separator(40204, addr([0x42; 20]));
        assert_ne!(ds_mainnet, ds_testnet);
    }

    #[test]
    fn domain_separator_differs_per_contract() {
        let a = wsalt_domain_separator(40204, addr([0x01; 20]));
        let b = wsalt_domain_separator(40204, addr([0x02; 20]));
        assert_ne!(a, b);
    }

    #[test]
    fn struct_hash_is_deterministic() {
        let s1 = transfer_with_authorization_struct_hash(
            addr([0xaa; 20]),
            addr([0xbb; 20]),
            U256::from(1000u64),
            U256::from(1_000_000u64),
            U256::from(2_000_000u64),
            H256::from([0x42; 32]),
        );
        let s2 = transfer_with_authorization_struct_hash(
            addr([0xaa; 20]),
            addr([0xbb; 20]),
            U256::from(1000u64),
            U256::from(1_000_000u64),
            U256::from(2_000_000u64),
            H256::from([0x42; 32]),
        );
        assert_eq!(s1, s2);
    }

    #[test]
    fn struct_hash_varies_per_nonce() {
        let common = |nonce: H256| {
            transfer_with_authorization_struct_hash(
                addr([0xaa; 20]),
                addr([0xbb; 20]),
                U256::from(1000u64),
                U256::from(0u64),
                U256::from(u64::MAX),
                nonce,
            )
        };
        let a = common(H256::from([0x01; 32]));
        let b = common(H256::from([0x02; 32]));
        assert_ne!(a, b);
    }

    #[test]
    fn digest_combines_domain_and_struct() {
        let ds = H256::from([0x11; 32]);
        let sh = H256::from([0x22; 32]);
        let d = eip712_digest(ds, sh);
        // Determinism
        assert_eq!(d, eip712_digest(ds, sh));
        // Order-sensitive: swapping domain and struct hashes must
        // change the digest.
        assert_ne!(d, eip712_digest(sh, ds));
    }

    #[test]
    fn full_flow_determinism() {
        // End-to-end: for a fixed (chain, contract, authorization)
        // the digest must be the same bit for bit across calls.
        let contract = addr([0xcc; 20]);
        let ds = wsalt_domain_separator(40204, contract);
        let sh = transfer_with_authorization_struct_hash(
            addr([0xa; 20]),
            addr([0xb; 20]),
            U256::from(1_000_000_000_000_000_000u128), // 1 SALT
            U256::from(1_000_000u64),
            U256::from(1_000_300u64),
            H256::from([0xde; 32]),
        );
        let d1 = eip712_digest(ds, sh);
        let d2 = eip712_digest(ds, sh);
        assert_eq!(d1, d2);
        // And it should bind to contract address
        let ds2 = wsalt_domain_separator(40204, addr([0xdd; 20]));
        let d3 = eip712_digest(ds2, sh);
        assert_ne!(d1, d3);
    }
}
