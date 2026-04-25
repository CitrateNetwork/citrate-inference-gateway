//! `X-PAYMENT` HTTP header codec.
//!
//! Wire format: base64-encoded [`PaymentPayload`] bytes (URL-safe
//! base64 without padding, since headers must avoid `=` for some
//! middleware that mishandles it).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::error::X402Error;
use crate::types::{PaymentPayload, PAYLOAD_BYTES};

/// Header name we read on the request side.
pub const X_PAYMENT_HEADER: &str = "x-payment";

/// Encode a [`PaymentPayload`] for transport in the `X-PAYMENT`
/// header. Output is URL-safe base64 of the 233-byte payload.
pub fn encode(payload: &PaymentPayload) -> String {
    URL_SAFE_NO_PAD.encode(payload.to_bytes())
}

/// Decode an `X-PAYMENT` header value back into a [`PaymentPayload`].
///
/// Returns [`X402Error::MalformedPaymentHeader`] on:
/// - non-base64 input
/// - decoded length not equal to [`PAYLOAD_BYTES`]
pub fn decode(value: &str) -> Result<PaymentPayload, X402Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|e| X402Error::MalformedPaymentHeader(format!("base64: {}", e)))?;
    if bytes.len() != PAYLOAD_BYTES {
        return Err(X402Error::MalformedPaymentHeader(format!(
            "expected {} bytes after base64 decode, got {}",
            PAYLOAD_BYTES,
            bytes.len()
        )));
    }
    PaymentPayload::parse(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H160, H256, U256};

    fn sample() -> PaymentPayload {
        PaymentPayload {
            from: H160::from([0xa1; 20]),
            to: H160::from([0xa2; 20]),
            value: U256::from(1_000_000_000_000_000_000u128),
            valid_after: U256::from(1_714_000_000u64),
            valid_before: U256::from(1_714_000_300u64),
            nonce: H256::from([0xde; 32]),
            v: 27,
            r: H256::from([0xab; 32]),
            s: H256::from([0xcd; 32]),
        }
    }

    #[test]
    fn header_round_trip() {
        let p = sample();
        let encoded = encode(&p);
        // No padding (we use URL_SAFE_NO_PAD).
        assert!(!encoded.contains('='));
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(decoded.from, p.from);
        assert_eq!(decoded.value, p.value);
        assert_eq!(decoded.nonce, p.nonce);
        assert_eq!(decoded.v, p.v);
    }

    #[test]
    fn decode_rejects_garbage() {
        let err = decode("not-valid-base64!@#").expect_err("should fail");
        assert!(matches!(err, X402Error::MalformedPaymentHeader(_)));
    }

    #[test]
    fn decode_rejects_short_payload() {
        // Valid base64 of 100 bytes — not 233, so structurally wrong.
        let s = URL_SAFE_NO_PAD.encode([0u8; 100]);
        let err = decode(&s).expect_err("should fail");
        assert!(matches!(err, X402Error::MalformedPaymentHeader(m) if m.contains("233")));
    }

    #[test]
    fn decode_tolerates_surrounding_whitespace() {
        let p = sample();
        let encoded = format!("  {}\n", encode(&p));
        decode(&encoded).expect("trim works");
    }

    #[test]
    fn header_name_is_lowercase() {
        // axum's HeaderMap is case-insensitive on lookup but
        // canonicalizes to lowercase. We pin the casing so the
        // grep target is stable.
        assert_eq!(X_PAYMENT_HEADER, "x-payment");
    }
}
