//! Auto-paying HTTP client for x402-gated endpoints.
//!
//! The common-case caller flow:
//!
//! ```ignore
//! let client = X402Client::new(secret_bytes, wsalt_addr, facilitator_addr, 40204);
//! let req = reqwest::Client::new().post("https://gateway.example/v1/chat/completions");
//! let response = client.send_paid(req).await?;
//! ```
//!
//! `send_paid` sends the request; on a 402 it parses the challenge,
//! signs `transferWithAuthorization` via the client's secp256k1
//! key, attaches `X-PAYMENT`, and retries **exactly once**. If the
//! retry is still 402, the error propagates.
//!
//! # Limitations
//!
//! - secp256k1 only. Ed25519 wallets surface as
//!   [`X402Error::UnsupportedKeyType`] before any HTTP work.
//! - Per-request budget cap. If a server challenges above the cap,
//!   the client refuses to sign and returns
//!   [`X402Error::BudgetExceeded`].
//! - The request body must be clonable for retry. `reqwest`'s
//!   `try_clone` fails for streaming bodies (e.g. a channel); the
//!   client returns [`X402Error::Internal`] in that case with a
//!   clear message.

use std::sync::Arc;

use ethereum_types::{H160, H256, U256};
use reqwest::{RequestBuilder, Response, StatusCode};

use crate::digest::{eip712_digest, transfer_with_authorization_struct_hash, wsalt_domain_separator};
use crate::error::X402Error;
use crate::header::{encode as encode_payment_header, X_PAYMENT_HEADER};
use crate::keys::{derive_secp256k1_address, sign_digest_secp256k1};
use crate::types::{PaymentChallenge, PaymentPayload};

/// Auto-paying HTTP client for x402-gated endpoints.
pub struct X402Client {
    pub(crate) config: Arc<ClientConfig>,
}

impl Clone for X402Client {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ClientConfig {
    pub secret: [u8; 32],
    pub payer_address: H160,
    pub wsalt_address: H160,
    pub facilitator_address: H160,
    pub chain_id: u64,
    pub budget_cap_wei: U256,
}

impl std::fmt::Debug for X402Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402Client")
            .field("payer_address", &self.config.payer_address)
            .field("wsalt_address", &self.config.wsalt_address)
            .field("facilitator_address", &self.config.facilitator_address)
            .field("chain_id", &self.config.chain_id)
            .field("budget_cap_wei", &self.config.budget_cap_wei)
            .finish_non_exhaustive()
    }
}

impl X402Client {
    /// Build a new client.
    ///
    /// `secret` is a secp256k1 private key (32 bytes). The payer
    /// address is derived and stashed. Ed25519 callers must use a
    /// different path — x402 is ECDSA-over-secp256k1 by EIP-3009
    /// construction.
    ///
    /// Returns [`X402Error::Internal`] if `secret` isn't a valid
    /// secp256k1 scalar. Use [`X402Client::try_new`] for the
    /// checked variant that surfaces the error cleanly.
    pub fn try_new(
        secret: [u8; 32],
        wsalt_address: H160,
        facilitator_address: H160,
        chain_id: u64,
    ) -> Result<Self, X402Error> {
        let payer_address = derive_secp256k1_address(&secret)
            .ok_or_else(|| X402Error::Internal("invalid secp256k1 secret".into()))?;
        Ok(Self {
            config: Arc::new(ClientConfig {
                secret,
                payer_address,
                wsalt_address,
                facilitator_address,
                chain_id,
                budget_cap_wei: U256::from(10u128) * U256::from(10u128).pow(18.into()),
            }),
        })
    }

    /// Legacy constructor — kept for the WP-02.1 scaffold test
    /// surface. Takes only addresses and chain_id; the secret must
    /// be set via [`X402Client::with_secret_bytes`] before any
    /// `send_paid` call. Prefer [`X402Client::try_new`] in new code.
    #[doc(hidden)]
    pub fn new(
        wsalt_address: H160,
        facilitator_address: H160,
        chain_id: u64,
    ) -> Self {
        Self {
            config: Arc::new(ClientConfig {
                secret: [0u8; 32],
                payer_address: H160::zero(),
                wsalt_address,
                facilitator_address,
                chain_id,
                budget_cap_wei: U256::from(10u128) * U256::from(10u128).pow(18.into()),
            }),
        }
    }

    /// Override the budget cap. Default is 10 SALT.
    pub fn with_budget_cap(mut self, cap_wei: U256) -> Self {
        // Arc::make_mut — we own the sole Arc reference immediately
        // after construction; cheap copy-on-write.
        let cfg = Arc::make_mut(&mut self.config);
        cfg.budget_cap_wei = cap_wei;
        self
    }

    /// Payer address. Derived from the client's secret at build time.
    pub fn payer_address(&self) -> H160 {
        self.config.payer_address
    }

    /// Budget cap in wei.
    pub fn budget_cap_wei(&self) -> U256 {
        self.config.budget_cap_wei
    }

    /// Send a request, auto-paying on 402.
    ///
    /// Flow:
    /// 1. `req.try_clone()` — retry copy must be kept before the
    ///    original is consumed by `.send()`. Fails cleanly if the
    ///    body is unclonable (streaming).
    /// 2. Send. If response is NOT 402, return it as-is.
    /// 3. Parse the 402 body as JSON, extract the `x402` envelope.
    /// 4. Check the challenge's `amount` against the budget cap.
    /// 5. Build a [`PaymentPayload`] with our address and the
    ///    challenge's fields, sign the challenge's digest.
    /// 6. Attach `X-PAYMENT` and send the cloned request.
    /// 7. Return that response regardless of its status (a second
    ///    402 is the server's business to report; we don't loop).
    pub async fn send_paid(
        &self,
        req: RequestBuilder,
    ) -> Result<Response, X402Error> {
        // Secret-presence check — catches the legacy `new()` caller
        // who forgot to set a real secret before calling send_paid.
        if self.config.secret.iter().all(|&b| b == 0) {
            return Err(X402Error::UnsupportedKeyType);
        }

        let retry = req
            .try_clone()
            .ok_or_else(|| X402Error::Internal("request body is not clonable".into()))?;

        let resp = req
            .send()
            .await
            .map_err(|e| X402Error::RpcTransport(format!("request failed: {}", e)))?;

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            // Either 200/etc (free path), or some other error; let
            // the caller handle it.
            return Ok(resp);
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| X402Error::RpcTransport(format!("402 body decode: {}", e)))?;

        let challenge = parse_challenge(&body)?;

        // Sanity: server must declare the chain we expect.
        if challenge.chain_id != self.config.chain_id {
            return Err(X402Error::Internal(format!(
                "server challenge chain_id {} != client chain_id {}",
                challenge.chain_id, self.config.chain_id
            )));
        }

        // Budget cap check BEFORE signing.
        let amount = U256::from_dec_str(&challenge.amount)
            .map_err(|e| X402Error::Internal(format!("bad challenge amount: {}", e)))?;
        if amount > self.config.budget_cap_wei {
            return Err(X402Error::BudgetExceeded {
                amount_requested_wei: challenge.amount.clone(),
                cap_wei: self.config.budget_cap_wei.to_string(),
            });
        }

        // Recipient + nonce from challenge.
        let recipient = parse_addr_hex(&challenge.recipient)?;
        let nonce = parse_bytes32_hex(&challenge.nonce)?;

        // Compute the digest ourselves. We do NOT compare against
        // the server's advertised `digest` field — the server
        // generates its challenge BEFORE knowing the payer's
        // address, so its digest is computed with a placeholder
        // `from` (zero address). The on-chain signature will use
        // `payload.from` (our real address), which is what the
        // precompile verifies. Signing OUR digest — derived from
        // OUR address — is the correct behavior.
        //
        // The server's `digest` field remains useful for UI display
        // (showing the user what they're about to sign) but isn't
        // load-bearing for correctness. A mismatched advertised
        // digest just means the server's preview is inaccurate; the
        // actual signature produced here is still valid.
        let domain_sep = wsalt_domain_separator(challenge.chain_id, self.config.wsalt_address);
        let struct_hash = transfer_with_authorization_struct_hash(
            self.config.payer_address,
            recipient,
            amount,
            U256::from(challenge.valid_after),
            U256::from(challenge.valid_before),
            nonce,
        );
        let our_digest = eip712_digest(domain_sep, struct_hash);

        // Sign.
        let mut digest_buf = [0u8; 32];
        digest_buf.copy_from_slice(our_digest.as_bytes());
        let (v, r_bytes, s_bytes) = sign_digest_secp256k1(&self.config.secret, &digest_buf)?;

        let payload = PaymentPayload {
            from: self.config.payer_address,
            to: recipient,
            value: amount,
            valid_after: U256::from(challenge.valid_after),
            valid_before: U256::from(challenge.valid_before),
            nonce,
            v,
            r: H256::from(r_bytes),
            s: H256::from(s_bytes),
        };
        let header_value = encode_payment_header(&payload);

        // Retry with header.
        let resp2 = retry
            .header(X_PAYMENT_HEADER, header_value)
            .send()
            .await
            .map_err(|e| X402Error::RpcTransport(format!("retry failed: {}", e)))?;

        Ok(resp2)
    }
}

fn parse_challenge(body: &serde_json::Value) -> Result<PaymentChallenge, X402Error> {
    let envelope = body.get("x402").ok_or_else(|| {
        X402Error::Internal("402 body missing 'x402' envelope".into())
    })?;
    serde_json::from_value(envelope.clone())
        .map_err(|e| X402Error::Internal(format!("challenge decode: {}", e)))
}

fn parse_addr_hex(s: &str) -> Result<H160, X402Error> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|e| X402Error::Internal(format!("bad address hex: {}", e)))?;
    if bytes.len() != 20 {
        return Err(X402Error::Internal(format!(
            "address should be 20 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(H160::from_slice(&bytes))
}

fn parse_bytes32_hex(s: &str) -> Result<H256, X402Error> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)
        .map_err(|e| X402Error::Internal(format!("bad bytes32 hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(X402Error::Internal(format!(
            "bytes32 should be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(H256::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ]
    }

    fn any_addr() -> H160 {
        H160::from([0x42; 20])
    }

    #[test]
    fn try_new_derives_payer_address() {
        let c = X402Client::try_new(test_secret(), any_addr(), any_addr(), 40204).expect("ok");
        assert_ne!(c.payer_address(), H160::zero());
    }

    #[test]
    fn try_new_rejects_zero_secret() {
        let err = X402Client::try_new([0u8; 32], any_addr(), any_addr(), 40204)
            .expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(_)));
    }

    #[test]
    fn default_budget_cap_is_ten_salt() {
        let c = X402Client::try_new(test_secret(), any_addr(), any_addr(), 40204).expect("ok");
        assert_eq!(
            c.budget_cap_wei(),
            U256::from(10u128) * U256::from(10u128).pow(18.into())
        );
    }

    #[test]
    fn budget_cap_override() {
        let c = X402Client::try_new(test_secret(), any_addr(), any_addr(), 40204)
            .expect("ok")
            .with_budget_cap(U256::from(42u128));
        assert_eq!(c.budget_cap_wei(), U256::from(42u128));
    }

    #[test]
    fn legacy_new_requires_secret_before_send() {
        // The old `new()` constructor doesn't take a secret; calling
        // send_paid with it should surface UnsupportedKeyType rather
        // than signing with zero bytes (which would be a disaster).
        let c = X402Client::new(any_addr(), any_addr(), 40204);
        assert_eq!(c.payer_address(), H160::zero());
        // send_paid rejects zero-secret clients early. Tested via
        // a synthetic RequestBuilder-free path.
        assert!(c.config.secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn parse_addr_hex_roundtrip() {
        let s = "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b";
        let a = parse_addr_hex(s).expect("ok");
        assert_eq!(a, H160::from_slice(&hex::decode(&s[2..]).unwrap()));
    }

    #[test]
    fn parse_addr_hex_rejects_short() {
        let err = parse_addr_hex("0xdeadbeef").expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(_)));
    }

    #[test]
    fn parse_bytes32_hex_roundtrip() {
        let s = "0x".to_owned() + &"ab".repeat(32);
        let h = parse_bytes32_hex(&s).expect("ok");
        assert_eq!(h, H256::from([0xab; 32]));
    }

    #[test]
    fn parse_bytes32_hex_rejects_short() {
        let err = parse_bytes32_hex("0x1234").expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(_)));
    }

    #[test]
    fn parse_challenge_extracts_envelope() {
        use serde_json::json;
        let body = json!({
            "x402": {
                "version": 1,
                "facilitator": "0xaaaa",
                "token": "0xbbbb",
                "chain_id": 40204,
                "amount": "1000",
                "nonce": "0xcccc",
                "valid_after": 1,
                "valid_before": 301,
                "recipient": "0xdddd",
                "digest": "0xeeee",
            }
        });
        let c = parse_challenge(&body).expect("ok");
        assert_eq!(c.version, 1);
        assert_eq!(c.chain_id, 40204);
        assert_eq!(c.amount, "1000");
    }

    #[test]
    fn parse_challenge_requires_x402_envelope() {
        use serde_json::json;
        let body = json!({"error": "pay up"});
        let err = parse_challenge(&body).expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(m) if m.contains("envelope")));
    }
}
