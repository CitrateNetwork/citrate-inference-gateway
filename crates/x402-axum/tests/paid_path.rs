//! End-to-end tests of the paid path with a MOCK chain client.
//!
//! No live network needed. Exercises the full flow:
//!   parse X-PAYMENT → precompile verify (mocked) → build calldata →
//!   sign tx → submit → wait receipt → extract PaymentSettled →
//!   attach X402Paid → forward to inner.
//!
//! The real [`HttpChainClient`] is integration-tested separately
//! against a devnet (gated by env var) in `tests/paid_path_live.rs`.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{routing::get, Extension, Router};
use ethereum_types::{H160, H256, U256};
use http_body_util::BodyExt;
use tower::ServiceExt;

use x402_axum::{
    encode_payment_header, payment_settled_topic, ChainClient, FixedPricing, PaymentPayload,
    RawLog, TxReceipt, X402Error, X402Layer, X402Paid, X_PAYMENT_HEADER,
};

// ── Mock chain client ────────────────────────────────────────────

struct MockChain {
    facilitator: H160,
    /// Verify returns Some(recovered) on success. For the mock, we
    /// simply trust the `from` field in the payload unless the test
    /// injects `force_invalid_sig`.
    force_invalid_sig: bool,
    /// Nonces already settled. Re-submission hits `nonce_replayed`
    /// by returning a receipt with status=false.
    settled: Mutex<HashSet<H256>>,
    /// If non-zero, wait_for_receipt sleeps this long before returning
    /// (to let tests verify timeout behaviour).
    artificial_latency_ms: u64,
    /// Fixed operator nonce returned by get_nonce.
    operator_nonce: u64,
}

impl MockChain {
    fn new(facilitator: H160) -> Self {
        Self {
            facilitator,
            force_invalid_sig: false,
            settled: Mutex::new(HashSet::new()),
            artificial_latency_ms: 0,
            operator_nonce: 0,
        }
    }

    fn build_settled_receipt(&self, payload_nonce: H256) -> TxReceipt {
        // Build a PaymentSettled log matching our mock. from / to
        // don't need to round-trip from the actual payload for this
        // mock — the layer only uses the event to populate X402Paid,
        // and the tests then assert what it populated.
        let from = H160::from([0xa1; 20]);
        let to = H160::from([0xa2; 20]);
        let value = U256::from(995_000_000_000_000_000u128);
        let fee = U256::from(5_000_000_000_000_000u128);

        let mut topics = Vec::with_capacity(3);
        topics.push(payment_settled_topic());
        let mut padded_from = [0u8; 32];
        padded_from[12..32].copy_from_slice(from.as_bytes());
        topics.push(H256::from(padded_from));
        let mut padded_to = [0u8; 32];
        padded_to[12..32].copy_from_slice(to.as_bytes());
        topics.push(H256::from(padded_to));

        let mut data = Vec::with_capacity(96);
        let mut buf = [0u8; 32];
        value.to_big_endian(&mut buf);
        data.extend_from_slice(&buf);
        fee.to_big_endian(&mut buf);
        data.extend_from_slice(&buf);
        data.extend_from_slice(payload_nonce.as_bytes());

        TxReceipt {
            status: true,
            block_number: 100,
            logs: vec![RawLog {
                address: self.facilitator,
                topics,
                data,
            }],
        }
    }
}

#[async_trait]
impl ChainClient for MockChain {
    async fn verify_offline(&self, precompile_input: &[u8]) -> Result<Option<H160>, X402Error> {
        if self.force_invalid_sig {
            return Ok(None);
        }
        // Input layout: domain(32) + from(20) + ... → return `from`.
        if precompile_input.len() != 265 {
            return Err(X402Error::RpcError(format!(
                "bad precompile input len {}",
                precompile_input.len()
            )));
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&precompile_input[32..52]);
        Ok(Some(H160::from(addr)))
    }

    async fn get_nonce(&self, _address: H160) -> Result<u64, X402Error> {
        Ok(self.operator_nonce)
    }

    async fn send_raw_tx(&self, _raw_tx: &[u8]) -> Result<H256, X402Error> {
        // Return a deterministic tx hash.
        Ok(H256::from([0xbe; 32]))
    }

    async fn wait_for_receipt(
        &self,
        _tx_hash: H256,
        timeout: Duration,
    ) -> Result<TxReceipt, X402Error> {
        if self.artificial_latency_ms > 0 {
            let delay = Duration::from_millis(self.artificial_latency_ms);
            if delay > timeout {
                return Err(X402Error::SettlePendingTimeout);
            }
            tokio::time::sleep(delay).await;
        }
        // If the current call's payload nonce is already in `settled`,
        // return status=false (replay). We don't know the payload
        // nonce from here, so we instead rely on the order-of-ops:
        // the test seeds `settled` beforehand and uses a nonce that
        // matches. For the happy path, nothing is seeded.
        let settled = self.settled.lock().expect("settled mutex");
        // If exactly ONE nonce is in settled, assume the caller
        // intends replay and fail.
        if let Some(&n) = settled.iter().next() {
            if settled.len() == 1 {
                // Return a revert receipt — layer maps to NonceReplayed.
                return Ok(TxReceipt {
                    status: false,
                    block_number: 101,
                    logs: vec![],
                });
            }
            // Fallback: return a synthesized successful receipt.
            drop(settled);
            return Ok(self.build_settled_receipt(n));
        }
        drop(settled);
        // Happy path: produce a receipt whose event uses nonce 0xde*32
        // — matching the sample payload the tests construct.
        Ok(self.build_settled_receipt(H256::from([0xde; 32])))
    }
}

// ── Test helpers ─────────────────────────────────────────────────

fn facilitator() -> H160 {
    H160::from([0xfa; 20])
}

fn any_addr() -> &'static str {
    "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b"
}

/// The H160 form of `any_addr()` — the configured gateway treasury.
/// RM-B1 / WP-D2.3 (audit F-1): payloads must address the same
/// treasury the gateway is bound to, otherwise the bind check
/// rejects the payment.
fn treasury_h160() -> H160 {
    let mut bytes = [0u8; 20];
    let hex_str = any_addr().trim_start_matches("0x");
    hex::decode_to_slice(hex_str, &mut bytes).expect("valid treasury hex");
    H160::from(bytes)
}

fn test_secret_hex() -> &'static str {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
}

fn sample_payload() -> PaymentPayload {
    PaymentPayload {
        from: H160::from([0xb1; 20]),
        to: treasury_h160(),
        value: U256::from(1_000_000_000_000_000_000u128), // 1 SALT
        // Pick a valid-now window. now - 100 to now + 100_000.
        valid_after: U256::from(0u64),
        valid_before: U256::from(u64::MAX),
        nonce: H256::from([0xde; 32]),
        v: 27,
        r: H256::from([0xab; 32]),
        s: H256::from([0xcd; 32]),
    }
}

fn build_app_with_mock(mock: MockChain) -> Router {
    let layer = X402Layer::builder()
        .chain_id(40204)
        .facilitator_address(&format!("0x{}", hex::encode(facilitator().as_bytes())))
        .wsalt_address(any_addr())
        .treasury(any_addr())
        .rpc_url("http://unused-the-mock-is-injected")
        .pricing(FixedPricing::new("1000000000000000000"))
        .operator_secret_hex(test_secret_hex())
        .chain_client(mock)
        .build()
        .expect("build layer");

    Router::new()
        .route(
            "/gated",
            get(|Extension(paid): Extension<X402Paid>| async move {
                // Inner handler returns JSON echoing the X402Paid info
                // so tests can assert forwarding worked.
                format!(
                    "{{\"payer\":\"0x{}\",\"amount_wei\":\"{}\"}}",
                    hex::encode(paid.payer.as_bytes()),
                    paid.amount_wei
                )
            }),
        )
        .layer(layer)
}

async fn call(app: Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let res = app.oneshot(req).await.expect("service");
    (
        res.status(),
        res.into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec(),
    )
}

fn paid_request(payload: &PaymentPayload) -> Request<Body> {
    Request::builder()
        .uri("/gated")
        .header(X_PAYMENT_HEADER, encode_payment_header(payload))
        .body(Body::empty())
        .expect("build request")
}

/// Perform the unpaid handshake: hit the gated route with no
/// X-PAYMENT header, parse the 402 challenge, and return the
/// server-issued nonce. Since the challenge-nonce ledger landed
/// (2026-05-31 audit 001), the paid path only accepts nonces minted
/// this way — payloads with self-minted nonces are rejected.
async fn issue_nonce(app: &Router) -> H256 {
    let req = Request::builder()
        .uri("/gated")
        .body(Body::empty())
        .expect("build request");
    let res = app.clone().oneshot(req).await.expect("service");
    assert_eq!(res.status(), StatusCode::PAYMENT_REQUIRED, "handshake 402");
    let body = res.into_body().collect().await.expect("body").to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).expect("challenge json");
    let nonce_hex = v["x402"]["nonce"].as_str().expect("challenge nonce");
    let bytes = hex::decode(nonce_hex.trim_start_matches("0x")).expect("nonce hex");
    H256::from_slice(&bytes)
}

// ── Tests ────────────────────────────────────────────────────────

/// 2026-05-31 audit 001 (challenge-nonce ledger): a payment whose
/// nonce was never issued by this gateway must be rejected before
/// any chain work — self-minted nonces no longer reach settlement.
#[tokio::test]
async fn unissued_nonce_rejected_402() {
    let mock = MockChain::new(facilitator());
    let app = build_app_with_mock(mock);
    // sample_payload() carries a self-minted nonce (0xde…) the server
    // never issued.
    let (status, body) = call(app, paid_request(&sample_payload())).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let reason = body["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("challenge"),
        "reason should mention the challenge ledger, got: {}",
        reason
    );
}

/// 2026-05-31 audit 001: an issued nonce is single-use — the second
/// payment with the same nonce is rejected at the ledger, before the
/// on-chain `_authorizationStates` backstop is even consulted.
#[tokio::test]
async fn issued_nonce_is_single_use() {
    let mock = MockChain::new(facilitator());
    let app = build_app_with_mock(mock);
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    let (status, _) = call(app.clone(), paid_request(&payload)).await;
    assert_eq!(status, StatusCode::OK, "first use settles");
    let (status, body) = call(app, paid_request(&payload)).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "second use refused");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert!(body["reason"].as_str().unwrap_or("").contains("challenge"));
}

#[tokio::test]
async fn happy_path_forwards_to_inner_with_x402paid() {
    let mock = MockChain::new(facilitator());
    let app = build_app_with_mock(mock);
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    let (status, body) = call(app, paid_request(&payload)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "body = {:?}",
        String::from_utf8_lossy(&body)
    );
    let text = String::from_utf8(body).expect("utf-8");
    assert!(text.contains("payer"));
    // IGW-B-001 (settle-after-serve): X402Paid is now attached from the
    // VALIDATED payload BEFORE the inner service runs, so `payer` is the
    // payload signer (`sample_payload().from` = 0xb1*20), not the mock's
    // synthetic post-settle event `from` (0xa1*20). The payload signer is
    // the correct payer identity.
    assert!(text.contains("b1b1b1b1"));
}

#[tokio::test]
async fn invalid_signature_returns_402() {
    let mut mock = MockChain::new(facilitator());
    mock.force_invalid_sig = true;
    let app = build_app_with_mock(mock);
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    let (status, body) = call(app, paid_request(&payload)).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let reason = body["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("signature"),
        "reason should mention signature, got: {}",
        reason
    );
}

#[tokio::test]
async fn recovered_signer_must_match_from_field() {
    // Even if precompile returns Some(addr), if addr != payload.from
    // the layer rejects.
    struct MismatchMock(MockChain);
    #[async_trait::async_trait]
    impl ChainClient for MismatchMock {
        async fn verify_offline(
            &self,
            _precompile_input: &[u8],
        ) -> Result<Option<H160>, X402Error> {
            // Return a deliberately different address than the
            // payload's `from`.
            Ok(Some(H160::from([0x99; 20])))
        }
        async fn get_nonce(&self, a: H160) -> Result<u64, X402Error> {
            self.0.get_nonce(a).await
        }
        async fn send_raw_tx(&self, b: &[u8]) -> Result<H256, X402Error> {
            self.0.send_raw_tx(b).await
        }
        async fn wait_for_receipt(&self, h: H256, t: Duration) -> Result<TxReceipt, X402Error> {
            self.0.wait_for_receipt(h, t).await
        }
    }
    let mock = MismatchMock(MockChain::new(facilitator()));
    let app = build_app_with_mock_impl(Box::new(mock));
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    let (status, body) = call(app, paid_request(&payload)).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert!(body["reason"].as_str().unwrap_or("").contains("signature"));
}

/// IGW-B-001 (settle-after-serve): under the fixed ordering, settlement runs
/// only AFTER the inner service returns 2xx. So a settle revert now happens
/// POST-serve — the client has already received its 200 and keeps it; the
/// OPERATOR bears the failed-settle loss (surfaced via `tracing::error` +
/// the observability `on_rejected("settle reverted")` hook, covered in
/// `observability.rs::settle_revert_fires_on_rejected_with_neutral_reason`).
/// This is the accepted trade-off: the invariant is that a NON-2xx never
/// charges the payer; a post-2xx settle miss is operator loss, not a client
/// rejection. Pre-fix (settle-before-serve) this returned a client-facing
/// 402 with the neutral reason; that path no longer exists.
#[tokio::test]
async fn settle_revert_post_serve_keeps_200_operator_bears_loss() {
    let mock = MockChain::new(facilitator());
    // Seeding `settled` makes wait_for_receipt return status=false —
    // an opaque revert receipt when the (post-serve) settle runs.
    mock.settled
        .lock()
        .expect("settled mutex")
        .insert(H256::from([0xde; 32]));

    let app = build_app_with_mock(mock);
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    let (status, _body) = call(app, paid_request(&payload)).await;
    // The inner /gated handler already returned 200 before settlement was
    // attempted; the post-serve settle revert does NOT downgrade it.
    assert_eq!(
        status,
        StatusCode::OK,
        "a settle revert AFTER a 2xx serve must not turn the served 200 into a 402"
    );
}

/// RM-B1 / WP-D2.3 (audit F-1): payment recipient must match the
/// gateway's configured treasury. A payload signed for a DIFFERENT
/// gateway's treasury must be rejected — without this check, an
/// attacker who captures a valid x402 header can replay it across
/// gateways for free service.
#[tokio::test]
async fn test_f1_cross_gateway_replay_rejected() {
    let mock = MockChain::new(facilitator());
    let app = build_app_with_mock(mock);

    // Payload addressed to a recipient that is NOT this gateway's
    // configured treasury.
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    payload.to = H160::from([0xbe; 20]); // attacker / other-gateway treasury

    let (status, body) = call(app, paid_request(&payload)).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "F-1: cross-gateway payload must be rejected"
    );
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let reason = body["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("treasury") || reason.contains("recipient"),
        "F-1 reason should mention treasury/recipient, got: {}",
        reason
    );
}

/// Companion: a payload with the correct treasury still works.
#[tokio::test]
async fn test_f1_correct_treasury_accepted() {
    let mock = MockChain::new(facilitator());
    let app = build_app_with_mock(mock);
    // sample_payload()`to` is now bound to treasury_h160() by default.
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    let (status, _) = call(app, paid_request(&payload)).await;
    assert_eq!(status, StatusCode::OK, "matched-treasury must be accepted");
}

#[tokio::test]
async fn expired_window_returns_402_expired() {
    let mut payload = sample_payload();
    // valid_before already in the past.
    payload.valid_before = U256::from(1u64);
    payload.valid_after = U256::from(0u64);
    let app = build_app_with_mock(MockChain::new(facilitator()));
    let (status, body) = call(app, paid_request(&payload)).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(body["reason"].as_str(), Some("expired"));
}

// ── Helper for the mismatch test (bypasses build_app_with_mock
// which requires MockChain concrete type) ──────────────────────

fn build_app_with_mock_impl(mock: Box<dyn ChainClient>) -> Router {
    struct Wrap(Box<dyn ChainClient>);
    #[async_trait::async_trait]
    impl ChainClient for Wrap {
        async fn verify_offline(&self, precompile_input: &[u8]) -> Result<Option<H160>, X402Error> {
            self.0.verify_offline(precompile_input).await
        }
        async fn get_nonce(&self, a: H160) -> Result<u64, X402Error> {
            self.0.get_nonce(a).await
        }
        async fn send_raw_tx(&self, b: &[u8]) -> Result<H256, X402Error> {
            self.0.send_raw_tx(b).await
        }
        async fn wait_for_receipt(&self, h: H256, t: Duration) -> Result<TxReceipt, X402Error> {
            self.0.wait_for_receipt(h, t).await
        }
    }
    let wrapped = Wrap(mock);
    let layer = X402Layer::builder()
        .chain_id(40204)
        .facilitator_address(&format!("0x{}", hex::encode(facilitator().as_bytes())))
        .wsalt_address(any_addr())
        .treasury(any_addr())
        .rpc_url("http://unused")
        .pricing(FixedPricing::new("1000000000000000000"))
        .operator_secret_hex(test_secret_hex())
        .chain_client(wrapped)
        .build()
        .expect("build layer");

    Router::new()
        .route(
            "/gated",
            get(|Extension(paid): Extension<X402Paid>| async move {
                format!("{{\"nonce\":\"0x{}\"}}", hex::encode(paid.nonce.as_bytes()))
            }),
        )
        .layer(layer)
}
