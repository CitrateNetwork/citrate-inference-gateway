//! Tripwire for IGW-B-001 (settle-after-serve, no refund).
//!
//! History: the blind leg of the 2026-09-02 federation graded audit dropped a
//! PoC here (`poc_igw_b_001_settle_without_serve_no_refund`) that ASSERTED the
//! buggy behavior — the layer settled the on-chain `settlePayment` tx BEFORE
//! invoking the inner handler, so a 503 (NoProviders / PoolDispatchUnimplemented),
//! 400 (UnknownModel), 402 (Underfunded), or a panic charged the payer for
//! nothing. After the fix (`layer.rs`: split validate/settle, settle only on a
//! 2xx inner response) that assertion is false.
//!
//! This file replaces the PoC with the TRIPWIRE it asks for: table-driven over
//! inner terminal statuses {2xx, 4xx, 5xx, panic}, asserting the class
//! invariant `settle ⟹ serve`:
//!
//!     on-chain-tx-count == (response.is_success() ? 1 : 0)
//!
//! so any future handler failure mode is covered, not just 503.
//!
//! RED→GREEN evidence: on the pre-fix layer (settle-before-serve) every row
//! except the 2xx one FAILS (tx count is 1 for 4xx/5xx/panic). On the fixed
//! layer every row passes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::{routing::get, Extension, Router};
use ethereum_types::{H160, H256, U256};
use http_body_util::BodyExt;
use tower::ServiceExt;

use x402_axum::{
    encode_payment_header, payment_settled_topic, ChainClient, FixedPricing, PaymentPayload,
    RawLog, TxReceipt, X402Error, X402Layer, X402Paid, X_PAYMENT_HEADER,
};

// ── Counting chain client ────────────────────────────────────────
//
// Verifies OK, settles OK — the ONLY thing it records is how many
// `send_raw_tx` calls (on-chain settlement submissions) happened. The
// invariant under test is precisely: how many times did money move?

struct CountingChain {
    facilitator: H160,
    /// Every `send_raw_tx` (settlement submission) bumps this. It is the
    /// on-chain-tx-count the tripwire asserts against.
    tx_count: Arc<AtomicUsize>,
}

impl CountingChain {
    fn new(facilitator: H160, tx_count: Arc<AtomicUsize>) -> Self {
        Self {
            facilitator,
            tx_count,
        }
    }

    fn settled_receipt(&self) -> TxReceipt {
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
        data.extend_from_slice(H256::from([0xde; 32]).as_bytes());

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
impl ChainClient for CountingChain {
    async fn verify_offline(&self, precompile_input: &[u8]) -> Result<Option<H160>, X402Error> {
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
        Ok(0)
    }

    async fn send_raw_tx(&self, _raw_tx: &[u8]) -> Result<H256, X402Error> {
        // THE money move. Count it.
        self.tx_count.fetch_add(1, Ordering::SeqCst);
        Ok(H256::from([0xbe; 32]))
    }

    async fn wait_for_receipt(
        &self,
        _tx_hash: H256,
        _timeout: Duration,
    ) -> Result<TxReceipt, X402Error> {
        Ok(self.settled_receipt())
    }
}

// ── Helpers ──────────────────────────────────────────────────────

fn facilitator() -> H160 {
    H160::from([0xfa; 20])
}

fn any_addr() -> &'static str {
    "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b"
}

fn treasury_h160() -> H160 {
    let mut bytes = [0u8; 20];
    hex::decode_to_slice(any_addr().trim_start_matches("0x"), &mut bytes).expect("hex");
    H160::from(bytes)
}

fn test_secret_hex() -> &'static str {
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
}

fn sample_payload() -> PaymentPayload {
    PaymentPayload {
        from: H160::from([0xb1; 20]),
        to: treasury_h160(),
        value: U256::from(1_000_000_000_000_000_000u128),
        valid_after: U256::from(0u64),
        valid_before: U256::from(u64::MAX),
        nonce: H256::from([0xde; 32]),
        v: 27,
        r: H256::from([0xab; 32]),
        s: H256::from([0xcd; 32]),
    }
}

/// The terminal status the inner handler produces, per table row.
#[derive(Clone, Copy, Debug)]
enum InnerTerminal {
    /// 2xx — service delivered. Settlement MUST happen (1 tx).
    Success,
    /// 4xx — e.g. UnknownModel / Underfunded. NO settlement (0 tx).
    ClientError,
    /// 5xx — e.g. NoProviders / PoolDispatchUnimplemented. NO settlement.
    ServerError,
    /// panic — inner handler blows up. NO settlement.
    Panic,
}

impl InnerTerminal {
    fn is_success(self) -> bool {
        matches!(self, InnerTerminal::Success)
    }
}

fn build_app(terminal: InnerTerminal, tx_count: Arc<AtomicUsize>) -> Router {
    let layer = X402Layer::builder()
        .chain_id(40204)
        .facilitator_address(&format!("0x{}", hex::encode(facilitator().as_bytes())))
        .wsalt_address(any_addr())
        .treasury(any_addr())
        .rpc_url("http://unused-the-mock-is-injected")
        .pricing(FixedPricing::new("1000000000000000000"))
        .operator_secret_hex(test_secret_hex())
        .chain_client(CountingChain::new(facilitator(), tx_count))
        .build()
        .expect("build layer");

    let handler = move |_paid: Extension<X402Paid>| async move {
        match terminal {
            InnerTerminal::Success => (StatusCode::OK, "served").into_response(),
            InnerTerminal::ClientError => {
                (StatusCode::BAD_REQUEST, "unknown model").into_response()
            }
            InnerTerminal::ServerError => {
                (StatusCode::SERVICE_UNAVAILABLE, "no providers").into_response()
            }
            InnerTerminal::Panic => panic!("inner handler exploded (simulated NoProviders panic)"),
        }
    };

    Router::new().route("/gated", get(handler)).layer(layer)
}

async fn issue_nonce(app: &Router) -> H256 {
    let req = Request::builder()
        .uri("/gated")
        .body(Body::empty())
        .expect("req");
    let res = app.clone().oneshot(req).await.expect("service");
    assert_eq!(res.status(), StatusCode::PAYMENT_REQUIRED, "handshake 402");
    let body = res.into_body().collect().await.expect("body").to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).expect("challenge json");
    let nonce_hex = v["x402"]["nonce"].as_str().expect("challenge nonce");
    let bytes = hex::decode(nonce_hex.trim_start_matches("0x")).expect("nonce hex");
    H256::from_slice(&bytes)
}

fn paid_request(payload: &PaymentPayload) -> Request<Body> {
    Request::builder()
        .uri("/gated")
        .header(X_PAYMENT_HEADER, encode_payment_header(payload))
        .body(Body::empty())
        .expect("req")
}

/// Drive one paid request to terminal and return `(inner_is_success,
/// on_chain_tx_count)`. A panicking inner handler is caught (via
/// `tokio::spawn`'s `JoinError`) and reported as not-success, exactly like a
/// 5xx from the client's perspective.
async fn run_row(terminal: InnerTerminal) -> (bool, usize) {
    let tx_count = Arc::new(AtomicUsize::new(0));
    let app = build_app(terminal, tx_count.clone());
    let mut payload = sample_payload();
    payload.nonce = issue_nonce(&app).await;
    let req = paid_request(&payload);

    // Spawn so a panicking inner handler surfaces as a JoinError instead of
    // unwinding the test thread.
    let join = tokio::spawn(async move { app.oneshot(req).await });
    let served_ok = match join.await {
        Ok(Ok(resp)) => resp.status().is_success(),
        Ok(Err(_svc_err)) => false,
        Err(_join_panic) => false,
    };
    (served_ok, tx_count.load(Ordering::SeqCst))
}

// ── Tripwire ─────────────────────────────────────────────────────

/// The class invariant: `settle ⟹ serve`. For every terminal inner status,
/// the on-chain settlement tx count equals 1 iff the response is a success,
/// and 0 otherwise. RED on the pre-fix (settle-before-serve) layer for every
/// non-2xx row; GREEN after the fix.
#[tokio::test]
async fn tripwire_igw_b_001_settle_iff_serve() {
    let rows = [
        InnerTerminal::Success,
        InnerTerminal::ClientError,
        InnerTerminal::ServerError,
        InnerTerminal::Panic,
    ];

    for row in rows {
        let (served_ok, tx_count) = run_row(row).await;
        let expected = if row.is_success() { 1 } else { 0 };
        assert_eq!(
            served_ok,
            row.is_success(),
            "{row:?}: served_ok must match the terminal class"
        );
        assert_eq!(
            tx_count,
            expected,
            "{row:?}: settle⟹serve violated — expected {expected} on-chain settle tx(s) \
             for a {} response, saw {tx_count} (the payer was charged for a non-2xx)",
            if row.is_success() { "2xx" } else { "non-2xx" }
        );
    }
}

/// Focused restatement of the original PoC scenario: a 503 (the state of the
/// chain whenever no provider is registered) must NOT charge the payer. This
/// is the exact case `poc_igw_b_001_settle_without_serve_no_refund` proved was
/// broken; here it must hold.
#[tokio::test]
async fn tripwire_igw_b_001_503_does_not_charge() {
    let (served_ok, tx_count) = run_row(InnerTerminal::ServerError).await;
    assert!(!served_ok, "503 is not a success");
    assert_eq!(
        tx_count, 0,
        "a 503 NoProviders must not settle any on-chain payment"
    );
}
