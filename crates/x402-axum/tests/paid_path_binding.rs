//! Paid-path binding pins at the layer entry point.
//!
//! A challenge nonce is bound to the exact request (method, path + query,
//! body) that minted it, and a payment must authorize at least the quoted
//! price. Each test drives the real `X402Layer` through an axum router with
//! an in-process mock chain, and asserts on the HTTP status, on whether the
//! inner handler ran, and on whether a settlement transaction was submitted.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::{routing::post, Router};
use ethereum_types::{H160, H256, U256};
use http_body_util::BodyExt;
use tower::ServiceExt;

use x402_axum::{
    encode_payment_header, payment_settled_topic, ChainClient, FixedPricing, PaymentPayload,
    RawLog, TxReceipt, X402Error, X402Layer, X_PAYMENT_HEADER,
};

const PRICE_WEI: u128 = 1_000_000_000_000_000_000;

fn facilitator() -> H160 {
    H160::from([0xfa; 20])
}

fn treasury() -> H160 {
    H160::from([0x7e; 20])
}

fn payer() -> H160 {
    H160::from([0xb1; 20])
}

fn hex_addr(a: H160) -> String {
    format!("0x{}", hex::encode(a.as_bytes()))
}

/// Mock chain: the precompile "recovers" the payload's `from`, every
/// submitted settlement is counted, and the receipt carries a matching
/// `PaymentSettled` event.
struct MockChain {
    submitted: Arc<AtomicUsize>,
}

#[async_trait]
impl ChainClient for MockChain {
    async fn verify_offline(&self, input: &[u8]) -> Result<Option<H160>, X402Error> {
        Ok(Some(H160::from_slice(&input[32..52])))
    }

    async fn get_nonce(&self, _address: H160) -> Result<u64, X402Error> {
        Ok(0)
    }

    async fn send_raw_tx(&self, _raw: &[u8]) -> Result<H256, X402Error> {
        self.submitted.fetch_add(1, Ordering::SeqCst);
        Ok(H256::from([0xbe; 32]))
    }

    async fn wait_for_receipt(
        &self,
        _tx_hash: H256,
        _timeout: Duration,
    ) -> Result<TxReceipt, X402Error> {
        let mut from = [0u8; 32];
        from[12..].copy_from_slice(payer().as_bytes());
        let mut to = [0u8; 32];
        to[12..].copy_from_slice(treasury().as_bytes());
        let mut data = Vec::with_capacity(96);
        let mut word = [0u8; 32];
        U256::from(PRICE_WEI).to_big_endian(&mut word);
        data.extend_from_slice(&word);
        U256::zero().to_big_endian(&mut word);
        data.extend_from_slice(&word);
        data.extend_from_slice(&[0u8; 32]);
        Ok(TxReceipt {
            status: true,
            block_number: 1,
            logs: vec![RawLog {
                address: facilitator(),
                topics: vec![payment_settled_topic(), H256::from(from), H256::from(to)],
                data,
            }],
        })
    }
}

struct Harness {
    app: Router,
    submitted: Arc<AtomicUsize>,
    served: Arc<AtomicUsize>,
}

fn harness() -> Harness {
    let submitted = Arc::new(AtomicUsize::new(0));
    let served = Arc::new(AtomicUsize::new(0));
    let layer = X402Layer::builder()
        .chain_id(40204)
        .facilitator_address(&hex_addr(facilitator()))
        .wsalt_address(&hex_addr(H160::from([0x5a; 20])))
        .treasury(&hex_addr(treasury()))
        .rpc_url("http://unused-the-mock-is-injected")
        .pricing(FixedPricing::new(PRICE_WEI.to_string()))
        .operator_secret_hex("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
        .chain_client(MockChain {
            submitted: submitted.clone(),
        })
        .build()
        .expect("build layer");
    let served_in = served.clone();
    let app = Router::new()
        .route(
            "/infer",
            post(move |body: String| {
                let served = served_in.clone();
                async move {
                    served.fetch_add(1, Ordering::SeqCst);
                    format!("ok:{body}")
                }
            }),
        )
        .layer(layer);
    Harness {
        app,
        submitted,
        served,
    }
}

fn request(uri: &str, body: &str, payment: Option<&PaymentPayload>) -> Request<Body> {
    let mut b = Request::builder().method(Method::POST).uri(uri);
    if let Some(p) = payment {
        b = b.header(X_PAYMENT_HEADER, encode_payment_header(p));
    }
    b.body(Body::from(body.to_string())).expect("request")
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let res = app.clone().oneshot(req).await.expect("service");
    let status = res.status();
    let bytes = res.into_body().collect().await.expect("body").to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Unpaid request → 402; returns the challenge nonce the layer minted for it.
async fn challenge_for(app: &Router, uri: &str, body: &str) -> H256 {
    let (status, json) = send(app, request(uri, body, None)).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "unpaid request gets 402"
    );
    let hex_nonce = json["x402"]["nonce"].as_str().expect("challenge nonce");
    H256::from_slice(&hex::decode(hex_nonce.trim_start_matches("0x")).expect("nonce hex"))
}

fn payment(nonce: H256, value: u128) -> PaymentPayload {
    PaymentPayload {
        from: payer(),
        to: treasury(),
        value: U256::from(value),
        valid_after: U256::zero(),
        valid_before: U256::from(u64::MAX),
        nonce,
        v: 27,
        r: H256::from([0xab; 32]),
        s: H256::from([0xcd; 32]),
    }
}

#[tokio::test]
async fn bound_payment_for_the_same_request_is_served_and_settled() {
    let h = harness();
    let nonce = challenge_for(&h.app, "/infer?model=a", "prompt-1").await;
    let (status, _) = send(
        &h.app,
        request(
            "/infer?model=a",
            "prompt-1",
            Some(&payment(nonce, PRICE_WEI)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.served.load(Ordering::SeqCst), 1);
    assert_eq!(h.submitted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn challenge_cannot_pay_for_a_different_body() {
    let h = harness();
    let nonce = challenge_for(&h.app, "/infer", "short prompt").await;
    let pay = payment(nonce, PRICE_WEI);

    let (status, json) = send(&h.app, request("/infer", "a different prompt", Some(&pay))).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "body swap must be refused"
    );
    assert!(
        json["reason"].as_str().unwrap_or("").contains("challenge"),
        "refused at the challenge ledger, got {json}"
    );
    assert_eq!(
        h.served.load(Ordering::SeqCst),
        0,
        "inner handler must not run"
    );
    assert_eq!(h.submitted.load(Ordering::SeqCst), 0, "nothing settled");

    // The mismatch did not burn the nonce: the original request still pays.
    let (status, _) = send(&h.app, request("/infer", "short prompt", Some(&pay))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.served.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn challenge_cannot_pay_for_a_different_path_or_query() {
    let h = harness();
    let nonce = challenge_for(&h.app, "/infer?model=small", "p").await;
    let pay = payment(nonce, PRICE_WEI);

    let (status, _) = send(&h.app, request("/infer?model=large", "p", Some(&pay))).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "query swap must be refused"
    );
    assert_eq!(h.served.load(Ordering::SeqCst), 0);
    assert_eq!(h.submitted.load(Ordering::SeqCst), 0);

    let (status, _) = send(&h.app, request("/infer?model=small", "p", Some(&pay))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn payment_below_the_quoted_price_is_refused_before_serving() {
    let h = harness();
    let nonce = challenge_for(&h.app, "/infer", "p").await;
    let (status, json) = send(
        &h.app,
        request("/infer", "p", Some(&payment(nonce, PRICE_WEI - 1))),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "underpayment must be refused"
    );
    assert!(
        json["detail"]
            .as_str()
            .unwrap_or("")
            .contains("below price"),
        "refusal names the price check, got {json}"
    );
    assert_eq!(
        h.served.load(Ordering::SeqCst),
        0,
        "inner handler must not run"
    );
    assert_eq!(h.submitted.load(Ordering::SeqCst), 0, "nothing settled");
}

#[tokio::test]
async fn payment_of_exactly_the_price_is_accepted() {
    let h = harness();
    let nonce = challenge_for(&h.app, "/infer", "p").await;
    let (status, _) = send(
        &h.app,
        request("/infer", "p", Some(&payment(nonce, PRICE_WEI))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.submitted.load(Ordering::SeqCst), 1);
}
