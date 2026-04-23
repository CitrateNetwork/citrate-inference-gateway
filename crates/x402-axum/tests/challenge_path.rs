//! End-to-end tests for the WP-02.2 unpaid-request path.
//!
//! Spin up an axum router protected by `X402Layer` + `FixedPricing`,
//! send a GET without an `X-PAYMENT` header, assert the 402 response
//! shape matches the Gherkin scenario #1 contract exactly.
//!
//! Driven via `tower::ServiceExt::oneshot` — no network, no external
//! test-server crate; the service is called directly. The paid path
//! is stubbed at 501 (WP-02.3 placeholder) and verified as such.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::{routing::get, Router};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use x402_axum::{FixedPricing, X402Layer};

fn any_addr() -> &'static str {
    "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b"
}

fn build_app() -> Router {
    let layer = X402Layer::builder()
        .chain_id(40204)
        .facilitator_address(any_addr())
        .wsalt_address(any_addr())
        .treasury(any_addr())
        .rpc_url("http://127.0.0.1:18545")
        .pricing(FixedPricing::new("1000000000000000000")) // 1 SALT
        .build()
        .expect("build layer");

    Router::new()
        .route("/gated", get(|| async { "secret payload" }))
        .layer(layer)
}

async fn call(app: Router, req: Request<Body>) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let res = app.oneshot(req).await.expect("service call");
    let status = res.status();
    let headers = res.headers().clone();
    let body = res
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, body, headers)
}

fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("parse body as json")
}

fn get_request(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("build request")
}

#[tokio::test]
async fn unpaid_request_gets_402_with_challenge_body() {
    let app = build_app();
    let (status, body, _) = call(app, get_request("/gated")).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);

    let body = json(&body);
    let x = body.get("x402").expect("x402 envelope");
    assert_eq!(x.get("version").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(x.get("chain_id").and_then(|v| v.as_u64()), Some(40204));
    assert_eq!(
        x.get("amount").and_then(|v| v.as_str()),
        Some("1000000000000000000")
    );
}

#[tokio::test]
async fn challenge_fields_have_correct_shapes() {
    let app = build_app();
    let (_, body, _) = call(app, get_request("/gated")).await;
    let body = json(&body);
    let x = &body["x402"];

    let facilitator = x["facilitator"].as_str().expect("facilitator");
    let token = x["token"].as_str().expect("token");
    let recipient = x["recipient"].as_str().expect("recipient");
    let nonce = x["nonce"].as_str().expect("nonce");
    let digest = x["digest"].as_str().expect("digest");

    assert_eq!(facilitator.len(), 42);
    assert_eq!(token.len(), 42);
    assert_eq!(recipient.len(), 42);
    assert_eq!(nonce.len(), 66);
    assert_eq!(digest.len(), 66);
    assert!(facilitator.starts_with("0x"));
    assert!(nonce.starts_with("0x"));
    assert!(digest.starts_with("0x"));
}

#[tokio::test]
async fn valid_before_is_300s_after_valid_after() {
    let app = build_app();
    let (_, body, _) = call(app, get_request("/gated")).await;
    let body = json(&body);
    let x = &body["x402"];
    let va = x["valid_after"].as_u64().expect("valid_after");
    let vb = x["valid_before"].as_u64().expect("valid_before");
    assert_eq!(vb - va, 300);
}

#[tokio::test]
async fn two_unpaid_requests_get_distinct_nonces() {
    // Replay-protection foundation: every challenge unique.
    // Locks in X402FacilitatorSettle.tla's NonceNeverReused
    // at the generation side.
    let app = build_app();
    let (_, a, _) = call(app.clone(), get_request("/gated")).await;
    let (_, b, _) = call(app, get_request("/gated")).await;
    let a = json(&a);
    let b = json(&b);

    assert_ne!(
        a["x402"]["nonce"].as_str().unwrap(),
        b["x402"]["nonce"].as_str().unwrap(),
    );
    assert_ne!(
        a["x402"]["digest"].as_str().unwrap(),
        b["x402"]["digest"].as_str().unwrap(),
    );
}

#[tokio::test]
async fn response_has_no_store_cache_header() {
    // 402 challenges are single-use; intermediaries must not cache.
    let app = build_app();
    let (_, _, headers) = call(app, get_request("/gated")).await;
    let cc = headers
        .get("cache-control")
        .expect("cache-control present")
        .to_str()
        .expect("utf-8");
    assert!(cc.contains("no-store"), "want no-store, got: {}", cc);
}

#[tokio::test]
async fn content_type_is_json() {
    let app = build_app();
    let (_, _, headers) = call(app, get_request("/gated")).await;
    let ct = headers
        .get("content-type")
        .expect("content-type present")
        .to_str()
        .expect("utf-8");
    assert!(ct.contains("application/json"), "got: {}", ct);
}

#[tokio::test]
async fn request_with_x_payment_header_gets_501_placeholder() {
    // WP-02.3 implements the paid path. Until then the service
    // returns 501 with a clear message — better than silently 500
    // or passing through.
    let app = build_app();
    let req = Request::builder()
        .uri("/gated")
        .header("x-payment", "anything")
        .body(Body::empty())
        .expect("build request");
    let (status, body, _) = call(app, req).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    let body = json(&body);
    assert_eq!(body["error"].as_str(), Some("not implemented"));
    assert!(
        body["reason"]
            .as_str()
            .unwrap_or("")
            .contains("WP-02.3"),
        "reason should name the next WP, got: {:?}",
        body["reason"]
    );
}

#[tokio::test]
async fn different_chain_ids_produce_different_challenge_chain_id() {
    // Cross-chain replay prevention lives in the domain separator.
    // This test simply confirms the layer surfaces its configured
    // chain_id verbatim in the challenge — a downstream signer that
    // binds to it gets the right chain.
    let mainnet_layer = X402Layer::builder()
        .chain_id(1)
        .facilitator_address(any_addr())
        .wsalt_address(any_addr())
        .treasury(any_addr())
        .rpc_url("http://127.0.0.1:18545")
        .pricing(FixedPricing::new("100"))
        .build()
        .expect("build");
    let app = Router::new()
        .route("/g", get(|| async { "" }))
        .layer(mainnet_layer);
    let (_, body, _) = call(app, get_request("/g")).await;
    let body = json(&body);
    assert_eq!(body["x402"]["chain_id"].as_u64(), Some(1));
}
