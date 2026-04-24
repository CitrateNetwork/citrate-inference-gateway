//! WP-03.1 smoke test — written BEFORE the implementation.
//!
//! Per CM-02 RETRO action item #1: "Write the smoke integration
//! test FIRST. Lesson from the digest mismatch [in WP-02.4]: build
//! a test that exercises the full intended flow, make it pass,
//! then break it into units."
//!
//! Scope of this test (matches WP-03.1 in the sprint file):
//!   - GET /health returns 200 with {"ok": true} EVEN WHEN the
//!     chain RPC is unreachable
//!   - GET /v1/models returns OpenAI-compatible JSON shape
//!   - No payment required for either endpoint
//!
//! What this test does NOT cover (later WPs):
//!   - WP-03.2: /v1/chat/completions (sync)
//!   - WP-03.3: /v1/batch
//!   - WP-03.4: API key auth
//!   - WP-03.5: /v1/usage
//!
//! When this test passes, WP-03.1 is done.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use citrate_gateway::{build_router, GatewayConfig};

fn config_with_unreachable_chain() -> GatewayConfig {
    GatewayConfig {
        chain_id: 40204,
        // Deliberately a port nothing is listening on — proves the
        // gateway doesn't depend on chain reachability for /health.
        rpc_url: "http://127.0.0.1:1".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        contracts: citrate_gateway::config::ContractAddresses::default(),
    }
}

async fn call(app: axum::Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let res = app.oneshot(req).await.expect("service call");
    let status = res.status();
    let body = res
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn health_returns_200_even_when_chain_is_unreachable() {
    // Gherkin scenario: "GET /v1/models is resilient to chain RPC
    // unreachable" — the actual claim is that /health stays up,
    // which load balancers depend on.
    let app = build_router(config_with_unreachable_chain()).await;
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .expect("build request");
    let (status, body) = call(app, req).await;
    assert_eq!(status, StatusCode::OK, "health must be 200 even with bad chain");
    let json: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["ok"].as_bool(), Some(true));
}

#[tokio::test]
async fn models_endpoint_returns_openai_shape() {
    // Gherkin scenario: "GET /v1/models returns OpenAI-compatible
    // model list". Body shape matches the OpenAI list-models response.
    let app = build_router(config_with_unreachable_chain()).await;
    let req = Request::builder()
        .uri("/v1/models")
        .body(Body::empty())
        .expect("build request");
    let (status, body) = call(app, req).await;
    assert_eq!(status, StatusCode::OK);

    let json: Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["object"].as_str(), Some("list"));
    let data = json["data"].as_array().expect("data array");
    // With unreachable chain the list is empty (no models from
    // ModelRegistry). That's a clean degraded state — better than
    // 500'ing.
    for entry in data {
        assert_eq!(entry["object"].as_str(), Some("model"));
        assert!(entry["id"].is_string(), "model entry must have string id");
        assert!(entry["created"].is_number(), "model entry must have created timestamp");
    }
}

#[tokio::test]
async fn models_endpoint_does_not_require_payment() {
    // Gherkin: "no payment is required for this endpoint"
    let app = build_router(config_with_unreachable_chain()).await;
    // Send WITHOUT an X-PAYMENT header — must still get 200.
    let req = Request::builder()
        .uri("/v1/models")
        .body(Body::empty())
        .expect("build request");
    let (status, _) = call(app, req).await;
    assert_eq!(status, StatusCode::OK, "no x402 challenge for free endpoint");
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let app = build_router(config_with_unreachable_chain()).await;
    let req = Request::builder()
        .uri("/v1/does-not-exist")
        .body(Body::empty())
        .expect("build request");
    let (status, _) = call(app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_response_is_under_a_kilobyte() {
    // Operational sanity: /health is hammered by load balancers
    // every second; oversized response = wasted bandwidth.
    let app = build_router(config_with_unreachable_chain()).await;
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .expect("build request");
    let (_, body) = call(app, req).await;
    assert!(
        body.len() < 1024,
        "health body should be tiny, got {} bytes",
        body.len()
    );
}
