//! WP-03.2 slice 2 smoke test — written FIRST.
//!
//! Covers gateway_inference.feature scenarios:
//!   - "Sync chat with provider timeout returns 503 (payment retained)"
//!     (variant: tries fallback provider; if BOTH fail → 503)
//!   - "Sync chat with no providers available returns 503"
//!   - "SSE streaming for stream=true requests"

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Json as JsonExtractor;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Json as JsonResp;
use ethereum_types::{H160, H256, U256};
use serde_json::Value;
use tokio::net::TcpListener;

use citrate_gateway::{build_router_with, GatewayConfig, ProviderInfo, ProviderProtocolRequest};
use citrate_gateway::queries::ChainQueries;
use x402_axum::{ChainClient, RawLog, TxReceipt, X402Client, X402Error};

/// 2026-05-31 audit -007 (SECREM-02 6.4a): explicit money-path
/// addresses (the placeholder default was removed from the builders).
const TEST_WSALT: &str = "0x61bc737f67b430fe2567630823694032a049253e";
const TEST_TREASURY: &str = "0x7e577e577e577e577e577e577e577e577e577e57";


// ── Stub providers with controllable behavior ────────────────────

#[derive(Clone, Copy)]
#[allow(dead_code)] // Timeout variant reserved for follow-up timeout test
enum StubBehavior {
    Ok,
    HttpFiveHundred,
    Timeout,
}

async fn spawn_stub(behavior: StubBehavior) -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(move |JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| async move {
            match behavior {
                StubBehavior::Ok => (
                    StatusCode::OK,
                    JsonResp(serde_json::json!({
                        "output": format!("OK: {}", req.prompt),
                        "input_tokens": 1,
                        "output_tokens": 1,
                    })),
                )
                    .into_response(),
                StubBehavior::HttpFiveHundred => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    JsonResp(serde_json::json!({"error": "stub 500"})),
                )
                    .into_response(),
                StubBehavior::Timeout => {
                    tokio::time::sleep(Duration::from_secs(120)).await;
                    (StatusCode::OK, JsonResp(serde_json::json!({"output": "late"})))
                        .into_response()
                }
            }
        }),
    );
    use axum::response::IntoResponse;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub serve");
    });
    addr
}

// ── Mock chain queries with configurable provider list ───────────

struct MockQueries {
    providers: Vec<ProviderInfo>,
}

#[async_trait]
impl ChainQueries for MockQueries {
    async fn resolve_model_name(&self, _name: &str) -> Result<H256, citrate_gateway::GatewayError> {
        Ok(H256::from([0xab; 32]))
    }
    async fn estimate_cost(
        &self,
        _: H256,
        _: u32,
        _: u32,
        _: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        Ok(U256::from(1_000_000_000_000_000_000u128)) // 1 SALT
    }
    async fn list_providers(
        &self,
        _: H256,
    ) -> Result<Vec<ProviderInfo>, citrate_gateway::GatewayError> {
        Ok(self.providers.clone())
    }
}

// ── Mock chain client (trusts every signature) ───────────────────

struct HonestMockChain {
    facilitator: H160,
    settled: Mutex<HashSet<H256>>,
}

impl HonestMockChain {
    fn new(facilitator: H160) -> Self {
        Self {
            facilitator,
            settled: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl ChainClient for HonestMockChain {
    async fn verify_offline(
        &self,
        precompile_input: &[u8],
    ) -> Result<Option<H160>, X402Error> {
        if precompile_input.len() != 265 {
            return Ok(None);
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&precompile_input[32..52]);
        Ok(Some(H160::from(addr)))
    }
    async fn get_nonce(&self, _: H160) -> Result<u64, X402Error> {
        Ok(0)
    }
    async fn send_raw_tx(&self, _: &[u8]) -> Result<H256, X402Error> {
        Ok(H256::from([0xab; 32]))
    }
    async fn wait_for_receipt(
        &self,
        _: H256,
        _: Duration,
    ) -> Result<TxReceipt, X402Error> {
        let nonce = H256::from([0x77; 32]);
        let mut s = self.settled.lock().expect("mutex");
        if !s.insert(nonce) {
            return Ok(TxReceipt {
                status: false,
                block_number: 2,
                logs: vec![],
            });
        }
        drop(s);
        let from = H160::from([0xa1; 20]);
        let to = H160::from([0xa2; 20]);
        let value = U256::from(995_000_000_000_000_000u128);
        let fee = U256::from(5_000_000_000_000_000u128);
        let mut padded_from = [0u8; 32];
        padded_from[12..32].copy_from_slice(from.as_bytes());
        let mut padded_to = [0u8; 32];
        padded_to[12..32].copy_from_slice(to.as_bytes());
        let mut data = Vec::with_capacity(96);
        let mut buf = [0u8; 32];
        value.to_big_endian(&mut buf);
        data.extend_from_slice(&buf);
        fee.to_big_endian(&mut buf);
        data.extend_from_slice(&buf);
        data.extend_from_slice(nonce.as_bytes());
        Ok(TxReceipt {
            status: true,
            block_number: 100,
            logs: vec![RawLog {
                address: self.facilitator,
                topics: vec![
                    x402_axum::payment_settled_topic(),
                    H256::from(padded_from),
                    H256::from(padded_to),
                ],
                data,
            }],
        })
    }
}

// ── Test helpers ────────────────────────────────────────────────

fn operator_secret() -> [u8; 32] {
    [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
        0xff, 0x80,
    ]
}

fn payer_secret() -> [u8; 32] {
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
        0x11, 0x22,
    ]
}

fn any_addr() -> &'static str {
    "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b"
}

fn provider_info(addr_byte: u8, endpoint: SocketAddr, reputation: u32) -> ProviderInfo {
    ProviderInfo {
        address: H160::from([addr_byte; 20]),
        endpoint: format!("http://{}/infer", endpoint),
        reputation_bps: reputation,
        current_load: 0,
        max_concurrent: 10,
    }
}

async fn spawn_gateway(providers: Vec<ProviderInfo>) -> SocketAddr {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(MockQueries { providers });
    let chain = Arc::new(HonestMockChain::new(facilitator));
    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused-mock".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        contracts: citrate_gateway::config::ContractAddresses::default(),
    };
    let app = build_router_with(
        config,
        queries,
        chain,
        operator_secret(),
        facilitator,
        TEST_WSALT,
        TEST_TREASURY,
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gw");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gw serve");
    });
    addr
}

async fn paid_chat(
    gateway_addr: SocketAddr,
) -> reqwest::Response {
    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");
    let url = format!("http://{}/v1/chat/completions", gateway_addr);
    let body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{ "role": "user", "content": "ping" }],
        "max_tokens": 5
    });
    client
        .send_paid(reqwest::Client::new().post(&url).json(&body))
        .await
        .expect("send_paid")
}

// ── Tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn provider_failover_first_5xx_second_succeeds() {
    // First provider returns 500; second returns OK. Gateway must
    // try the fallback and return 200.
    let bad = spawn_stub(StubBehavior::HttpFiveHundred).await;
    let good = spawn_stub(StubBehavior::Ok).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Higher reputation on the BAD provider so the selector picks
    // it first; the good one is the fallback.
    let providers = vec![
        provider_info(0x01, bad, 9500),
        provider_info(0x02, good, 8000),
    ];
    let gw = spawn_gateway(providers).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = paid_chat(gw).await;
    assert_eq!(
        resp.status(),
        200,
        "gateway should fail over to second provider"
    );
    let body: Value = resp.json().await.expect("json");
    let content = body["choices"][0]["message"]["content"]
        .as_str()
        .expect("content");
    assert!(
        content.contains("OK:"),
        "response should be from the good provider, got: {}",
        content
    );
}

#[tokio::test]
async fn all_providers_fail_returns_503() {
    let bad1 = spawn_stub(StubBehavior::HttpFiveHundred).await;
    let bad2 = spawn_stub(StubBehavior::HttpFiveHundred).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let providers = vec![
        provider_info(0x01, bad1, 9500),
        provider_info(0x02, bad2, 8000),
    ];
    let gw = spawn_gateway(providers).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = paid_chat(gw).await;
    assert_eq!(
        resp.status(),
        503,
        "all-fail must surface as 503 Service Unavailable"
    );
    // Per the documented "chargeback" policy, payment is NOT
    // refunded from this layer (mock chain has already settled).
    let body: Value = resp.json().await.expect("json");
    assert!(
        body["error"]["message"]
            .as_str()
            .map(|m| m.to_lowercase().contains("provider"))
            .unwrap_or(false),
        "error message should mention provider, got: {}",
        body
    );
}

#[tokio::test]
async fn no_providers_returns_503() {
    let gw = spawn_gateway(vec![]).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = paid_chat(gw).await;
    assert_eq!(
        resp.status(),
        503,
        "empty provider list → 503 NoProviders"
    );
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("provider"),
        "error should mention providers, got: {}",
        msg
    );
}

#[tokio::test]
async fn sse_stream_returns_event_stream_content_type() {
    // stream=true requests must return text/event-stream per OpenAI's
    // SSE convention, ending with "data: [DONE]\n\n".
    let good = spawn_stub(StubBehavior::Ok).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let providers = vec![provider_info(0x01, good, 9500)];
    let gw = spawn_gateway(providers).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");
    let url = format!("http://{}/v1/chat/completions", gw);
    let body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role": "user", "content": "stream me"}],
        "max_tokens": 5,
        "stream": true
    });
    let resp = client
        .send_paid(reqwest::Client::new().post(&url).json(&body))
        .await
        .expect("send_paid");
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/event-stream"),
        "content-type must be text/event-stream, got: {}",
        ct
    );
    let body_text = resp.text().await.expect("text");
    assert!(
        body_text.contains("data: "),
        "body should contain SSE data lines"
    );
    assert!(
        body_text.trim_end().ends_with("data: [DONE]"),
        "stream should end with [DONE], got: {:?}",
        body_text.lines().last()
    );
}
