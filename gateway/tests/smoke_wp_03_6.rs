//! WP-03.6 smoke test — `/metrics` Prometheus endpoint.
//!
//! Proves:
//!   - `GET /metrics` returns 200 with the Prometheus text-exposition
//!     content type
//!   - The exposition format advertises every metric from the
//!     runbook catalogue (see `gateway/src/metrics.rs` constants)
//!   - After a successful chat request via an API key, the
//!     `gateway_chat_requests_total{outcome="success"}` counter
//!     reports a non-zero value

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Json as JsonExtractor;
use axum::routing::post;
use axum::Json as JsonResp;
use ethereum_types::{H160, H256, U256};
use tokio::net::TcpListener;

use citrate_gateway::auth::{create_key, ApiKeyStore};
use citrate_gateway::queries::ChainQueries;
use citrate_gateway::{
    build_router_with_auth, GatewayConfig, ProviderInfo, ProviderProtocolRequest,
};
use x402_axum::{ChainClient, RawLog, TxReceipt, X402Error};

/// 2026-05-31 audit -007 (SECREM-02 6.4a): explicit money-path
/// addresses (the placeholder default was removed from the builders).
const TEST_WSALT: &str = "0x61bc737f67b430fe2567630823694032a049253e";
const TEST_TREASURY: &str = "0x7e577e577e577e577e577e577e577e577e577e57";

async fn spawn_stub_provider() -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(
            |JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| async move {
                let prompt = req.prompt.clone();
                JsonResp(serde_json::json!({
                    "output": format!("STUB-RESPONSE: {}", prompt),
                    "input_tokens": 7,
                    "output_tokens": 13,
                }))
            },
        ),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub serve");
    });
    addr
}

struct MockChainQueries {
    provider_endpoint: String,
}
#[async_trait]
impl ChainQueries for MockChainQueries {
    async fn resolve_model_name(&self, _: &str) -> Result<H256, citrate_gateway::GatewayError> {
        Ok(H256::from([0xab; 32]))
    }
    async fn estimate_cost(
        &self,
        _: H256,
        _: u32,
        _: u32,
        _: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        Ok(U256::from(1_000_000_000_000_000_000u128))
    }
    async fn list_providers(
        &self,
        _: H256,
    ) -> Result<Vec<ProviderInfo>, citrate_gateway::GatewayError> {
        Ok(vec![ProviderInfo {
            address: H160::from([0xb1; 20]),
            endpoint: format!("http://{}/infer", self.provider_endpoint),
            reputation_bps: 9500,
            current_load: 0,
            max_concurrent: 10,
        }])
    }
}

struct HonestMockChain {
    facilitator: H160,
    settled: Mutex<HashSet<H256>>,
}
impl HonestMockChain {
    fn new(f: H160) -> Self {
        Self {
            facilitator: f,
            settled: Mutex::new(HashSet::new()),
        }
    }
}
#[async_trait]
impl ChainClient for HonestMockChain {
    async fn verify_offline(&self, input: &[u8]) -> Result<Option<H160>, X402Error> {
        if input.len() != 265 {
            return Ok(None);
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&input[32..52]);
        Ok(Some(H160::from(a)))
    }
    async fn get_nonce(&self, _: H160) -> Result<u64, X402Error> {
        Ok(0)
    }
    async fn send_raw_tx(&self, _: &[u8]) -> Result<H256, X402Error> {
        Ok(H256::from([0xab; 32]))
    }
    async fn wait_for_receipt(&self, _: H256, _: Duration) -> Result<TxReceipt, X402Error> {
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

fn operator_secret() -> [u8; 32] {
    [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
        0xff, 0x80,
    ]
}

async fn spawn_gateway(provider: SocketAddr) -> (SocketAddr, Arc<ApiKeyStore>) {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(MockChainQueries {
        provider_endpoint: provider.to_string(),
    });
    let chain = Arc::new(HonestMockChain::new(facilitator));
    let keys = Arc::new(ApiKeyStore::new());
    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused-mock".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        contracts: citrate_gateway::config::ContractAddresses::default(),
    };
    let app = build_router_with_auth(
        config,
        queries,
        chain,
        operator_secret(),
        facilitator,
        TEST_WSALT,
        TEST_TREASURY,
        keys.clone(),
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gw");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gw serve");
    });
    (addr, keys)
}

#[tokio::test]
async fn metrics_endpoint_returns_text_exposition() {
    // IGW-B-012: /metrics is now gated behind an operator bearer token.
    // Pre-fix an unauthenticated GET returned 200 with the full Prometheus
    // catalogue (a request-volume / credential-feedback oracle). Configure
    // the token, prove an unauthenticated scrape is refused (401), then a
    // token-bearing scrape renders the exposition.
    std::env::set_var("CITRATE_GATEWAY_METRICS_TOKEN", "smoke-metrics-secret");
    let provider = spawn_stub_provider().await;
    let (gw, _) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/metrics", gw);

    // Unauthenticated → 401 (the catalogue is not exposed).
    let unauth = reqwest::get(&url).await.expect("metrics unauth");
    assert_eq!(
        unauth.status(),
        401,
        "unauthenticated /metrics must be refused (IGW-B-012)"
    );

    // With the operator token → 200 + exposition.
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth("smoke-metrics-secret")
        .send()
        .await
        .expect("metrics");
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.starts_with("text/plain"), "got: {}", ct);
    let body = resp.text().await.expect("text");
    // Every metric in the runbook catalogue must be advertised via
    // at least a TYPE / HELP line so dashboards can wire up cleanly.
    for name in [
        "gateway_chat_requests_total",
        "gateway_batch_submissions_total",
        "gateway_api_key_requests_total",
        "gateway_usage_rows_emitted_total",
        "gateway_provider_dispatch_failures_total",
    ] {
        assert!(
            body.contains(name),
            "metric {} missing from /metrics exposition:\n{}",
            name,
            body
        );
    }
}

#[tokio::test]
async fn chat_request_increments_counter() {
    // IGW-B-012: /metrics requires the operator token; configure it so the
    // scrape below is authorized.
    std::env::set_var("CITRATE_GATEWAY_METRICS_TOKEN", "smoke-metrics-secret");
    let provider = spawn_stub_provider().await;
    let (gw, keys) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Fund a key, issue a chat call.
    let initial = U256::from(100) * U256::from(1_000_000_000_000_000_000u128);
    let key_id = create_key(&keys, "pilot", initial, H160::from([0xde; 20])).await;
    let chat_url = format!("http://{}/v1/chat/completions", gw);
    let resp = reqwest::Client::new()
        .post(&chat_url)
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&serde_json::json!({
            "model": "llama-3.1-8b",
            "messages": [{"role":"user","content":"ping"}],
            "max_tokens": 10
        }))
        .send()
        .await
        .expect("chat");
    assert_eq!(resp.status(), 200);

    // Scrape /metrics (with the operator token) and confirm the success
    // counter moved.
    let body = reqwest::Client::new()
        .get(format!("http://{}/metrics", gw))
        .bearer_auth("smoke-metrics-secret")
        .send()
        .await
        .expect("metrics")
        .text()
        .await
        .expect("text");

    // The exposition writes per-label lines; look for the success
    // variant and parse its value > 0.
    let success_line = body
        .lines()
        .find(|l| {
            l.starts_with("gateway_chat_requests_total{") && l.contains("outcome=\"success\"")
        })
        .unwrap_or_else(|| panic!("no success counter in\n{}", body));
    let val: f64 = success_line
        .split_whitespace()
        .last()
        .expect("value")
        .parse()
        .expect("f64");
    assert!(
        val >= 1.0,
        "counter should be ≥ 1, got {} in line {}",
        val,
        success_line
    );
}
