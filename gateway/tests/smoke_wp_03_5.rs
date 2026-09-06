//! WP-03.5 smoke test — `/v1/usage` endpoint, written FIRST.
//!
//! Slice 1 scope:
//!   - In-memory `UsageStore` aggregated by `{key_id, date}`
//!   - Writer: each successful chat completion (when submitted with
//!     an API key) emits exactly one usage row
//!   - Reader: `GET /v1/usage` with `Authorization: Bearer <key>`
//!     returns per-day + aggregate totals for the caller's key only
//!   - SALT spent surfaced in BOTH `salt_spent_grains` (U256 string)
//!     and `salt_spent_display` (human-readable via
//!     `citrate-wallet-core::format::grains_to_salt`)

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Json as JsonExtractor;
use axum::routing::post;
use axum::Json as JsonResp;
use ethereum_types::{H160, H256, U256};
use serde_json::Value;
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


// ── Stub provider — fixed token counts for deterministic assertions ──

async fn spawn_stub_provider() -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(|JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| async move {
            let prompt = req.prompt.clone();
            JsonResp(serde_json::json!({
                "output": format!("STUB-RESPONSE: {}", prompt),
                "input_tokens": 7,
                "output_tokens": 13,
            }))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub serve");
    });
    addr
}

// ── Mocks (unchanged from smoke_wp_03_4) ────────────────────────

struct MockChainQueries {
    provider_endpoint: String,
}
#[async_trait]
impl ChainQueries for MockChainQueries {
    async fn resolve_model_name(&self, _n: &str) -> Result<H256, citrate_gateway::GatewayError> {
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
    fn new(facilitator: H160) -> Self {
        Self { facilitator, settled: Mutex::new(HashSet::new()) }
    }
}
#[async_trait]
impl ChainClient for HonestMockChain {
    async fn verify_offline(&self, precompile_input: &[u8]) -> Result<Option<H160>, X402Error> {
        if precompile_input.len() != 265 {
            return Ok(None);
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&precompile_input[32..52]);
        Ok(Some(H160::from(addr)))
    }
    async fn get_nonce(&self, _: H160) -> Result<u64, X402Error> { Ok(0) }
    async fn send_raw_tx(&self, _: &[u8]) -> Result<H256, X402Error> { Ok(H256::from([0xab; 32])) }
    async fn wait_for_receipt(&self, _: H256, _: Duration) -> Result<TxReceipt, X402Error> {
        let nonce = H256::from([0x77; 32]);
        let mut settled = self.settled.lock().expect("mutex");
        if !settled.insert(nonce) {
            return Ok(TxReceipt { status: false, block_number: 2, logs: vec![] });
        }
        drop(settled);
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
    let queries = Arc::new(MockChainQueries { provider_endpoint: provider.to_string() });
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

fn chat_body() -> Value {
    serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 10
    })
}

async fn chat_with_key(gw: SocketAddr, key_id: &str) {
    let url = format!("http://{}/v1/chat/completions", gw);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&chat_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

async fn get_usage(gw: SocketAddr, bearer: Option<&str>) -> (reqwest::StatusCode, Value) {
    let url = format!("http://{}/v1/usage", gw);
    let mut req = reqwest::Client::new().get(&url);
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {}", b));
    }
    let resp = req.send().await.expect("send");
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

// ── Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn three_requests_appear_in_usage_totals() {
    let provider = spawn_stub_provider().await;
    let (gw, keys) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let initial = U256::from(100) * U256::from(1_000_000_000_000_000_000u128);
    let key_id = create_key(&keys, "pilot", initial, H160::from([0xde; 20])).await;

    chat_with_key(gw, &key_id).await;
    chat_with_key(gw, &key_id).await;
    chat_with_key(gw, &key_id).await;

    let (status, body) = get_usage(gw, Some(&key_id)).await;
    assert_eq!(status, 200);
    assert_eq!(body["total_requests"].as_u64(), Some(3));
    assert_eq!(body["total_input_tokens"].as_u64(), Some(21));
    // Provider reports 13, but the request's max_tokens=10 is the authoritative
    // output bound used for persisted usage.
    assert_eq!(body["total_output_tokens"].as_u64(), Some(30));
    assert!(body["salt_spent_grains"].is_string(), "grains as U256 string");
    let display = body["salt_spent_display"].as_str().expect("display");
    assert!(display.ends_with(" SALT"), "display suffix, got: {}", display);
}

#[tokio::test]
async fn missing_authorization_is_401() {
    let provider = spawn_stub_provider().await;
    let (gw, _) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, body) = get_usage(gw, None).await;
    assert_eq!(status, 401);
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.to_lowercase().contains("bearer") || msg.to_lowercase().contains("authorization"),
        "got: {}",
        msg
    );
}

#[tokio::test]
async fn unknown_key_is_401() {
    let provider = spawn_stub_provider().await;
    let (gw, _) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, _) = get_usage(gw, Some("nope-not-real")).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn usage_is_per_key_not_global() {
    let provider = spawn_stub_provider().await;
    let (gw, keys) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let initial = U256::from(100) * U256::from(1_000_000_000_000_000_000u128);
    let key_a = create_key(&keys, "a", initial, H160::from([0xa1; 20])).await;
    let key_b = create_key(&keys, "b", initial, H160::from([0xb1; 20])).await;

    chat_with_key(gw, &key_a).await;
    chat_with_key(gw, &key_a).await;
    chat_with_key(gw, &key_b).await;
    chat_with_key(gw, &key_b).await;
    chat_with_key(gw, &key_b).await;

    let (_, body_a) = get_usage(gw, Some(&key_a)).await;
    assert_eq!(body_a["total_requests"].as_u64(), Some(2));

    let (_, body_b) = get_usage(gw, Some(&key_b)).await;
    assert_eq!(body_b["total_requests"].as_u64(), Some(3));
}

#[tokio::test]
async fn usage_has_daily_breakdown_for_today() {
    let provider = spawn_stub_provider().await;
    let (gw, keys) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let initial = U256::from(100) * U256::from(1_000_000_000_000_000_000u128);
    let key_id = create_key(&keys, "pilot", initial, H160::from([0xde; 20])).await;

    chat_with_key(gw, &key_id).await;
    chat_with_key(gw, &key_id).await;

    let (_, body) = get_usage(gw, Some(&key_id)).await;
    let daily = body["daily"].as_array().expect("daily array");
    assert_eq!(daily.len(), 1, "only today's row");
    let entry = &daily[0];
    assert_eq!(entry["requests"].as_u64(), Some(2));
    assert_eq!(entry["input_tokens"].as_u64(), Some(14));
    // Provider reports 13 per request; the gateway clamps to max_tokens=10.
    assert_eq!(entry["output_tokens"].as_u64(), Some(20));
    assert!(entry["date"].is_string(), "date YYYY-MM-DD");
}
