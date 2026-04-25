//! WP-03.4 smoke test — API key auth, written FIRST.
//!
//! Slice 1 scope:
//!   - In-memory `ApiKeyStore`
//!   - `ApiKeyLayer` sits in front of `X402Layer`; valid key bypasses
//!     x402 by injecting a synthetic `X402Paid` into request extensions
//!   - Exhausted key falls through to x402 with a `deposit_instructions`
//!     field in the challenge body
//!   - Revoked / unknown keys are rejected with 401
//!
//! RocksDB persistence, admin CLI, and the SALT → wSALT auto-wrap
//! flow are slice 2.

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

// ── Stub provider ───────────────────────────────────────────────

async fn spawn_stub_provider() -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(|JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| async move {
            let prompt = req.prompt.clone();
            JsonResp(serde_json::json!({
                "output": format!("STUB-RESPONSE: {}", prompt),
                "input_tokens": prompt.split_whitespace().count(),
                "output_tokens": 4,
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

// ── Mock chain queries ──────────────────────────────────────────

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

// ── Mock chain client (copied from smoke_wp_03_2) ───────────────

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
    async fn verify_offline(&self, precompile_input: &[u8]) -> Result<Option<H160>, X402Error> {
        if precompile_input.len() != 265 {
            return Ok(None);
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&precompile_input[32..52]);
        Ok(Some(H160::from(addr)))
    }
    async fn get_nonce(&self, _a: H160) -> Result<u64, X402Error> {
        Ok(0)
    }
    async fn send_raw_tx(&self, _tx: &[u8]) -> Result<H256, X402Error> {
        Ok(H256::from([0xab; 32]))
    }
    async fn wait_for_receipt(
        &self,
        _h: H256,
        _t: Duration,
    ) -> Result<TxReceipt, X402Error> {
        let nonce = H256::from([0x77; 32]);
        let mut settled = self.settled.lock().expect("mutex");
        if !settled.insert(nonce) {
            return Ok(TxReceipt {
                status: false,
                block_number: 2,
                logs: vec![],
            });
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

// ── Helpers ─────────────────────────────────────────────────────

fn operator_secret() -> [u8; 32] {
    [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
        0xff, 0x80,
    ]
}

async fn spawn_gateway(
    provider_addr: SocketAddr,
) -> (SocketAddr, Arc<ApiKeyStore>) {
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(MockChainQueries {
        provider_endpoint: provider_addr.to_string(),
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

// ── Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn valid_key_with_balance_bypasses_x402() {
    let provider = spawn_stub_provider().await;
    let (gateway, keys) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Fund with 10 SALT (10 × 1e18 grains).
    let initial = U256::from(10) * U256::from(1_000_000_000_000_000_000u128);
    let key_id = create_key(&keys, "pilot", initial, H160::from([0xde; 20])).await;

    let url = format!("http://{}/v1/chat/completions", gateway);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&chat_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200, "valid key should bypass x402");
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["object"].as_str(), Some("chat.completion"));

    // Balance should have dropped by exactly the priced amount.
    let record = keys.get(&key_id).await.expect("key still exists");
    assert!(
        record.balance_grains < initial,
        "balance should drop after request; was {} now {}",
        initial,
        record.balance_grains
    );
    let deducted = initial - record.balance_grains;
    // TokenBasedPricing default estimate is deterministic — must be
    // non-zero and ≤ initial.
    assert!(deducted > U256::zero());
}

#[tokio::test]
async fn unknown_key_is_rejected_401() {
    let provider = spawn_stub_provider().await;
    let (gateway, _) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/v1/chat/completions", gateway);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", "Bearer nope-not-a-key")
        .json(&chat_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("unknown"), "got: {}", msg);
}

#[tokio::test]
async fn revoked_key_is_rejected_401() {
    let provider = spawn_stub_provider().await;
    let (gateway, keys) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let initial = U256::from(10) * U256::from(1_000_000_000_000_000_000u128);
    let key_id = create_key(&keys, "pilot", initial, H160::from([0xde; 20])).await;
    keys.revoke(&key_id).await.expect("revoke");

    let url = format!("http://{}/v1/chat/completions", gateway);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&chat_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("revoked"), "got: {}", msg);
}

#[tokio::test]
async fn exhausted_key_falls_through_to_402_with_deposit_hint() {
    let provider = spawn_stub_provider().await;
    let (gateway, keys) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let deposit = H160::from([0xde; 20]);
    // Zero balance from the start.
    let key_id = create_key(&keys, "pilot", U256::zero(), deposit).await;

    let url = format!("http://{}/v1/chat/completions", gateway);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&chat_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 402, "exhausted key should see x402 challenge");
    let body: Value = resp.json().await.expect("json");
    assert!(body.get("x402").is_some(), "challenge envelope required");
    let hint = body["deposit_instructions"]
        .as_object()
        .expect("deposit_instructions field present");
    let addr = hint["address"].as_str().expect("address");
    let expected = format!("0x{}", hex::encode(deposit.as_bytes()));
    assert_eq!(addr, expected);
}

#[tokio::test]
async fn missing_authorization_keeps_plain_x402_path() {
    let provider = spawn_stub_provider().await;
    let (gateway, _) = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/v1/chat/completions", gateway);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&chat_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 402);
    let body: Value = resp.json().await.expect("json");
    assert!(body.get("x402").is_some());
    assert!(
        body.get("deposit_instructions").is_none(),
        "no auth → no per-key deposit hint"
    );
}
