//! WP-05.4 smoke test — pool-aware dispatch in the gateway.
//!
//! Slice 1 scope:
//!   - `ChainQueries::list_pools(model_hash)` returns pool entries
//!     alongside individual providers
//!   - `/v1/models` includes pool entries prefixed with `pool-`
//!   - The dispatch selector scores pools and individuals on one
//!     comparable axis; a pool with min-member-reputation × stake
//!     above the best individual's score wins
//!   - When a pool wins, the chat handler returns 503 with a clear
//!     slice-2 message (on-chain `requestPoolCompute` requires the
//!     gateway wallet, deferred to WP-05.4 slice 2)
//!   - When NO pool exists, the existing individual-provider path
//!     is unchanged
//!
//! Spec: .agentile/formal/specs/compute/InferencePoolLifecycle.tla
//! Behavior: citrate_v0.01.1/specs/gherkin/inference_pool.feature
//!   ("Gateway prefers a pool over individual provider when both
//!    serve a model"; "Pool appears in /v1/models alongside
//!    individual providers")

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

use citrate_gateway::queries::{ChainQueries, PoolEntry, ProviderInfo};
use citrate_gateway::{
    build_router_with, GatewayConfig, ProviderProtocolRequest,
};
use x402_axum::{ChainClient, RawLog, TxReceipt, X402Client, X402Error};

// ── Stub provider ───────────────────────────────────────────────

async fn spawn_stub_provider() -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(|JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| async move {
            JsonResp(serde_json::json!({
                "output": format!("STUB-RESPONSE: {}", req.prompt),
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

// ── Mock chain queries (pools + individuals) ────────────────────

struct MockQueries {
    provider_endpoint: String,
    pools: Vec<PoolEntry>,
    /// If false, list_providers returns empty so the only option is
    /// a pool (or a 503 if no pool either).
    expose_individual: bool,
}

#[async_trait]
impl ChainQueries for MockQueries {
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
        if !self.expose_individual {
            return Ok(vec![]);
        }
        Ok(vec![ProviderInfo {
            address: H160::from([0xb1; 20]),
            endpoint: format!("http://{}/infer", self.provider_endpoint),
            reputation_bps: 9000, // moderate individual
            current_load: 0,
            max_concurrent: 10,
        }])
    }
    async fn list_pools(
        &self,
        _: H256,
    ) -> Result<Vec<PoolEntry>, citrate_gateway::GatewayError> {
        Ok(self.pools.clone())
    }
}

// ── Mock chain client (x402) ────────────────────────────────────

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
    async fn verify_offline(&self, input: &[u8]) -> Result<Option<H160>, X402Error> {
        if input.len() != 265 { return Ok(None); }
        let mut a = [0u8; 20];
        a.copy_from_slice(&input[32..52]);
        Ok(Some(H160::from(a)))
    }
    async fn get_nonce(&self, _: H160) -> Result<u64, X402Error> { Ok(0) }
    async fn send_raw_tx(&self, _: &[u8]) -> Result<H256, X402Error> { Ok(H256::from([0xab; 32])) }
    async fn wait_for_receipt(&self, _: H256, _: Duration) -> Result<TxReceipt, X402Error> {
        let nonce = H256::from([0x77; 32]);
        let mut s = self.settled.lock().expect("mutex");
        if !s.insert(nonce) { return Ok(TxReceipt { status: false, block_number: 2, logs: vec![] }); }
        drop(s);
        let from = H160::from([0xa1; 20]);
        let to = H160::from([0xa2; 20]);
        let value = U256::from(995_000_000_000_000_000u128);
        let fee = U256::from(5_000_000_000_000_000u128);
        let mut padded_from = [0u8; 32]; padded_from[12..32].copy_from_slice(from.as_bytes());
        let mut padded_to = [0u8; 32]; padded_to[12..32].copy_from_slice(to.as_bytes());
        let mut data = Vec::with_capacity(96);
        let mut buf = [0u8; 32];
        value.to_big_endian(&mut buf); data.extend_from_slice(&buf);
        fee.to_big_endian(&mut buf); data.extend_from_slice(&buf);
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

async fn spawn_gateway(
    provider: SocketAddr,
    pools: Vec<PoolEntry>,
    expose_individual: bool,
) -> SocketAddr {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(MockQueries {
        provider_endpoint: provider.to_string(),
        pools,
        expose_individual,
    });
    let chain = Arc::new(HonestMockChain::new(facilitator));
    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        contracts: citrate_gateway::config::ContractAddresses::default(),
    };
    let app = build_router_with(config, queries, chain, operator_secret(), facilitator).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gw");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gw serve");
    });
    addr
}

fn good_pool() -> PoolEntry {
    PoolEntry {
        pool_id: 7,
        name: "pool-llama-70b".to_string(),
        total_stake_grains: U256::from(500u64) * U256::from(1_000_000_000_000_000_000u128),
        member_count: 3,
        // Min-member-reputation 9500 bps × stake 500 SALT >> any
        // single 9000 bps × 100 SALT individual.
        min_member_reputation_bps: 9500,
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn models_endpoint_lists_pools_with_pool_prefix() {
    let provider = spawn_stub_provider().await;
    let gateway = spawn_gateway(provider, vec![good_pool()], true).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/v1/models", gateway);
    let resp = reqwest::get(&url).await.expect("get");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json");
    let data = body["data"].as_array().expect("data");

    // At least one entry has id starting with "pool-"
    let pool_ids: Vec<String> = data
        .iter()
        .filter_map(|e| e["id"].as_str().map(String::from))
        .filter(|id| id.starts_with("pool-"))
        .collect();
    assert!(!pool_ids.is_empty(), "no pool- entries: {}", body);
    assert!(
        pool_ids.iter().any(|id| id == "pool-llama-70b"),
        "pool-llama-70b missing: {:?}",
        pool_ids
    );
}

#[tokio::test]
async fn models_without_pools_returns_only_individuals() {
    let provider = spawn_stub_provider().await;
    let gateway = spawn_gateway(provider, vec![], true).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/v1/models", gateway);
    let body: Value = reqwest::get(&url)
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    let data = body["data"].as_array().expect("data");
    for e in data {
        let id = e["id"].as_str().unwrap_or("");
        assert!(!id.starts_with("pool-"), "unexpected pool entry: {}", id);
    }
}

#[tokio::test]
async fn pool_wins_selection_returns_503_slice2() {
    // High-scoring pool + a normal individual provider. Selector
    // picks the pool. Slice-1 chat handler returns 503 with the
    // documented "slice 2" message.
    let provider = spawn_stub_provider().await;
    let gateway = spawn_gateway(provider, vec![good_pool()], true).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).expect("hex"));
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    let url = format!("http://{}/v1/chat/completions", gateway);
    let body = serde_json::json!({
        "model": "pool-llama-70b",
        "messages": [{"role":"user","content":"ping"}],
        "max_tokens": 10
    });
    let req = reqwest::Client::new().post(&url).json(&body);
    let resp = client.send_paid(req).await.expect("send");
    assert_eq!(resp.status(), 503, "pool dispatch should be 503 in slice 1");
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_lowercase();
    assert!(
        msg.contains("pool") && msg.contains("slice"),
        "want explicit slice-2 marker, got: {}",
        msg
    );
}

#[tokio::test]
async fn no_pool_falls_through_to_individual_dispatch() {
    // Same setup but no pools listed. Existing individual-provider
    // path must work unchanged (CM-03 WP-03.2 happy path).
    let provider = spawn_stub_provider().await;
    let gateway = spawn_gateway(provider, vec![], true).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).expect("hex"));
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    let url = format!("http://{}/v1/chat/completions", gateway);
    let body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role":"user","content":"ping"}],
        "max_tokens": 10
    });
    let req = reqwest::Client::new().post(&url).json(&body);
    let resp = client.send_paid(req).await.expect("send");
    assert_eq!(resp.status(), 200, "individual path should still 200");
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["object"].as_str(), Some("chat.completion"));
}

#[tokio::test]
async fn weak_pool_loses_to_strong_individual() {
    // Pool with 1 member at 5000 bps & 10 SALT stake should LOSE
    // to a 9000-bps individual with 100 SALT stake. The chat call
    // therefore reaches the individual via the existing path → 200.
    let weak_pool = PoolEntry {
        pool_id: 9,
        name: "pool-wimpy".to_string(),
        total_stake_grains: U256::from(10u64) * U256::from(1_000_000_000_000_000_000u128),
        member_count: 1,
        min_member_reputation_bps: 5000,
    };
    let provider = spawn_stub_provider().await;
    let gateway = spawn_gateway(provider, vec![weak_pool], true).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).expect("hex"));
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    let url = format!("http://{}/v1/chat/completions", gateway);
    let body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role":"user","content":"ping"}],
        "max_tokens": 10
    });
    let req = reqwest::Client::new().post(&url).json(&body);
    let resp = client.send_paid(req).await.expect("send");
    assert_eq!(resp.status(), 200, "individual with stronger score should win");
}
