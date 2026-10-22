//! `/v1/chat/completions` only accepts a provider result that is non-empty
//! AND passes the result-binding policy. A result whose signature does not
//! verify, or an empty result, is a dispatch failure: the buyer gets no 200
//! and the key is not charged for it.
//!
//! Drives the real router (`build_router_with_auth`) against a local stub
//! provider and in-process mocks. No network beyond loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::routing::post;
use axum::Json as JsonResp;
use ethereum_types::{H160, H256, U256};
use tokio::net::TcpListener;

use citrate_gateway::auth::{create_key, ApiKeyStore};
use citrate_gateway::queries::ChainQueries;
use citrate_gateway::{build_router_with_auth, GatewayConfig, GatewayError, ProviderInfo};
use x402_axum::{ChainClient, TxReceipt, X402Error};

const TEST_WSALT: &str = "0x61bc737f67b430fe2567630823694032a049253e";
const TEST_TREASURY: &str = "0x7e577e577e577e577e577e577e577e577e577e57";
const PRICE: u128 = 1_000_000_000_000_000_000;

/// A stub provider that always answers with `reply`.
async fn spawn_provider(reply: serde_json::Value) -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(move || {
            let reply = reply.clone();
            async move { JsonResp(reply) }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub serve");
    });
    addr
}

struct OneProvider {
    endpoint: String,
}

#[async_trait]
impl ChainQueries for OneProvider {
    async fn resolve_model_name(&self, _n: &str) -> Result<H256, GatewayError> {
        Ok(H256::from([0xab; 32]))
    }
    async fn estimate_cost(&self, _: H256, _: u32, _: u32, _: u8) -> Result<U256, GatewayError> {
        Ok(U256::from(PRICE))
    }
    async fn list_providers(&self, _: H256) -> Result<Vec<ProviderInfo>, GatewayError> {
        Ok(vec![ProviderInfo {
            address: H160::from([0xb1; 20]),
            endpoint: format!("http://{}/infer", self.endpoint),
            reputation_bps: 9500,
            current_load: 0,
            max_concurrent: 10,
        }])
    }
}

/// The API-key path never reaches the chain; every method refuses.
struct NoChain;

#[async_trait]
impl ChainClient for NoChain {
    async fn verify_offline(&self, _: &[u8]) -> Result<Option<H160>, X402Error> {
        Err(X402Error::RpcError("not used".into()))
    }
    async fn get_nonce(&self, _: H160) -> Result<u64, X402Error> {
        Err(X402Error::RpcError("not used".into()))
    }
    async fn send_raw_tx(&self, _: &[u8]) -> Result<H256, X402Error> {
        Err(X402Error::RpcError("not used".into()))
    }
    async fn wait_for_receipt(&self, _: H256, _: Duration) -> Result<TxReceipt, X402Error> {
        Err(X402Error::RpcError("not used".into()))
    }
}

/// Spin up the gateway against `provider`; return its address, a funded key
/// and the key store.
async fn gateway(provider: SocketAddr) -> (SocketAddr, String, Arc<ApiKeyStore>) {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let keys = Arc::new(ApiKeyStore::new());
    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused-mock".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        contracts: citrate_gateway::config::ContractAddresses::default(),
    };
    let app = build_router_with_auth(
        config,
        Arc::new(OneProvider {
            endpoint: provider.to_string(),
        }),
        Arc::new(NoChain),
        [0x11; 32],
        H160::from([0xfa; 20]),
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
    let key = create_key(
        &keys,
        "binding",
        U256::from(10 * PRICE),
        H160::from([0xde; 20]),
    )
    .await;
    (addr, key, keys)
}

async fn chat(gw: SocketAddr, key: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("http://{gw}/v1/chat/completions"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 8
        }))
        .send()
        .await
        .expect("send")
        .status()
}

async fn balance(keys: &ApiKeyStore, key: &str) -> U256 {
    keys.get(key).await.expect("key exists").balance_grains
}

#[tokio::test]
async fn unsigned_non_empty_result_is_served_while_signatures_are_optional() {
    let provider = spawn_provider(serde_json::json!({
        "output": "pong", "input_tokens": 1, "output_tokens": 1
    }))
    .await;
    let (gw, key, keys) = gateway(provider).await;
    assert_eq!(chat(gw, &key).await, 200);
    assert!(
        balance(&keys, &key).await < U256::from(10 * PRICE),
        "served call is charged"
    );
}

#[tokio::test]
async fn result_with_a_signature_that_does_not_verify_is_not_served() {
    // 65 bytes that are not a valid signature over this result.
    let bad_sig = format!("0x{}", "11".repeat(64) + "1b");
    let provider = spawn_provider(serde_json::json!({
        "output": "pong", "input_tokens": 1, "output_tokens": 1, "signature": bad_sig
    }))
    .await;
    let (gw, key, keys) = gateway(provider).await;
    let status = chat(gw, &key).await;
    assert_ne!(status, 200, "an unverified result must not be served");
    assert!(status.is_server_error(), "dispatch failure, got {status}");
    assert_eq!(
        balance(&keys, &key).await,
        U256::from(10 * PRICE),
        "a refused result is not charged"
    );
}

#[tokio::test]
async fn empty_result_is_not_served() {
    let provider = spawn_provider(serde_json::json!({
        "output": "", "input_tokens": 1, "output_tokens": 0
    }))
    .await;
    let (gw, key, keys) = gateway(provider).await;
    let status = chat(gw, &key).await;
    assert_ne!(status, 200, "an empty result must not be served");
    assert_eq!(balance(&keys, &key).await, U256::from(10 * PRICE));
}
