//! Per-model budgets at the chat entry point (`POST /v1/chat/completions`
//! behind the API-key layer). The keystore-level budget arithmetic has its
//! own tests (`infer_wpe_model_budgets.rs`); these pin what the HANDLER does
//! with it: an exhausted model budget refuses the request before any provider
//! is called, a served request debits exactly the quoted cost, and a request
//! that fails downstream gives the per-model debit back.
//!
//! Everything is in-process: a stub provider on loopback, mocked chain
//! queries and a mocked chain client. No network, no host state.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
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

use citrate_gateway::auth::{create_key, ApiKeyStore};
use citrate_gateway::queries::ChainQueries;
use citrate_gateway::{
    build_router_with_auth, GatewayConfig, ProviderInfo, ProviderProtocolRequest,
};
use x402_axum::{ChainClient, RawLog, TxReceipt, X402Error};

const TEST_WSALT: &str = "0x61bc737f67b430fe2567630823694032a049253e";
const TEST_TREASURY: &str = "0x7e577e577e577e577e577e577e577e577e577e57";
const MODEL: &str = "llama-3.1-8b";
/// `MockChainQueries::estimate_cost` prices a request at its output-token
/// budget, so `max_tokens: 10` costs exactly 10 grains.
const MAX_TOKENS: u32 = 10;

/// Stub provider. `ok == false` answers 500 (a dispatch failure). Counts calls.
async fn spawn_provider(ok: bool, calls: Arc<AtomicUsize>) -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(
            move |JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if ok {
                        (
                            StatusCode::OK,
                            JsonResp(serde_json::json!({
                                "output": format!("STUB-RESPONSE: {}", req.prompt),
                                "input_tokens": 1,
                                "output_tokens": 4,
                            })),
                        )
                    } else {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            JsonResp(serde_json::json!({"error": "stub-fail"})),
                        )
                    }
                }
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
    async fn resolve_model_name(&self, _n: &str) -> Result<H256, citrate_gateway::GatewayError> {
        Ok(H256::from([0xab; 32]))
    }
    async fn estimate_cost(
        &self,
        _: H256,
        _: u32,
        output_tokens: u32,
        _: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        Ok(U256::from(output_tokens as u64))
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
    async fn wait_for_receipt(&self, _h: H256, _t: Duration) -> Result<TxReceipt, X402Error> {
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

fn operator_secret() -> [u8; 32] {
    [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
        0xff, 0x80,
    ]
}

async fn spawn_gateway(provider_addr: SocketAddr) -> (SocketAddr, Arc<ApiKeyStore>) {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
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

fn salt(n: u64) -> U256 {
    U256::from(n) * U256::from(1_000_000_000_000_000_000u128)
}

async fn chat(gateway: SocketAddr, key_id: &str) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("http://{gateway}/v1/chat/completions"))
        .bearer_auth(key_id)
        .json(&serde_json::json!({
            "model": MODEL,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": MAX_TOKENS,
        }))
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

async fn model_budget(keys: &ApiKeyStore, key_id: &str) -> Option<U256> {
    keys.get_model_budgets(key_id)
        .await
        .into_iter()
        .find(|(m, _)| m == MODEL)
        .map(|(_, b)| b)
}

#[tokio::test]
async fn an_exhausted_model_budget_refuses_before_any_provider_is_called() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = spawn_provider(true, calls.clone()).await;
    let (gateway, keys) = spawn_gateway(provider).await;

    // Plenty of overall balance; the model's own budget is below the cost.
    let initial = salt(10);
    let key_id = create_key(&keys, "pilot", initial, H160::from([0xde; 20])).await;
    keys.set_model_budget(&key_id, MODEL, U256::from(MAX_TOKENS as u64 - 1))
        .await
        .expect("set budget");

    let (status, body) = chat(gateway, &key_id).await;
    assert_eq!(
        status, 402,
        "an exhausted per-model budget must refuse: {body}"
    );
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("model budget"),
        "the refusal must name the per-model budget, got: {body}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no provider may be dispatched once the model budget refuses"
    );
    assert_eq!(
        model_budget(&keys, &key_id).await,
        Some(U256::from(MAX_TOKENS as u64 - 1)),
        "a refused request must not touch the model budget"
    );
    let record = keys.get(&key_id).await.expect("key");
    assert_eq!(
        record.balance_grains, initial,
        "a refused request must leave the overall balance whole"
    );
}

#[tokio::test]
async fn a_served_request_debits_the_model_budget_by_the_quoted_cost() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = spawn_provider(true, calls.clone()).await;
    let (gateway, keys) = spawn_gateway(provider).await;

    let key_id = create_key(&keys, "pilot", salt(10), H160::from([0xde; 20])).await;
    keys.set_model_budget(&key_id, MODEL, U256::from(25u64))
        .await
        .expect("set budget");

    let (status, body) = chat(gateway, &key_id).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        model_budget(&keys, &key_id).await,
        Some(U256::from(25u64 - MAX_TOKENS as u64)),
        "the model budget must drop by exactly the quoted cost"
    );

    // Spend down to below one request's cost: the next one is refused.
    let (status, _) = chat(gateway, &key_id).await;
    assert_eq!(status, 200);
    let (status, body) = chat(gateway, &key_id).await;
    assert_eq!(status, 402, "the third request exceeds the budget: {body}");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(model_budget(&keys, &key_id).await, Some(U256::from(5u64)));
}

#[tokio::test]
async fn a_request_that_fails_downstream_gives_the_model_debit_back() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = spawn_provider(false, calls.clone()).await;
    let (gateway, keys) = spawn_gateway(provider).await;

    let key_id = create_key(&keys, "pilot", salt(10), H160::from([0xde; 20])).await;
    keys.set_model_budget(&key_id, MODEL, U256::from(25u64))
        .await
        .expect("set budget");

    let (status, body) = chat(gateway, &key_id).await;
    assert!(
        status >= 500,
        "a failing provider must not be a success: {status} {body}"
    );
    assert!(calls.load(Ordering::SeqCst) >= 1, "the provider was tried");
    assert_eq!(
        model_budget(&keys, &key_id).await,
        Some(U256::from(25u64)),
        "a failed request must refund its per-model debit"
    );
}
