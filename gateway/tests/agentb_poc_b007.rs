//! IGW-B-007 tripwire: unknown model resolution must not repeatedly enumerate
//! the entire on-chain registry, and a batch must not fan that cost out across
//! an unbounded number of distinct attacker-controlled names.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::routing::post;
use axum::{Json, Router};
use ethereum_types::{H256, U256};
use serde_json::{json, Value};
use tokio::net::TcpListener;

use citrate_gateway::pricing::TokenBasedPricing;
use citrate_gateway::queries::{ChainQueries, HttpChainQueries, ProviderInfo};
use x402_axum::{PricingError, PricingStrategy};

fn encode_hash_array(hashes: &[H256]) -> String {
    let mut bytes = vec![0u8; 64 + hashes.len() * 32];
    U256::from(32u64).to_big_endian(&mut bytes[0..32]);
    U256::from(hashes.len()).to_big_endian(&mut bytes[32..64]);
    for (index, hash) in hashes.iter().enumerate() {
        let start = 64 + index * 32;
        bytes[start..start + 32].copy_from_slice(hash.as_bytes());
    }
    format!("0x{}", hex::encode(bytes))
}

async fn spawn_rpc(counter: Arc<AtomicUsize>) -> String {
    let hashes = [
        H256::from([0x11; 32]),
        H256::from([0x22; 32]),
        H256::from([0x33; 32]),
    ];
    let app = Router::new().route(
        "/",
        post(move |Json(body): Json<Value>| {
            let counter = counter.clone();
            async move {
                let data = body["params"][0]["data"].as_str().expect("eth_call data");
                counter.fetch_add(1, Ordering::SeqCst);
                let result = if data.len() == 10 {
                    encode_hash_array(&hashes)
                } else {
                    "0x".to_string()
                };
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"].clone(),
                    "result": result,
                }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("rpc bind");
    let addr = listener.local_addr().expect("rpc address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("rpc serve");
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn repeated_unknown_model_is_negative_cached() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rpc_url = spawn_rpc(calls.clone()).await;
    let queries = HttpChainQueries::new(
        rpc_url,
        citrate_gateway::config::ContractAddresses::default(),
    );

    let (first, second, third) = tokio::join!(
        queries.resolve_model_name("b007-never-registered-model"),
        queries.resolve_model_name("b007-never-registered-model"),
        queries.resolve_model_name("b007-never-registered-model"),
    );
    for result in [first, second, third] {
        let error = result.expect_err("unknown model must remain unknown");
        assert!(error.to_string().contains("b007-never-registered-model"));
    }

    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn unauthenticated_model_listing_is_cached() {
    let calls = Arc::new(AtomicUsize::new(0));
    let rpc_url = spawn_rpc(calls.clone()).await;
    let queries = HttpChainQueries::new(
        rpc_url,
        citrate_gateway::config::ContractAddresses::default(),
    );

    queries.list_models().await.expect("first model listing");
    queries.list_models().await.expect("cached model listing");

    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

struct CountingQueries {
    resolve_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl ChainQueries for CountingQueries {
    async fn resolve_model_name(&self, _name: &str) -> Result<H256, citrate_gateway::GatewayError> {
        self.resolve_calls.fetch_add(1, Ordering::SeqCst);
        Ok(H256::from([0xab; 32]))
    }

    async fn estimate_cost(
        &self,
        _model_hash: H256,
        _input_tokens: u32,
        _output_tokens: u32,
        _tier: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        Ok(U256::one())
    }

    async fn list_providers(
        &self,
        _model_hash: H256,
    ) -> Result<Vec<ProviderInfo>, citrate_gateway::GatewayError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn distinct_model_batch_resolution_is_bounded() {
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let pricing = TokenBasedPricing::new(
        Arc::new(CountingQueries {
            resolve_calls: resolve_calls.clone(),
        }),
        "default-model",
    );
    let requests: Vec<Value> = (0..1000)
        .map(|index| {
            json!({
                "model": format!("b007-attacker-model-{index}"),
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
            })
        })
        .collect();
    let request = http::Request::new(axum::body::Bytes::from(
        serde_json::to_vec(&json!({"requests": requests})).expect("batch json"),
    ));

    let result = pricing.price_for(&request).await;
    assert!(matches!(result, Err(PricingError::NotPriceable(_))));
    assert!(
        resolve_calls.load(Ordering::SeqCst) <= 32,
        "1000 distinct model names must not cause 1000 resolutions; got {}",
        resolve_calls.load(Ordering::SeqCst)
    );
}
