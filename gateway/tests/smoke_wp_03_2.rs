//! WP-03.2 smoke test — sync chat completions, written FIRST.
//!
//! Per CM-02 RETRO action item #1: integration test before
//! implementation. This test defines the shape WP-03.2 must
//! satisfy — only THEN do we build the handler, pricing, dispatcher.
//!
//! Flow:
//!   1. Spin up a stub provider on a random port that echoes the
//!      prompt back as a canned chat completion.
//!   2. Build the gateway with:
//!      - MockChainQueries returning a fixed model + provider list
//!        pointing at the stub provider's URL
//!      - MockChain (from x402-axum) trusting any signature
//!      - X402Layer wrapping /v1/chat/completions
//!   3. Build an X402Client with a test secret.
//!   4. POST a chat request through reqwest. Client auto-pays
//!      the 402, retries with X-PAYMENT, gateway settles, dispatches
//!      to stub provider, translates response to OpenAI shape,
//!      returns 200.
//!   5. Assert OpenAI-shape response with the echoed prompt.

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

use citrate_gateway::{build_router_with, GatewayConfig, ProviderInfo, ProviderProtocolRequest};
use citrate_gateway::queries::ChainQueries;
use x402_axum::{ChainClient, RawLog, TxReceipt, X402Client, X402Error};

// ── Stub provider ────────────────────────────────────────────────

async fn spawn_stub_provider() -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(|JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| async move {
            // Echo the prompt back as a canned completion.
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
    async fn resolve_model_name(&self, _name: &str) -> Result<H256, citrate_gateway::GatewayError> {
        Ok(H256::from([0xab; 32]))
    }

    async fn estimate_cost(
        &self,
        _model_hash: H256,
        _input_tokens: u32,
        _output_tokens: u32,
        _tier: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        // Fixed price: 1 SALT
        Ok(U256::from(1_000_000_000_000_000_000u128))
    }

    async fn list_providers(
        &self,
        _model_hash: H256,
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

// ── Mock chain client (from x402-axum integration tests) ────────

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

    async fn get_nonce(&self, _address: H160) -> Result<u64, X402Error> {
        Ok(0)
    }

    async fn send_raw_tx(&self, _raw_tx: &[u8]) -> Result<H256, X402Error> {
        Ok(H256::from([0xab; 32]))
    }

    async fn wait_for_receipt(
        &self,
        _tx_hash: H256,
        _timeout: Duration,
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

async fn spawn_gateway(provider_addr: SocketAddr) -> SocketAddr {
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(MockChainQueries {
        provider_endpoint: provider_addr.to_string(),
    });
    let chain = Arc::new(HonestMockChain::new(facilitator));

    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused-mock".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
    };

    let app = build_router_with(config, queries, chain, operator_secret(), facilitator).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gw");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gw serve");
    });
    addr
}

// ── Tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn sync_chat_happy_path_via_x402_client() {
    let provider_addr = spawn_stub_provider().await;
    let gateway_addr = spawn_gateway(provider_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await; // listeners up

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    let url = format!("http://{}/v1/chat/completions", gateway_addr);
    let body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [
            { "role": "user", "content": "ping" }
        ],
        "max_tokens": 10
    });
    let req = reqwest::Client::new().post(&url).json(&body);
    let resp = client.send_paid(req).await.expect("auto-pay flow");
    assert_eq!(resp.status(), 200, "gateway should return 200 after settle");

    let body: Value = resp.json().await.expect("json");
    // OpenAI-shape response: object="chat.completion", choices array.
    assert_eq!(body["object"].as_str(), Some("chat.completion"));
    let choices = body["choices"].as_array().expect("choices");
    assert!(!choices.is_empty(), "should have ≥ 1 choice");
    let content = choices[0]["message"]["content"]
        .as_str()
        .expect("content");
    assert!(
        content.contains("STUB-RESPONSE"),
        "stub provider's response should propagate; got: {}",
        content
    );
    assert!(
        body["usage"].is_object(),
        "usage block required by OpenAI shape"
    );
}

#[tokio::test]
async fn unpaid_chat_request_gets_402_with_challenge() {
    let provider_addr = spawn_stub_provider().await;
    let gateway_addr = spawn_gateway(provider_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/v1/chat/completions", gateway_addr);
    let body = serde_json::json!({"model": "llama-3.1-8b", "messages": []});
    // Plain POST without X402Client — should get 402.
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 402);
    let body: Value = resp.json().await.expect("json");
    assert!(body.get("x402").is_some(), "must include x402 envelope");
}
