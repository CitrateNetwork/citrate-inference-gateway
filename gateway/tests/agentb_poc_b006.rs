//! IGW-B-006 tripwire: x402 pricing and authorization must bind to the
//! request being paid for.
//!
//! The parent implementation prices every request from a fixed default
//! model/256-in/512-out estimate and accepts the resulting payment on a
//! different request. The fixed contract must price the actual model/body and
//! reject reuse of a challenge on a different request.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Json as JsonExtractor;
use axum::routing::post;
use axum::Json as JsonResponse;
use ethereum_types::{H160, H256, U256};
use reqwest::StatusCode;
use serde_json::Value;
use tokio::net::TcpListener;

use citrate_gateway::queries::ChainQueries;
use citrate_gateway::{build_router_with, GatewayConfig, ProviderInfo, ProviderProtocolRequest};
use x402_axum::keys::{derive_secp256k1_address, sign_digest_secp256k1};
use x402_axum::{
    eip712_digest, encode_payment_header, transfer_with_authorization_struct_hash, ChainClient,
    RawLog, TxReceipt, X402Error,
};

const TEST_WSALT: &str = "0x61bc737f67b430fe2567630823694032a049253e";
const TEST_TREASURY: &str = "0x7e577e577e577e577e577e577e577e577e577e57";

fn payer_secret() -> [u8; 32] {
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
        0x11, 0x22,
    ]
}

fn operator_secret() -> [u8; 32] {
    [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
        0xff, 0x80,
    ]
}

fn parse_addr(value: &str) -> H160 {
    let bytes = hex::decode(value.trim_start_matches("0x")).expect("address hex");
    H160::from_slice(&bytes)
}

struct PricingQueries {
    provider_endpoint: String,
}

#[async_trait]
impl ChainQueries for PricingQueries {
    async fn resolve_model_name(&self, name: &str) -> Result<H256, citrate_gateway::GatewayError> {
        let tag = match name {
            "cheap-model" => 0x01,
            "expensive-model" => 0x02,
            _ => 0xff,
        };
        Ok(H256::from([tag; 32]))
    }

    async fn estimate_cost(
        &self,
        model_hash: H256,
        _input_tokens: u32,
        output_tokens: u32,
        _tier: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        let per_model = match model_hash.as_bytes()[0] {
            0x01 => 1_000u64,
            0x02 => 5_000u64,
            // Parent's fixed fallback quote must still cover the expensive
            // handler-side re-quote, so the request-binding half reaches the
            // old vulnerable success path rather than an underfunded branch.
            _ => 10_000u64,
        };
        Ok(U256::from(per_model) + U256::from(output_tokens))
    }

    async fn list_providers(
        &self,
        _model_hash: H256,
    ) -> Result<Vec<ProviderInfo>, citrate_gateway::GatewayError> {
        Ok(vec![ProviderInfo {
            address: H160::from([0xb1; 20]),
            endpoint: format!("http://{}/infer", self.provider_endpoint),
            reputation_bps: 9_500,
            current_load: 0,
            max_concurrent: 10,
        }])
    }
}

struct HonestMockChain {
    facilitator: H160,
    settled: Mutex<HashSet<H256>>,
}

#[async_trait]
impl ChainClient for HonestMockChain {
    async fn verify_offline(&self, input: &[u8]) -> Result<Option<H160>, X402Error> {
        if input.len() != 265 {
            return Ok(None);
        }
        Ok(Some(H160::from_slice(&input[32..32 + 20])))
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
        if !self.settled.lock().expect("settled mutex").insert(nonce) {
            return Ok(TxReceipt {
                status: false,
                block_number: 2,
                logs: vec![],
            });
        }
        let from = H160::from([0xa1; 20]);
        let to = H160::from([0xa2; 20]);
        let mut from_word = [0u8; 32];
        from_word[12..].copy_from_slice(from.as_bytes());
        let mut to_word = [0u8; 32];
        to_word[12..].copy_from_slice(to.as_bytes());
        let mut data = vec![0u8; 96];
        U256::from(9_995u64).to_big_endian(&mut data[0..32]);
        U256::from(5u64).to_big_endian(&mut data[32..64]);
        data[64..].copy_from_slice(nonce.as_bytes());
        Ok(TxReceipt {
            status: true,
            block_number: 100,
            logs: vec![RawLog {
                address: self.facilitator,
                topics: vec![
                    x402_axum::payment_settled_topic(),
                    H256::from(from_word),
                    H256::from(to_word),
                ],
                data,
            }],
        })
    }
}

async fn spawn_provider() -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(
            |JsonExtractor(_req): JsonExtractor<ProviderProtocolRequest>| async {
                JsonResponse(serde_json::json!({
                    "output": "served",
                    "input_tokens": 1,
                    "output_tokens": 1
                }))
            },
        ),
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("provider bind");
    let addr = listener.local_addr().expect("provider address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("provider serve");
    });
    addr
}

async fn spawn_gateway(provider: SocketAddr) -> SocketAddr {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(PricingQueries {
        provider_endpoint: provider.to_string(),
    });
    let chain = Arc::new(HonestMockChain {
        facilitator,
        settled: Mutex::new(HashSet::new()),
    });
    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused-mock".into(),
        listen_addr: "127.0.0.1:0".into(),
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
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gateway bind");
    let addr = listener.local_addr().expect("gateway address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gateway serve");
    });
    addr
}

async fn challenge_for(client: &reqwest::Client, url: &str, body: &str) -> Value {
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send()
        .await
        .expect("challenge request");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    response.json().await.expect("challenge json")
}

fn payment_header(challenge: &Value, secret: &[u8; 32]) -> String {
    let payer = derive_secp256k1_address(secret).expect("payer address");
    let recipient = parse_addr(challenge["x402"]["recipient"].as_str().expect("recipient"));
    let wsalt = parse_addr(TEST_WSALT);
    let amount = U256::from_dec_str(challenge["x402"]["amount"].as_str().expect("amount"))
        .expect("amount wei");
    let valid_after = U256::from(
        challenge["x402"]["valid_after"]
            .as_u64()
            .expect("valid_after"),
    );
    let valid_before = U256::from(
        challenge["x402"]["valid_before"]
            .as_u64()
            .expect("valid_before"),
    );
    let nonce_bytes = hex::decode(
        challenge["x402"]["nonce"]
            .as_str()
            .expect("nonce")
            .trim_start_matches("0x"),
    )
    .expect("nonce hex");
    let nonce = H256::from_slice(&nonce_bytes);
    let domain = x402_axum::wsalt_domain_separator(40204, wsalt);
    let struct_hash = transfer_with_authorization_struct_hash(
        payer,
        recipient,
        amount,
        valid_after,
        valid_before,
        nonce,
    );
    let digest = eip712_digest(domain, struct_hash);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(digest.as_bytes());
    let (v, r, s) = sign_digest_secp256k1(secret, &digest_bytes).expect("signature");
    encode_payment_header(&x402_axum::PaymentPayload {
        from: payer,
        to: recipient,
        value: amount,
        valid_after,
        valid_before,
        nonce,
        v,
        r: H256::from(r),
        s: H256::from(s),
    })
}

#[tokio::test]
async fn challenge_amount_tracks_actual_model_and_budget() {
    let provider = spawn_provider().await;
    let gateway = spawn_gateway(provider).await;
    let url = format!("http://{gateway}/v1/chat/completions");
    let client = reqwest::Client::new();
    let cheap = challenge_for(
        &client,
        &url,
        r#"{"model":"cheap-model","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#,
    )
    .await;
    let expensive = challenge_for(
        &client,
        &url,
        r#"{"model":"expensive-model","messages":[{"role":"user","content":"hi"}],"max_tokens":4096}"#,
    )
    .await;
    let cheap_amount = U256::from_dec_str(cheap["x402"]["amount"].as_str().expect("cheap amount"))
        .expect("cheap wei");
    let expensive_amount = U256::from_dec_str(
        expensive["x402"]["amount"]
            .as_str()
            .expect("expensive amount"),
    )
    .expect("expensive wei");
    assert!(
        expensive_amount > cheap_amount,
        "expensive request must not receive the fixed cheap quote: cheap={cheap_amount}, expensive={expensive_amount}"
    );
}

#[tokio::test]
async fn payment_is_rejected_when_replayed_on_a_different_request() {
    let provider = spawn_provider().await;
    let gateway = spawn_gateway(provider).await;
    let url = format!("http://{gateway}/v1/chat/completions");
    let client = reqwest::Client::new();
    let cheap_body =
        r#"{"model":"cheap-model","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#;
    let expensive_body = r#"{"model":"expensive-model","messages":[{"role":"user","content":"hi"}],"max_tokens":4096}"#;
    let challenge = challenge_for(&client, &url, cheap_body).await;
    let header = payment_header(&challenge, &payer_secret());

    let response = client
        .post(&url)
        .header("content-type", "application/json")
        .header("x-payment", header)
        .body(expensive_body)
        .send()
        .await
        .expect("replay request");
    assert_eq!(
        response.status(),
        StatusCode::PAYMENT_REQUIRED,
        "a payment minted for the cheap request must not authorize the expensive request"
    );
}
