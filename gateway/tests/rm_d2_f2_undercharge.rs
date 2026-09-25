//! RM-D2 / WP-D2.4 (audit F-2) acceptance test.
//!
//! Asserts the gateway rejects a chat completion when the caller's
//! signed amount falls short of the actual cost computed against
//! their declared `max_tokens`. Pre-fix the gateway priced at the
//! pricing strategy's assumed default (512 output tokens) and a
//! caller could request `max_tokens = 65535` for the same fee.
//!
//! Construction:
//!   - MockChainQueries returns a cost that scales linearly with
//!     `output_tokens` so the fixed-amount payer can underfund.
//!   - HonestMockChain settles the X402 payment for a small fixed
//!     value (1 wei).
//!   - Send a chat with `max_tokens = 65535` → expect 402 Underfunded.
//!   - Send a chat with `max_tokens = 1` → expect 200 (paid amount
//!     covers the actual cost).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ethereum_types::{H160, H256, U256};
use serde_json::Value;
use tokio::net::TcpListener;
use x402_axum::keys::{derive_secp256k1_address, sign_digest_secp256k1};
use x402_axum::{
    eip712_digest, encode_payment_header, payment_settled_topic,
    transfer_with_authorization_struct_hash, ChainClient, RawLog, TxReceipt, X402Client, X402Error,
    X_PAYMENT_HEADER,
};

use citrate_gateway::config::GatewayConfig;
use citrate_gateway::queries::{ChainQueries, ProviderInfo};

/// 2026-05-31 audit -007 (SECREM-02 6.4a): explicit money-path
/// addresses (the placeholder default was removed from the builders).
const TEST_WSALT: &str = "0x61bc737f67b430fe2567630823694032a049253e";
const TEST_TREASURY: &str = "0x7e577e577e577e577e577e577e577e577e577e57";

mod common {
    pub use citrate_gateway::build_router_with;
}

// ── Mocks ────────────────────────────────────────────────────────

struct LinearCostQueries {
    provider_endpoint: String,
}

#[async_trait]
impl ChainQueries for LinearCostQueries {
    async fn resolve_model_name(&self, _name: &str) -> Result<H256, citrate_gateway::GatewayError> {
        Ok(H256::from([0xab; 32]))
    }

    /// Cost = `output_tokens` wei. Lets us craft an exact undercharge.
    async fn estimate_cost(
        &self,
        _model_hash: H256,
        _input_tokens: u32,
        output_tokens: u32,
        _tier: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        Ok(U256::from(output_tokens as u64))
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

struct FixedAmountChain {
    facilitator: H160,
    settled: Mutex<HashSet<H256>>,
    /// Amount settled per call (gross = value + fee in the event).
    /// Increment nonce each call so multi-call tests don't collide.
    next_nonce: Mutex<u8>,
    value_wei: u128,
    fee_wei: u128,
}

impl FixedAmountChain {
    fn new(facilitator: H160, value_wei: u128, fee_wei: u128) -> Self {
        Self {
            facilitator,
            settled: Mutex::new(HashSet::new()),
            next_nonce: Mutex::new(0x40),
            value_wei,
            fee_wei,
        }
    }
}

#[async_trait]
impl ChainClient for FixedAmountChain {
    async fn verify_offline(&self, precompile_input: &[u8]) -> Result<Option<H160>, X402Error> {
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
        Ok(H256::from([0xcd; 32]))
    }

    async fn wait_for_receipt(
        &self,
        _tx_hash: H256,
        _timeout: Duration,
    ) -> Result<TxReceipt, X402Error> {
        let nonce_byte = {
            let mut g = self.next_nonce.lock().expect("nonce mutex");
            let v = *g;
            *g = g.wrapping_add(1);
            v
        };
        let mut nonce_bytes = [0u8; 32];
        nonce_bytes.fill(nonce_byte);
        let nonce = H256::from(nonce_bytes);
        let mut settled = self.settled.lock().expect("settled mutex");
        settled.insert(nonce);
        drop(settled);

        let from = H160::from([0xa1; 20]);
        let to = H160::from([0xa2; 20]);
        let value = U256::from(self.value_wei);
        let fee = U256::from(self.fee_wei);
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
                    payment_settled_topic(),
                    H256::from(padded_from),
                    H256::from(padded_to),
                ],
                data,
            }],
        })
    }
}

// ── Stub provider ────────────────────────────────────────────────

async fn spawn_stub_provider() -> SocketAddr {
    use axum::routing::post;
    use axum::{Json, Router};

    async fn infer_handler(Json(_body): Json<Value>) -> Json<Value> {
        Json(serde_json::json!({
            "output": "pong",
            "input_tokens": 1,
            "output_tokens": 1
        }))
    }

    let app = Router::new().route("/infer", post(infer_handler));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind provider");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("provider serve");
    });
    addr
}

// ── Gateway harness ──────────────────────────────────────────────

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

async fn spawn_gateway(provider_addr: SocketAddr, value_wei: u128, fee_wei: u128) -> SocketAddr {
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(LinearCostQueries {
        provider_endpoint: provider_addr.to_string(),
    });
    let chain = Arc::new(FixedAmountChain::new(facilitator, value_wei, fee_wei));

    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused-mock".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        contracts: citrate_gateway::config::ContractAddresses::default(),
    };

    let app = common::build_router_with(
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

// ── Tests ────────────────────────────────────────────────────────

fn parse_addr(value: &str) -> H160 {
    let bytes = hex::decode(value.trim_start_matches("0x")).expect("address hex");
    H160::from_slice(&bytes)
}

/// Sign a valid challenge while intentionally lowering the authorized
/// amount. This keeps the F-2 handler/settlement gate test meaningful after
/// IGW-B-006 made the initial challenge quote request-aware.
fn payment_header_for_amount(challenge: &Value, secret: &[u8; 32], amount: U256) -> String {
    let payer = derive_secp256k1_address(secret).expect("payer address");
    let recipient = parse_addr(challenge["x402"]["recipient"].as_str().expect("recipient"));
    let wsalt = parse_addr(TEST_WSALT);
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

/// F-2: declaring a large max_tokens budget while authorizing only a tiny
/// amount must be rejected with 402.
#[tokio::test]
async fn test_f2_undercharge_rejected_402() {
    let provider_addr = spawn_stub_provider().await;
    // The request-aware B-006 quote is intentionally obtained first. Then
    // sign the same challenge for only 100 wei, below its quoted cost.
    let gateway_addr = spawn_gateway(provider_addr, 95, 5).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/v1/chat/completions", gateway_addr);
    let body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{ "role": "user", "content": "ping" }],
        "max_tokens": 65535
    });
    let http = reqwest::Client::new();
    let challenge_response = http
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("challenge request");
    assert_eq!(
        challenge_response.status(),
        reqwest::StatusCode::PAYMENT_REQUIRED
    );
    let challenge: Value = challenge_response.json().await.expect("challenge json");
    let header = payment_header_for_amount(&challenge, &payer_secret(), U256::from(100u64));
    let resp = http
        .post(&url)
        .header(X_PAYMENT_HEADER, header)
        .json(&body)
        .send()
        .await
        .expect("underfunded retry");

    assert_eq!(
        resp.status().as_u16(),
        402,
        "F-2: underfunded request must be rejected"
    );
    let text = resp.text().await.unwrap_or_default();
    assert!(
        text.to_lowercase().contains("below price") || text.to_lowercase().contains("payment"),
        "F-2 body should mention the payment shortfall: {}",
        text
    );
}

/// F-2 happy path: when the paid amount covers actual cost, request
/// goes through.
#[tokio::test]
async fn test_f2_sufficient_payment_accepted() {
    let provider_addr = spawn_stub_provider().await;
    // Settle gross = 1000 wei. max_tokens = 1 → cost = 1 wei. 1000 ≥ 1.
    let gateway_addr = spawn_gateway(provider_addr, 995, 5).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    let url = format!("http://{}/v1/chat/completions", gateway_addr);
    let body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{ "role": "user", "content": "ping" }],
        "max_tokens": 1
    });
    let req = reqwest::Client::new().post(&url).json(&body);
    let resp = client.send_paid(req).await.expect("auto-pay flow");
    assert_eq!(resp.status().as_u16(), 200, "sufficient payment must pass");
}
