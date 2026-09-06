//! WP-03.3 smoke test — async batch endpoint, written FIRST.
//!
//! Per CM-02 RETRO action item #1. Defines the shape of the
//! /v1/batch endpoint and the in-memory state machine before
//! implementation.
//!
//! Slice scope (this file):
//!   - POST /v1/batch (inline {requests: [...]} form, ≤1000)
//!   - GET  /v1/batch/{id} (status polling)
//!   - GET  /v1/batch/{id}/output (JSONL when terminal)
//!   - In-memory store, no RocksDB yet
//!   - Provider dispatch via the same path as /v1/chat/completions
//!   - On-chain `postJob` posting deferred to slice 2
//!
//! State machine mirrors GatewayBatchLifecycle.tla:
//!   batch:   Submitted → Running → {Completed | PartialFailure | Failed}
//!   request: Pending   → Dispatched → {Done | Errored}

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

use citrate_gateway::queries::ChainQueries;
use citrate_gateway::{build_router_with, GatewayConfig, ProviderInfo, ProviderProtocolRequest};
use x402_axum::{ChainClient, RawLog, TxReceipt, X402Client, X402Error};

/// 2026-05-31 audit -007 (SECREM-02 6.4a): explicit money-path
/// addresses (the placeholder default was removed from the builders).
const TEST_WSALT: &str = "0x61bc737f67b430fe2567630823694032a049253e";
const TEST_TREASURY: &str = "0x7e577e577e577e577e577e577e577e577e577e57";


// ── Stub provider with selective failure ────────────────────────

/// Counts requests; for indices in `fail_indices` returns 500.
async fn spawn_stub_provider(fail_indices: HashSet<usize>) -> SocketAddr {
    let counter = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(fail_indices);
    let app = axum::Router::new().route(
        "/infer",
        post({
            let counter = counter.clone();
            let fail = fail.clone();
            move |JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| {
                let counter = counter.clone();
                let fail = fail.clone();
                async move {
                    let idx = counter.fetch_add(1, Ordering::SeqCst);
                    if fail.contains(&idx) {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            JsonResp(serde_json::json!({"error": "stub-fail"})),
                        );
                    }
                    let prompt = req.prompt.clone();
                    (
                        StatusCode::OK,
                        JsonResp(serde_json::json!({
                            "output": format!("STUB-RESPONSE: {}", prompt),
                            "input_tokens": prompt.split_whitespace().count(),
                            "output_tokens": 4,
                        })),
                    )
                }
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stub serve");
    });
    addr
}

/// Spawn a provider that records the output-token budget it receives.
async fn spawn_recording_provider(observed: Arc<Mutex<Vec<u32>>>) -> SocketAddr {
    let app = axum::Router::new().route(
        "/infer",
        post(
            move |JsonExtractor(req): JsonExtractor<ProviderProtocolRequest>| {
                let observed = observed.clone();
                async move {
                    observed
                        .lock()
                        .expect("observed mutex")
                        .push(req.max_tokens);
                    JsonResp(serde_json::json!({
                        "output": "recorded",
                        "input_tokens": 1,
                        "output_tokens": 1,
                    }))
                }
            },
        ),
    );
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recorder");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("recorder serve");
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
        input_tokens: u32,
        output_tokens: u32,
        _tier: u8,
    ) -> Result<U256, citrate_gateway::GatewayError> {
        if input_tokens == citrate_gateway::pricing::ASSUMED_INPUT_TOKENS && output_tokens == 512 {
            return Ok(U256::from(5_000u64));
        }
        let assumed = citrate_gateway::pricing::ASSUMED_INPUT_TOKENS;
        let input_units = ((input_tokens.saturating_add(assumed - 1)) / assumed).max(1);
        Ok(U256::from(input_units as u64 * 1_000))
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

// ── Mock chain client ───────────────────────────────────────────

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
        let value = U256::from(4_995u64);
        let fee = U256::from(5u64);
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
    std::env::set_var("CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS", "1");
    let facilitator = H160::from([0xfa; 20]);
    let queries = Arc::new(MockChainQueries {
        provider_endpoint: provider_addr.to_string(),
    });
    let chain = Arc::new(HonestMockChain::new(facilitator));
    let config = GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://unused-mock".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
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
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gw");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("gw serve");
    });
    addr
}

/// Submit a concrete batch body. Auto-pays via X402Client.
async fn submit_batch_requests(gateway: SocketAddr, requests: Vec<Value>) -> reqwest::Response {
    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).expect("hex"));
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    let url = format!("http://{}/v1/batch", gateway);
    let body = serde_json::json!({"requests": requests});
    let req = reqwest::Client::new().post(&url).json(&body);
    client.send_paid(req).await.expect("submit")
}

/// Submit a batch of `n` chat-completion requests and return
/// `(batch_id, read_token)`. Auto-pays via X402Client. The read token
/// (2026-05-31 audit -004) is required on every subsequent read.
async fn submit_batch(gateway: SocketAddr, n: usize) -> (String, String) {
    let requests: Vec<Value> = (0..n)
        .map(|i| {
            serde_json::json!({
                "model": "llama-3.1-8b",
                "messages": [{"role": "user", "content": format!("ping-{}", i)}],
                "max_tokens": 10
            })
        })
        .collect();

    let resp = submit_batch_requests(gateway, requests).await;
    assert_eq!(resp.status(), 200, "expected 200 from /v1/batch");
    let body: Value = resp.json().await.expect("json");
    (
        body["batch_id"].as_str().expect("batch_id").to_string(),
        body["read_token"]
            .as_str()
            .expect("read_token (audit -004)")
            .to_string(),
    )
}

#[tokio::test]
async fn batch_underfunded_request_count_rejected_402() {
    let provider = spawn_stub_provider(HashSet::new()).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let requests: Vec<Value> = (0..6)
        .map(|i| {
            serde_json::json!({
                "model": "llama-3.1-8b",
                "messages": [{"role": "user", "content": format!("ping-{}", i)}],
                "max_tokens": 10
            })
        })
        .collect();
    let resp = submit_batch_requests(gateway, requests).await;
    assert_eq!(resp.status(), 402);
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("underfunded"), "got: {}", msg);
}

#[tokio::test]
async fn batch_underfunded_long_prompt_rejected_402() {
    let provider = spawn_stub_provider(HashSet::new()).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let requests = vec![serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role": "user", "content": "A".repeat(32 * 1024)}],
        "max_tokens": 10
    })];
    let resp = submit_batch_requests(gateway, requests).await;
    assert_eq!(resp.status(), 402);
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("underfunded"), "got: {}", msg);
}

/// Poll until terminal state or timeout. Presents the submit-time read
/// token (audit -004).
async fn wait_terminal(
    gateway: SocketAddr,
    batch_id: &str,
    read_token: &str,
    timeout: Duration,
) -> Value {
    let deadline = std::time::Instant::now() + timeout;
    let url = format!("http://{}/v1/batch/{}", gateway, batch_id);
    let http = reqwest::Client::new();
    loop {
        let resp = http
            .get(&url)
            .bearer_auth(read_token)
            .send()
            .await
            .expect("poll");
        assert_eq!(resp.status(), 200);
        let body: Value = resp.json().await.expect("json");
        let status = body["status"].as_str().unwrap_or("");
        if matches!(status, "completed" | "partial_failure" | "failed") {
            return body;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "batch did not reach terminal in {:?}; last={}",
                timeout, body
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn batch_happy_path_5_requests_completes() {
    let provider = spawn_stub_provider(HashSet::new()).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (batch_id, token) = submit_batch(gateway, 5).await;
    let terminal = wait_terminal(gateway, &batch_id, &token, Duration::from_secs(10)).await;
    assert_eq!(terminal["status"].as_str(), Some("completed"));
    assert_eq!(terminal["completed_count"].as_u64(), Some(5));
    assert_eq!(terminal["errored_count"].as_u64(), Some(0));
    assert_eq!(terminal["request_count"].as_u64(), Some(5));
    assert_eq!(terminal["object"].as_str(), Some("batch"));
}

#[tokio::test]
async fn batch_partial_failure_one_errors() {
    let mut fails = HashSet::new();
    fails.insert(1);
    let provider = spawn_stub_provider(fails).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (batch_id, token) = submit_batch(gateway, 3).await;
    let terminal = wait_terminal(gateway, &batch_id, &token, Duration::from_secs(10)).await;
    assert_eq!(terminal["status"].as_str(), Some("partial_failure"));
    assert_eq!(terminal["completed_count"].as_u64(), Some(2));
    assert_eq!(terminal["errored_count"].as_u64(), Some(1));

    // Escrow invariant: paid = released + refunded.
    let paid = terminal["paid_escrow_grains"].as_str().expect("paid");
    let released = terminal["released_grains"].as_str().expect("released");
    let refunded = terminal["refunded_grains"].as_str().expect("refunded");
    let paid = U256::from_dec_str(paid).expect("paid u256");
    let released = U256::from_dec_str(released).expect("released u256");
    let refunded = U256::from_dec_str(refunded).expect("refunded u256");
    assert_eq!(paid, released + refunded, "EscrowBalances + Settled");
    assert!(refunded > U256::zero(), "refunds nonzero with 1 error");
}

#[tokio::test]
async fn batch_all_fail_returns_failed() {
    let fails: HashSet<usize> = (0..2).collect();
    let provider = spawn_stub_provider(fails).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (batch_id, token) = submit_batch(gateway, 2).await;
    let terminal = wait_terminal(gateway, &batch_id, &token, Duration::from_secs(10)).await;
    assert_eq!(terminal["status"].as_str(), Some("failed"));
    assert_eq!(terminal["completed_count"].as_u64(), Some(0));
    assert_eq!(terminal["errored_count"].as_u64(), Some(2));
}

#[tokio::test]
async fn batch_output_returns_jsonl() {
    let provider = spawn_stub_provider(HashSet::new()).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (batch_id, token) = submit_batch(gateway, 2).await;
    let _ = wait_terminal(gateway, &batch_id, &token, Duration::from_secs(10)).await;

    let url = format!("http://{}/v1/batch/{}/output", gateway, batch_id);
    let resp = reqwest::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .expect("output");
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("application/x-ndjson"), "got {}", ct);
    let body = resp.text().await.expect("text");
    let lines: Vec<&str> = body.trim_end().lines().collect();
    assert_eq!(lines.len(), 2);
    for (i, line) in lines.iter().enumerate() {
        let v: Value = serde_json::from_str(line).expect("ndjson line");
        assert_eq!(v["request_index"].as_u64(), Some(i as u64));
        assert_eq!(v["status"].as_str(), Some("completed"));
        assert!(v["response"].is_object(), "completed line has response");
    }
}

/// 2026-05-31 audit -004 (SECREM-02 6.4a): batch reads must be bound to
/// the submitter. Pre-fix, `GET /v1/batch/{id}` and `/output` were fully
/// unauthenticated — anyone who learned (or guessed) a batch id could read
/// another tenant's prompts and outputs. Post-fix an x402-paid submit
/// returns a one-time `read_token`; reads presenting no/wrong credentials
/// get 404 (same body as an unknown id — no existence oracle).
#[tokio::test]
async fn batch_reads_require_submit_time_credentials() {
    let provider = spawn_stub_provider(HashSet::new()).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let requests = vec![serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role": "user", "content": "secret-tenant-prompt"}],
        "max_tokens": 10
    })];
    let resp = submit_batch_requests(gateway, requests).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.expect("json");
    let batch_id = body["batch_id"].as_str().expect("batch_id").to_string();
    let read_token = body["read_token"]
        .as_str()
        .expect("audit -004: x402-paid submit must return a read_token")
        .to_string();

    let status_url = format!("http://{}/v1/batch/{}", gateway, batch_id);
    let output_url = format!("http://{}/v1/batch/{}/output", gateway, batch_id);
    let http = reqwest::Client::new();

    // No credentials → 404 on both reads.
    let resp = reqwest::get(&status_url).await.expect("get");
    assert_eq!(resp.status(), 404, "unauthenticated status read must 404");
    let resp = reqwest::get(&output_url).await.expect("get");
    assert_eq!(resp.status(), 404, "unauthenticated output read must 404");

    // Wrong token → 404 (no existence oracle).
    let resp = http
        .get(&status_url)
        .bearer_auth("brt_definitely-not-the-token")
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 404, "wrong-token read must 404");

    // Correct token → 200.
    let resp = http
        .get(&status_url)
        .bearer_auth(&read_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200, "payer's token must read its own batch");
    let resp = http
        .get(&output_url)
        .bearer_auth(&read_token)
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), 200, "payer's token must read its own output");
}

#[tokio::test]
async fn batch_unknown_id_returns_404() {
    let provider = spawn_stub_provider(HashSet::new()).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{}/v1/batch/does-not-exist", gateway);
    let resp = reqwest::get(&url).await.expect("get");
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn batch_size_limit_returns_400() {
    let provider = spawn_stub_provider(HashSet::new()).await;
    let gateway = spawn_gateway(provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).expect("hex"));
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    let requests: Vec<Value> = (0..1001)
        .map(|i| {
            serde_json::json!({
                "model": "llama-3.1-8b",
                "messages": [{"role": "user", "content": format!("p{}", i)}],
                "max_tokens": 1
            })
        })
        .collect();

    let url = format!("http://{}/v1/batch", gateway);
    let body = serde_json::json!({"requests": requests});
    let req = reqwest::Client::new().post(&url).json(&body);
    // 400 happens before payment, so a plain reqwest is fine — but
    // we use the X402Client to mirror the real call shape. The 402
    // challenge will come first, then after payment the 400 fires.
    let resp = client.send_paid(req).await.expect("send");
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.expect("json");
    let msg = body["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("1000"), "got: {}", msg);
}

/// IGW-B-004 RC-8 tripwire: the batch route must not let an explicit
/// over-ceiling budget reach pricing or provider dispatch. The sync chat route
/// is checked in the same test to prove its existing clamp still holds at the
/// provider boundary.
#[tokio::test]
async fn batch_enforces_max_tokens_ceiling_at_dispatch_boundary() {
    let batch_observed = Arc::new(Mutex::new(Vec::new()));
    let batch_provider = spawn_recording_provider(batch_observed.clone()).await;
    let batch_gateway = spawn_gateway(batch_provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).expect("hex"));
    let batch_client =
        X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("batch client");
    let batch_url = format!("http://{}/v1/batch", batch_gateway);
    let batch_body = serde_json::json!({
        "requests": [{
            "model": "llama-3.1-8b",
            "messages": [{"role": "user", "content": "bounded batch"}],
            "max_tokens": u32::MAX
        }]
    });
    let response = batch_client
        .send_paid(reqwest::Client::new().post(&batch_url).json(&batch_body))
        .await
        .expect("batch request");
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.expect("batch json");
    let message = body["error"]["message"].as_str().unwrap_or("");
    assert!(message.contains("max_tokens"), "got: {}", message);
    assert!(
        batch_observed.lock().expect("observed mutex").is_empty(),
        "an over-ceiling batch must not dispatch to a provider"
    );

    // Use a fresh chain/gateway because the mock settlement is intentionally
    // single-use. This confirms the existing sync route still clamps before
    // provider dispatch when presented with the same hostile value.
    let chat_observed = Arc::new(Mutex::new(Vec::new()));
    let chat_provider = spawn_recording_provider(chat_observed.clone()).await;
    let chat_gateway = spawn_gateway(chat_provider).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let chat_client =
        X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("chat client");
    let chat_url = format!("http://{}/v1/chat/completions", chat_gateway);
    let chat_body = serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role": "user", "content": "bounded chat"}],
        "max_tokens": u32::MAX
    });
    let response = chat_client
        .send_paid(reqwest::Client::new().post(&chat_url).json(&chat_body))
        .await
        .expect("chat request");
    assert_eq!(response.status(), 200);
    let dispatched = chat_observed.lock().expect("observed mutex").clone();
    assert_eq!(dispatched.len(), 1);
    assert!(
        dispatched[0] <= 8_192,
        "chat provider budget exceeded ceiling: {}",
        dispatched[0]
    );
}
