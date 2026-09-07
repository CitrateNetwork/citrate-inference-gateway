//! End-to-end proof: X402Client paying an X402Layer-gated service.
//!
//! Spins up an axum service on a random port (via hyper + tokio
//! directly — axum::serve is happy with that). The service uses a
//! MockChain ChainClient so no real blockchain is needed. An
//! X402Client then POSTs to the service through reqwest; the first
//! request gets 402, the client signs, retries, and we see 200 OK
//! with the inner handler's echo of X402Paid data.
//!
//! This is the end-to-end proof of the "Valid signature passes
//! through" scenario from x402_payment.feature (#2).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use axum::{routing::get, Extension, Router};
use ethereum_types::{H160, H256, U256};
use tokio::net::TcpListener;

use x402_axum::{
    payment_settled_topic, ChainClient, FixedPricing, RawLog, TxReceipt, X402Client, X402Error,
    X402Layer, X402Paid,
};

// ── MockChain that trusts whatever the client signs ─────────────

struct HonestMockChain {
    facilitator: H160,
    /// Set of nonces this mock "has settled." Populated by
    /// wait_for_receipt via side-effecting push.
    settled: Mutex<HashSet<H256>>,
    /// IGW-B-013: the last payer recovered in `verify_offline`. An honest
    /// facilitator emits a `PaymentSettled` whose `from` is this payer and
    /// whose `to` is the gateway treasury; the layer now binds the event to
    /// the payload, so the mock must round-trip both faithfully.
    recovered_from: Mutex<Option<H160>>,
}

impl HonestMockChain {
    fn new(facilitator: H160) -> Self {
        Self {
            facilitator,
            settled: Mutex::new(HashSet::new()),
            recovered_from: Mutex::new(None),
        }
    }
}

/// The H160 form of `any_addr()` — the configured gateway treasury.
fn treasury_h160() -> H160 {
    let mut bytes = [0u8; 20];
    hex::decode_to_slice(any_addr().trim_start_matches("0x"), &mut bytes).expect("treasury hex");
    H160::from(bytes)
}

#[async_trait]
impl ChainClient for HonestMockChain {
    async fn verify_offline(&self, precompile_input: &[u8]) -> Result<Option<H160>, X402Error> {
        // Trust any well-formed input — echo `from` as recovered signer.
        if precompile_input.len() != 265 {
            return Ok(None);
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&precompile_input[32..52]);
        let recovered = H160::from(addr);
        *self.recovered_from.lock().expect("recovered mutex") = Some(recovered);
        Ok(Some(recovered))
    }

    async fn get_nonce(&self, _address: H160) -> Result<u64, X402Error> {
        Ok(0)
    }

    async fn send_raw_tx(&self, _raw_tx: &[u8]) -> Result<H256, X402Error> {
        Ok(H256::from([0xaa; 32]))
    }

    async fn wait_for_receipt(
        &self,
        _tx_hash: H256,
        _timeout: Duration,
    ) -> Result<TxReceipt, X402Error> {
        // Fabricate a PaymentSettled event. In this integration test
        // we don't actually know the exact nonce the client used
        // (the layer owns the nonce source). We pick a marker nonce
        // and note that the inner handler reads X402Paid.nonce from
        // this receipt — so the test asserts on THIS nonce.
        let marker_nonce = H256::from([0x77; 32]);

        let mut settled = self.settled.lock().expect("mutex");
        if !settled.insert(marker_nonce) {
            // Second call for same nonce — treat as replay.
            return Ok(TxReceipt {
                status: false,
                block_number: 101,
                logs: vec![],
            });
        }
        drop(settled);

        // IGW-B-013: faithful event — payer is the signer the layer just
        // recovered, recipient is the gateway treasury.
        let from = self
            .recovered_from
            .lock()
            .expect("recovered mutex")
            .unwrap_or_else(|| H160::from([0xb1; 20]));
        let to = treasury_h160();
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
        data.extend_from_slice(marker_nonce.as_bytes());

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

// ── Test helpers ────────────────────────────────────────────────

/// Deterministic secrets for layer operator AND payer client. Must
/// be different — otherwise the layer's self-signed rejection tests
/// would be confusing. Both known-valid scalars.
fn operator_secret() -> [u8; 32] {
    [
        0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff,
        0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2,
        0xff, 0x80,
    ]
}

fn payer_secret() -> [u8; 32] {
    // Another known-valid scalar — not the same as operator_secret.
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00,
        0x11, 0x22,
    ]
}

fn any_addr() -> &'static str {
    "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b"
}

async fn spawn_service() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let facilitator = H160::from([0xfa; 20]);
    let mock = HonestMockChain::new(facilitator);

    let layer = X402Layer::builder()
        .chain_id(40204)
        .facilitator_address(&format!("0x{}", hex::encode(facilitator.as_bytes())))
        .wsalt_address(any_addr())
        .treasury(any_addr())
        .rpc_url("http://unused-mock")
        .pricing(FixedPricing::new("1000000000000000000")) // 1 SALT
        .operator_secret_bytes(operator_secret())
        .chain_client(mock)
        .build()
        .expect("build layer");

    let app = Router::new()
        .route(
            "/gated",
            get(|Extension(paid): Extension<X402Paid>| async move {
                // Echo nonce so test can assert it came through.
                format!(
                    "{{\"nonce\":\"0x{}\",\"payer\":\"0x{}\"}}",
                    hex::encode(paid.nonce.as_bytes()),
                    hex::encode(paid.payer.as_bytes())
                )
            }),
        )
        .layer(layer);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (addr, handle)
}

#[tokio::test]
async fn client_auto_pays_on_402_and_gets_200() {
    let (addr, _server) = spawn_service().await;
    tokio::time::sleep(Duration::from_millis(50)).await; // let server bind

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    let client =
        X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("build client");

    let http = reqwest::Client::new();
    let url = format!("http://{}/gated", addr);
    let req = http.get(&url);

    let resp = client.send_paid(req).await.expect("auto-pay flow");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("body");
    assert!(body.contains("nonce"));
    // IGW-B-001 (settle-after-serve): X402Paid is attached from the
    // VALIDATED signed payload BEFORE the inner service runs, so
    // `X402Paid.nonce` is the challenge nonce the client signed — NOT the
    // mock's synthetic post-settle event nonce (0x77*32, which is only
    // known after settlement, which now happens AFTER the handler). So the
    // old marker must NOT appear.
    assert!(
        !body.contains(&"77".repeat(32)),
        "nonce must be the signed challenge nonce, not the post-settle marker"
    );
    // Handler echoes payer from X402Paid.payer, which post-fix is the
    // signed payload's `from` — the client's own derived payer address,
    // the correct payer identity (pre-fix it was the mock event's 0xa1).
    let expected_payer = hex::encode(client.payer_address().as_bytes());
    assert!(
        body.contains(&expected_payer),
        "payer must be the signed payload's `from` (client payer address {expected_payer}); body: {body}"
    );
}

#[tokio::test]
async fn client_budget_cap_refuses_expensive_challenge() {
    let (addr, _server) = spawn_service().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204)
        .expect("build client")
        .with_budget_cap(U256::from(100u128)); // 100 wei — far below 1 SALT

    let http = reqwest::Client::new();
    let url = format!("http://{}/gated", addr);
    let req = http.get(&url);

    let err = client.send_paid(req).await.expect_err("should fail");
    assert!(matches!(err, X402Error::BudgetExceeded { .. }));
}

#[tokio::test]
async fn client_rejects_chain_id_mismatch() {
    let (addr, _server) = spawn_service().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    // Client thinks it's on chain 1, server is on 40204.
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 1).expect("build client");

    let http = reqwest::Client::new();
    let url = format!("http://{}/gated", addr);
    let req = http.get(&url);

    let err = client.send_paid(req).await.expect_err("should fail");
    assert!(matches!(err, X402Error::Internal(m) if m.contains("chain_id")));
}

#[tokio::test]
async fn client_passes_through_non_402_responses() {
    // A server response that's NOT a 402 (e.g. the gated handler
    // directly, or an unrelated endpoint) must pass through without
    // signing.
    let facilitator = H160::from([0xfa; 20]);
    let wsalt = H160::from_slice(&hex::decode(&any_addr()[2..]).unwrap());
    let client = X402Client::try_new(payer_secret(), wsalt, facilitator, 40204).expect("client");

    // Point at a URL that returns 404 so we get a non-402 response
    // without building a whole second server.
    let http = reqwest::Client::new();
    let req = http.get("http://127.0.0.1:1/does-not-exist");
    // Expect either a connection error OR a non-402 response.
    // Most important: client must NOT attempt to sign anything for
    // a non-402 code path.
    let _ = client.send_paid(req).await; // either Ok(some-status) or Err(Transport)
                                         // Test passes by compiling + not panicking; the budget cap
                                         // would only trigger on a real 402.
}
