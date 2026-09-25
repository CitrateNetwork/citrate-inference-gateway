//! INFER-S1 / WP-C — anvil end-to-end: the gateway operator wallet signs and
//! submits `requestPoolCompute` to a live chain, with correct single-writer
//! nonce serialization under concurrency.
//!
//! Uses a `LocalSigner` (anvil's prefunded account 0 — its key is the same
//! deterministic vector the unit tests use); production swaps in `AwsKmsSigner`,
//! which produces byte-identical EIP-155 output (proven in x402-axum's
//! `signer_trait_path_is_byte_identical_to_local`). Requires the `anvil` binary.

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use citrate_gateway::signer::OperatorWallet;
use ethereum_types::{H160, U256};
use serde_json::{json, Value};
use x402_axum::sign_tx::LocalSigner;

/// anvil's default account 0 secret (deterministic "test...junk" mnemonic).
const ANVIL_ACCT0: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];
const ANVIL_CHAIN_ID: u64 = 31337;

struct Anvil {
    child: Child,
    url: String,
}
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn anvil_bin() -> Option<String> {
    for c in ["anvil", "/home/saul/.foundry/bin/anvil"] {
        if Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
        {
            return Some(c.to_string());
        }
    }
    None
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().expect("addr").port()
}

async fn start_anvil() -> Option<Anvil> {
    let bin = anvil_bin()?;
    let port = free_port();
    let child = Command::new(bin)
        .args([
            "--port",
            &port.to_string(),
            "--chain-id",
            &ANVIL_CHAIN_ID.to_string(),
            "--silent",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let url = format!("http://127.0.0.1:{port}");
    // Wait until the RPC answers eth_blockNumber.
    let http = reqwest::Client::new();
    for _ in 0..50 {
        let ok = http
            .post(&url)
            .json(&json!({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}))
            .send()
            .await
            .ok()
            .is_some();
        if ok {
            // one more check that we get a result, not just a connection
            if let Ok(resp) = http
                .post(&url)
                .json(&json!({"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}))
                .send()
                .await
            {
                if let Ok(v) = resp.json::<Value>().await {
                    if v.get("result").is_some() {
                        return Some(Anvil { child, url });
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn receipt_from(url: &str, tx: &str) -> Option<H160> {
    let http = reqwest::Client::new();
    for _ in 0..300 {
        let resp = http
            .post(url)
            .json(
                &json!({"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":[tx],"id":1}),
            )
            .send()
            .await
            .ok()?;
        let v: Value = resp.json().await.ok()?;
        if let Some(r) = v.get("result").filter(|r| !r.is_null()) {
            let from = r.get("from")?.as_str()?;
            let bytes = hex::decode(from.trim_start_matches("0x")).ok()?;
            return Some(H160::from_slice(&bytes));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

fn wallet(url: &str) -> OperatorWallet {
    let signer = Arc::new(LocalSigner::from_secret(ANVIL_ACCT0).expect("signer"));
    OperatorWallet::new(
        signer,
        url,
        ANVIL_CHAIN_ID,
        H160::from([0xcc; 20]), // dummy ComputePool target (no-code; proves sign+submit)
        U256::from(10u64).pow(U256::from(21u64)), // generous per-epoch cap
        100,
    )
}

#[tokio::test]
async fn dispatch_pool_compute_signs_and_lands_on_anvil() {
    let Some(anvil) = start_anvil().await else {
        eprintln!("SKIP: anvil binary not available");
        return;
    };
    let w = wallet(&anvil.url);
    let operator = w.address();

    let tx = w
        .dispatch_pool_compute(
            U256::from(1u64),
            b"job-spec",
            U256::from(1000u64),
            U256::from(1000u64),
        )
        .await
        .expect("dispatch");

    let tx_hex = format!("0x{}", hex::encode(tx.as_bytes()));
    let from = receipt_from(&anvil.url, &tx_hex).await.expect("mined");
    assert_eq!(from, operator, "tx must be signed by the operator");
}

#[tokio::test]
async fn concurrent_dispatches_serialize_nonces() {
    let Some(anvil) = start_anvil().await else {
        eprintln!("SKIP: anvil binary not available");
        return;
    };
    let w = Arc::new(wallet(&anvil.url));

    // Fire several dispatches concurrently. The single-writer nonce manager must
    // assign distinct nonces with no reuse/gap, so all of them mine.
    let mut handles = Vec::new();
    for i in 0..5u64 {
        let w = Arc::clone(&w);
        handles.push(tokio::spawn(async move {
            w.dispatch_pool_compute(U256::from(i), b"x", U256::from(1u64), U256::from(1u64))
                .await
        }));
    }
    let mut hashes = Vec::new();
    for h in handles {
        let tx = h.await.expect("join").expect("dispatch");
        hashes.push(format!("0x{}", hex::encode(tx.as_bytes())));
    }
    // All distinct, and all mine.
    let mut uniq = hashes.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 5, "5 distinct txs (no nonce reuse)");
    for h in &hashes {
        assert!(
            receipt_from(&anvil.url, h).await.is_some(),
            "each dispatch must mine"
        );
    }
}

/// INFER-S2 / WP-D — the gateway (as the job's requester) signs + submits
/// `reclaimExpiredJob` on anvil for its refund-on-timeout path.
#[tokio::test]
async fn reclaim_expired_job_signs_and_lands_on_anvil() {
    let Some(anvil) = start_anvil().await else {
        eprintln!("SKIP: anvil binary not available");
        return;
    };
    let w = wallet(&anvil.url);
    let operator = w.address();

    let tx = w
        .reclaim_expired_job(U256::from(7u64))
        .await
        .expect("reclaim");
    let from = receipt_from(&anvil.url, &format!("0x{}", hex::encode(tx.as_bytes())))
        .await
        .expect("mined");
    assert_eq!(
        from, operator,
        "reclaim must be signed by the operator (the requester)"
    );
}
