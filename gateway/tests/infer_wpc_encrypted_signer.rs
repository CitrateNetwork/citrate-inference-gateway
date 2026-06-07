//! INFER-S1 / WP-C — the DEV/TESTNET encrypted-file operator signer.
//!
//! `EncryptedFileSigner` loads a V3 keystore (scrypt + AES-128-CTR) and produces
//! byte-identical EIP-155 output to the local/KMS signers. It is the testnet
//! custody path: `OperatorWallet::from_env` only builds it behind an explicit
//! `CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER=1` opt-in (mainnet stays KMS-only — see
//! `scripts/ci/check_no_plaintext_operator_key.py`).
//!
//! These tests prove (1) the keystore roundtrips to the right operator address,
//! (2) `from_env` fails closed without the opt-in and builds the signer with it,
//! and (3) the signer lands a real `requestPoolCompute` on anvil.

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use citrate_gateway::signer::{EncryptedFileSigner, OperatorWallet};
use ethereum_types::{H160, U256};
use serde_json::{json, Value};
use x402_axum::sign_tx::{LocalSigner, Signer};

/// anvil's default account 0 secret (deterministic "test...junk" mnemonic).
const ANVIL_ACCT0: [u8; 32] = [
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
];
const ANVIL_CHAIN_ID: u64 = 31337;
const PASSWORD: &str = "correct horse battery staple";

static UNIQ: AtomicU64 = AtomicU64::new(0);

/// A throwaway directory unique to this process + call (no Date/rand needed).
fn scratch_dir() -> std::path::PathBuf {
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("citrate-keystore-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

/// Write a V3 keystore encrypting `secret` and return its path.
fn write_keystore(secret: &[u8; 32], password: &str) -> std::path::PathBuf {
    let dir = scratch_dir();
    let mut rng = rand::thread_rng();
    // `encrypt_key` returns the keystore UUID, not the filename; with an explicit
    // name it writes to `dir/<name>`.
    eth_keystore::encrypt_key(&dir, &mut rng, secret, password, Some("operator.json"))
        .expect("encrypt keystore");
    dir.join("operator.json")
}

#[tokio::test]
async fn keystore_roundtrips_to_operator_address() {
    let path = write_keystore(&ANVIL_ACCT0, PASSWORD);
    let signer = EncryptedFileSigner::from_keystore(&path, PASSWORD).expect("load keystore");

    let expected = LocalSigner::from_secret(ANVIL_ACCT0).expect("local").address();
    assert_eq!(signer.address(), expected, "keystore must decrypt to the operator EOA");

    // And it actually signs: the recovered signer matches the operator.
    let hash = [7u8; 32];
    let sig = Signer::sign_hash(&signer, &hash).await.expect("sign");
    let recovered =
        x402_axum::sign_tx::ecrecover(&hash, &sig.r, &sig.s, sig.recovery_id).expect("recover");
    assert_eq!(recovered, expected, "signature must recover to the operator");
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let path = write_keystore(&ANVIL_ACCT0, PASSWORD);
    let err = EncryptedFileSigner::from_keystore(&path, "not the password");
    assert!(err.is_err(), "a bad password must fail closed, not load a wrong key");
}

#[tokio::test]
async fn from_env_fails_closed_without_optin_then_builds_with_it() {
    // This test owns the CITRATE_GATEWAY_* env for its duration. Other tests in
    // this binary don't touch these vars, so the (serial) set/clear is safe.
    let path = write_keystore(&ANVIL_ACCT0, PASSWORD);
    std::env::set_var("CITRATE_GATEWAY_OPERATOR_KEYSTORE", &path);
    std::env::set_var("CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD", PASSWORD);
    std::env::set_var("CITRATE_GATEWAY_COMPUTE_POOL", "0xcccccccccccccccccccccccccccccccccccccccc");
    std::env::set_var("CITRATE_GATEWAY_OPERATOR_SPEND_CAP_WEI", "1000000000000000000000");
    std::env::remove_var("CITRATE_GATEWAY_KMS_KEY_ID");

    // No opt-in → fail closed (the encrypted-file signer is never silent).
    std::env::remove_var("CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER");
    let denied = OperatorWallet::from_env("http://127.0.0.1:1", ANVIL_CHAIN_ID).await;
    assert!(denied.is_err(), "keystore without ALLOW_LOCAL_SIGNER=1 must error");

    // Explicit opt-in → builds a wallet bound to the keystore operator.
    std::env::set_var("CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER", "1");
    let wallet = OperatorWallet::from_env("http://127.0.0.1:1", ANVIL_CHAIN_ID)
        .await
        .expect("from_env ok")
        .expect("Some(wallet)");
    let expected = LocalSigner::from_secret(ANVIL_ACCT0).expect("local").address();
    assert_eq!(wallet.address(), expected, "wallet must use the keystore operator key");

    for k in [
        "CITRATE_GATEWAY_OPERATOR_KEYSTORE",
        "CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD",
        "CITRATE_GATEWAY_COMPUTE_POOL",
        "CITRATE_GATEWAY_OPERATOR_SPEND_CAP_WEI",
        "CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER",
    ] {
        std::env::remove_var(k);
    }
}

// ----- anvil end-to-end -------------------------------------------------------

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
        if Command::new(c).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok() {
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
        .args(["--port", &port.to_string(), "--chain-id", &ANVIL_CHAIN_ID.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let url = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    for _ in 0..50 {
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn receipt_from(url: &str, tx: &str) -> Option<H160> {
    let http = reqwest::Client::new();
    for _ in 0..50 {
        let resp = http
            .post(url)
            .json(&json!({"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":[tx],"id":1}))
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

#[tokio::test]
async fn encrypted_signer_dispatch_lands_on_anvil() {
    let Some(anvil) = start_anvil().await else {
        eprintln!("SKIP: anvil binary not available");
        return;
    };
    let path = write_keystore(&ANVIL_ACCT0, PASSWORD);
    let signer = EncryptedFileSigner::from_keystore(&path, PASSWORD).expect("load keystore");
    let operator = signer.address();

    let wallet = OperatorWallet::new(
        Arc::new(signer),
        &anvil.url,
        ANVIL_CHAIN_ID,
        H160::from([0xcc; 20]), // dummy ComputePool target (no-code; proves sign+submit)
        U256::from(10u64).pow(U256::from(21u64)),
        100,
    );

    let tx = wallet
        .dispatch_pool_compute(U256::from(1u64), b"dry-run", U256::from(1000u64), U256::from(1000u64))
        .await
        .expect("dispatch");

    let tx_hex = format!("0x{}", hex::encode(tx.as_bytes()));
    let from = receipt_from(&anvil.url, &tx_hex).await.expect("mined");
    assert_eq!(from, operator, "tx must be signed by the encrypted-file operator");
}
