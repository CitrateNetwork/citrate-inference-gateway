//! INFER-S1 / WP-C — the gateway operator wallet / signer.
//!
//! Gives `marketplace` mode a custody-safe signer that submits
//! `ComputePool.requestPoolCompute` (and later `reclaimExpiredJob`). The key
//! never lives as plaintext in the gateway: production signs via **AWS KMS**
//! (the key stays in KMS; it returns only `(r, s)`), and the gateway derives
//! the EIP-155 `v` by recovery. A `LocalSigner` (k256) backs tests + the anvil
//! e2e. Both implement [`x402_axum::sign_tx::Signer`].
//!
//! Custody hardening (handoff WP-C): single-writer account-nonce manager,
//! per-epoch spend cap (blast-radius bound), KMS key never logged. Do NOT point
//! at a funded testnet until citrate-security reviews custody.

use std::sync::Arc;

use ethereum_types::{H160, H256, U256};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tokio::sync::Mutex;

use x402_axum::sign_tx::{sign_settlement_tx_with, SettlementTx, Signer};

use crate::error::GatewayError;

/// Generous gas limit for a pool-dispatch call.
const POOL_DISPATCH_GAS: u64 = 600_000;
/// Fallback gas price (wei) if `eth_gasPrice` is unavailable.
const DEFAULT_GAS_PRICE_WEI: u64 = 1_000_000_000;

// ── Account-nonce manager ───────────────────────────────────────────

/// Single-writer account-nonce manager. Seeds lazily from the chain
/// (`eth_getTransactionCount(addr, "pending")`) and hands out strictly
/// increasing nonces under a mutex, so concurrent pool dispatches can never
/// reuse or gap a nonce. On a submit failure the caller `resync`s from chain.
#[derive(Default)]
pub struct NonceManager {
    inner: Mutex<Option<u64>>,
}

impl NonceManager {
    /// Empty (unseeded) manager.
    pub fn new() -> Self {
        Self { inner: Mutex::new(None) }
    }

    /// Reserve the next nonce. Seeds from `seed` (the chain) on first use. The
    /// lock is held across the seed await so the seed happens exactly once and
    /// concurrent callers serialize.
    pub async fn reserve<F, Fut>(&self, seed: F) -> Result<u64, GatewayError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<u64, GatewayError>>,
    {
        let mut guard = self.inner.lock().await;
        let n = match *guard {
            Some(n) => n,
            None => seed().await?,
        };
        *guard = Some(n + 1);
        Ok(n)
    }

    /// Re-seed from chain after a failed/dropped tx so the next reserve is correct.
    pub async fn resync(&self, chain_nonce: u64) {
        *self.inner.lock().await = Some(chain_nonce);
    }
}

// ── Per-epoch spend cap ─────────────────────────────────────────────

/// A blast-radius bound: at most `ceiling` wei of native value may be dispatched
/// per `blocks_per_epoch` window. A bug or compromise can't drain the hot wallet
/// faster than one epoch's ceiling.
pub struct SpendCap {
    ceiling_wei: U256,
    blocks_per_epoch: u64,
    inner: Mutex<(u64, U256)>, // (epoch, spent_this_epoch)
}

impl SpendCap {
    /// `ceiling_wei` per `blocks_per_epoch` window.
    pub fn new(ceiling_wei: U256, blocks_per_epoch: u64) -> Self {
        Self {
            ceiling_wei,
            blocks_per_epoch: blocks_per_epoch.max(1),
            inner: Mutex::new((0, U256::zero())),
        }
    }

    /// Reserve `amount` against the cap for the epoch containing `block`.
    /// Rolls the window over at epoch boundaries. `Err(SpendCapExceeded)` if it
    /// would breach the ceiling.
    pub async fn try_spend(&self, amount: U256, block: u64) -> Result<(), GatewayError> {
        let epoch = block / self.blocks_per_epoch;
        let mut guard = self.inner.lock().await;
        if guard.0 != epoch {
            *guard = (epoch, U256::zero());
        }
        let next = guard.1.saturating_add(amount);
        if next > self.ceiling_wei {
            return Err(GatewayError::SpendCapExceeded {
                requested_wei: amount.to_string(),
                remaining_wei: self.ceiling_wei.saturating_sub(guard.1).to_string(),
            });
        }
        guard.1 = next;
        Ok(())
    }
}

// ── requestPoolCompute calldata ─────────────────────────────────────

/// ABI-encode `requestPoolCompute(uint256 poolId, bytes jobSpec, uint256 maxPrice)`.
pub fn encode_request_pool_compute(pool_id: U256, job_spec: &[u8], max_price: U256) -> Vec<u8> {
    let selector = &Keccak256::digest(b"requestPoolCompute(uint256,bytes,uint256)")[..4];
    let mut out = Vec::with_capacity(4 + 32 * 4 + job_spec.len() + 32);
    out.extend_from_slice(selector);
    out.extend_from_slice(&u256_word(pool_id));
    // head: offset to the `bytes` tail = 3 words after the head start = 0x60.
    out.extend_from_slice(&u256_word(U256::from(0x60u64)));
    out.extend_from_slice(&u256_word(max_price));
    // tail: length-prefixed, right-padded jobSpec.
    out.extend_from_slice(&u256_word(U256::from(job_spec.len() as u64)));
    out.extend_from_slice(job_spec);
    let pad = (32 - (job_spec.len() % 32)) % 32;
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}

/// ABI-encode `reclaimExpiredJob(uint256 jobId)` (INFER-S2 / WP-D refund). The
/// gateway is the job's `requester`, so it is the only actor that can reclaim
/// escrow after `JOB_DEADLINE` — this is the gateway's refund-on-timeout call.
pub fn encode_reclaim_expired_job(job_id: U256) -> Vec<u8> {
    let selector = &Keccak256::digest(b"reclaimExpiredJob(uint256)")[..4];
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(selector);
    out.extend_from_slice(&u256_word(job_id));
    out
}

fn u256_word(v: U256) -> [u8; 32] {
    let mut w = [0u8; 32];
    v.to_big_endian(&mut w);
    w
}

// ── Operator wallet ─────────────────────────────────────────────────

/// The operator wallet: a [`Signer`] (KMS or local) plus the nonce manager,
/// spend cap, and the RPC client used to submit pool-dispatch txs.
pub struct OperatorWallet {
    signer: Arc<dyn Signer>,
    http: reqwest::Client,
    rpc_url: String,
    chain_id: u64,
    compute_pool: H160,
    nonce: NonceManager,
    spend_cap: SpendCap,
}

impl OperatorWallet {
    /// Build from a signer + chain config. `ceiling_wei`/`blocks_per_epoch`
    /// bound the per-epoch spend.
    pub fn new(
        signer: Arc<dyn Signer>,
        rpc_url: impl Into<String>,
        chain_id: u64,
        compute_pool: H160,
        ceiling_wei: U256,
        blocks_per_epoch: u64,
    ) -> Self {
        Self {
            signer,
            http: reqwest::Client::new(),
            rpc_url: rpc_url.into(),
            chain_id,
            compute_pool,
            nonce: NonceManager::new(),
            spend_cap: SpendCap::new(ceiling_wei, blocks_per_epoch),
        }
    }

    /// Load the production operator wallet from the environment, if configured.
    /// `CITRATE_GATEWAY_KMS_KEY_ID` (KMS key ARN/alias) gates it; the spend cap
    /// and compute-pool address are required when it is set. Returns `Ok(None)`
    /// when unset (pool dispatch stays unavailable until WP-D wires it + custody
    /// is reviewed). **Fail-closed:** if a KMS key is configured but the binary
    /// was built without the `aws-kms` feature, this errors rather than running
    /// the marketplace without a signer.
    pub async fn from_env(rpc_url: impl Into<String>, chain_id: u64) -> Result<Option<Self>, GatewayError> {
        let kms = std::env::var("CITRATE_GATEWAY_KMS_KEY_ID").ok().filter(|s| !s.is_empty());
        let keystore = std::env::var("CITRATE_GATEWAY_OPERATOR_KEYSTORE").ok().filter(|s| !s.is_empty());
        if kms.is_none() && keystore.is_none() {
            return Ok(None);
        }

        let compute_pool = parse_addr_env("CITRATE_GATEWAY_COMPUTE_POOL")?;
        let ceiling = std::env::var("CITRATE_GATEWAY_OPERATOR_SPEND_CAP_WEI")
            .ok()
            .and_then(|s| U256::from_dec_str(&s).ok())
            .ok_or_else(|| GatewayError::Internal(
                "set CITRATE_GATEWAY_OPERATOR_SPEND_CAP_WEI (operator blast-radius bound)".into(),
            ))?;
        let epoch_blocks: u64 = std::env::var("CITRATE_GATEWAY_OPERATOR_EPOCH_BLOCKS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);

        // 1. Production custody: AWS KMS (takes precedence; the key never leaves KMS).
        if let Some(key_id) = kms {
            #[cfg(feature = "aws-kms")]
            {
                let signer = Arc::new(AwsKmsSigner::from_env(key_id).await?);
                return Ok(Some(Self::new(signer, rpc_url, chain_id, compute_pool, ceiling, epoch_blocks)));
            }
            #[cfg(not(feature = "aws-kms"))]
            {
                let _ = key_id;
                return Err(GatewayError::Internal(
                    "CITRATE_GATEWAY_KMS_KEY_ID is set but this gateway was built without the \
                     `aws-kms` feature — rebuild with `--features aws-kms`.".into(),
                ));
            }
        }

        // 2. DEV/TESTNET custody: encrypted-file signer (explicit opt-in, NEVER
        //    mainnet — mainnet must use AWS KMS, enforced by precedence above +
        //    the CI tripwire). Requires `CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER=1`.
        let keystore = keystore.expect("keystore present (checked)");
        if std::env::var("CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER").ok().as_deref() != Some("1") {
            return Err(GatewayError::Internal(
                "CITRATE_GATEWAY_OPERATOR_KEYSTORE is set but CITRATE_GATEWAY_ALLOW_LOCAL_SIGNER=1 \
                 is required — the encrypted-file signer is DEV/TESTNET only; mainnet must use AWS \
                 KMS (--features aws-kms).".into(),
            ));
        }
        let password = std::env::var("CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD")
            .ok()
            .or_else(|| {
                std::env::var("CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD_FILE")
                    .ok()
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .map(|s| s.trim().to_string())
            })
            .ok_or_else(|| GatewayError::Internal(
                "set CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD or ..._PASSWORD_FILE".into(),
            ))?;
        let signer = std::sync::Arc::new(EncryptedFileSigner::from_keystore(&keystore, &password)?);
        tracing::warn!(
            operator = %format!("0x{}", hex::encode(signer.address().as_bytes())),
            "⚠ DEV/TESTNET operator signer loaded from an ENCRYPTED FILE (not KMS) — do NOT use on mainnet"
        );
        Ok(Some(Self::new(signer, rpc_url, chain_id, compute_pool, ceiling, epoch_blocks)))
    }

    /// The operator EOA address (never the key).
    pub fn address(&self) -> H160 {
        self.signer.address()
    }

    /// Sign + submit `requestPoolCompute`, escrowing `payment` wei. Returns the
    /// tx hash. The nonce is reserved under the single-writer lock; on a submit
    /// failure we resync the nonce from chain to avoid a gap.
    pub async fn dispatch_pool_compute(
        &self,
        pool_id: U256,
        job_spec: &[u8],
        max_price: U256,
        payment: U256,
    ) -> Result<H256, GatewayError> {
        // Blast-radius: the payment counts against the per-epoch cap.
        let block = self.eth_block_number().await?;
        self.spend_cap.try_spend(payment, block).await?;

        let addr = self.signer.address();
        let nonce = self
            .nonce
            .reserve(|| self.eth_get_transaction_count(addr))
            .await?;
        let gas_price = self.eth_gas_price().await.unwrap_or(DEFAULT_GAS_PRICE_WEI);

        let data = encode_request_pool_compute(pool_id, job_spec, max_price);
        let tx = SettlementTx {
            chain_id: self.chain_id,
            nonce,
            gas_price_wei: gas_price,
            gas_limit: POOL_DISPATCH_GAS,
            to: self.compute_pool,
            value: payment,
            data: &data,
        };
        let signed = sign_settlement_tx_with(self.signer.as_ref(), tx)
            .await
            .map_err(|e| GatewayError::Internal(format!("sign pool dispatch: {e}")))?;

        self.submit_signed(addr, &signed.raw).await
    }

    /// Sign + submit `reclaimExpiredJob(jobId)` — the gateway's refund-on-timeout
    /// (INFER-S2 / WP-D). Callable as the job's `requester` after `JOB_DEADLINE`;
    /// the contract refunds the escrow to the gateway, which then credits the
    /// buyer's key balance. No spend-cap (it's a refund, not a spend) and no
    /// `value` (the contract returns escrow). Returns the tx hash.
    pub async fn reclaim_expired_job(&self, job_id: U256) -> Result<H256, GatewayError> {
        let addr = self.signer.address();
        let nonce = self
            .nonce
            .reserve(|| self.eth_get_transaction_count(addr))
            .await?;
        let gas_price = self.eth_gas_price().await.unwrap_or(DEFAULT_GAS_PRICE_WEI);
        let data = encode_reclaim_expired_job(job_id);
        let tx = SettlementTx {
            chain_id: self.chain_id,
            nonce,
            gas_price_wei: gas_price,
            gas_limit: POOL_DISPATCH_GAS,
            to: self.compute_pool,
            value: U256::zero(),
            data: &data,
        };
        let signed = sign_settlement_tx_with(self.signer.as_ref(), tx)
            .await
            .map_err(|e| GatewayError::Internal(format!("sign reclaim: {e}")))?;
        self.submit_signed(addr, &signed.raw).await
    }

    /// Submit a signed tx; on failure, resync the nonce from chain so the
    /// reserved-but-unsent nonce isn't left as a gap.
    async fn submit_signed(&self, addr: H160, raw: &[u8]) -> Result<H256, GatewayError> {
        match self.eth_send_raw_transaction(raw).await {
            Ok(h) => Ok(h),
            Err(e) => {
                if let Ok(n) = self.eth_get_transaction_count(addr).await {
                    self.nonce.resync(n).await;
                }
                Err(e)
            }
        }
    }

    // ── JSON-RPC (reqwest, mirrors queries.rs) ──────────────────────

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, GatewayError> {
        let body = json!({ "jsonrpc": "2.0", "method": method, "params": params, "id": 1 });
        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| GatewayError::ChainUnavailable(format!("rpc transport: {e}")))?;
        let value: Value = resp
            .json()
            .await
            .map_err(|e| GatewayError::ChainUnavailable(format!("rpc decode: {e}")))?;
        if let Some(err) = value.get("error") {
            return Err(GatewayError::ChainUnavailable(format!("rpc error: {err}")));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| GatewayError::ChainUnavailable("rpc missing result".into()))
    }

    async fn eth_get_transaction_count(&self, addr: H160) -> Result<u64, GatewayError> {
        let r = self
            .rpc(
                "eth_getTransactionCount",
                json!([format!("0x{}", hex::encode(addr.as_bytes())), "pending"]),
            )
            .await?;
        parse_hex_u64(&r).ok_or_else(|| GatewayError::ChainUnavailable("bad nonce".into()))
    }

    async fn eth_block_number(&self) -> Result<u64, GatewayError> {
        let r = self.rpc("eth_blockNumber", json!([])).await?;
        parse_hex_u64(&r).ok_or_else(|| GatewayError::ChainUnavailable("bad block number".into()))
    }

    async fn eth_gas_price(&self) -> Result<u64, GatewayError> {
        let r = self.rpc("eth_gasPrice", json!([])).await?;
        parse_hex_u64(&r).ok_or_else(|| GatewayError::ChainUnavailable("bad gas price".into()))
    }

    async fn eth_send_raw_transaction(&self, raw: &[u8]) -> Result<H256, GatewayError> {
        let r = self
            .rpc(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(raw))]),
            )
            .await?;
        let s = r
            .as_str()
            .ok_or_else(|| GatewayError::ChainUnavailable("bad tx hash".into()))?;
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| GatewayError::ChainUnavailable(format!("bad tx hash hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(GatewayError::ChainUnavailable("tx hash not 32 bytes".into()));
        }
        Ok(H256::from_slice(&bytes))
    }
}

fn parse_hex_u64(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn parse_addr_env(key: &str) -> Result<H160, GatewayError> {
    let s = std::env::var(key).map_err(|_| GatewayError::Internal(format!("set {key}")))?;
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| GatewayError::Internal(format!("{key}: bad hex: {e}")))?;
    if bytes.len() != 20 {
        return Err(GatewayError::Internal(format!("{key}: not a 20-byte address")));
    }
    Ok(H160::from_slice(&bytes))
}

// ── KMS signer crypto (the AWS SDK adapter is deferred) ──────────────
//
// These KMS-agnostic helpers (DER→(r,s), SPKI→address) are exactly what a
// future `AwsKmsSigner` uses to turn KMS's `(r, s)` + public key into a
// recoverable EIP-155 signature — tested here without AWS. The KMS *network
// client* (`aws-sdk-kms` + `aws-config`) is intentionally NOT vendored in this
// slice: it transitively pulls a vulnerable legacy rustls
// (RUSTSEC-2026-0098/0099/0104) the audit gate denies. The adapter lands in the
// security-reviewed custody slice that gates the funded-testnet deploy.

/// Parse a DER-encoded ECDSA signature (as AWS KMS returns) into low-S `(r, s)`.
/// Uses k256 so DER decoding + EIP-2 low-S normalization are battle-tested.
fn parse_kms_der_signature(der: &[u8]) -> Result<([u8; 32], [u8; 32]), GatewayError> {
    use k256::ecdsa::Signature;
    let sig = Signature::from_der(der)
        .map_err(|e| GatewayError::Internal(format!("kms DER signature: {e}")))?;
    let sig = sig.normalize_s().unwrap_or(sig); // EIP-2 low-S
    let b = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&b[..32]);
    s.copy_from_slice(&b[32..]);
    Ok((r, s))
}

/// Derive the EOA address from a KMS SubjectPublicKeyInfo (SPKI) DER. The
/// uncompressed secp256k1 point (`0x04 || X || Y`, 65 bytes) is the SPKI's
/// trailing bytes; address = keccak256(point[1..])[12..].
fn address_from_spki(spki: &[u8]) -> Result<H160, GatewayError> {
    if spki.len() < 65 {
        return Err(GatewayError::Internal("kms SPKI too short".into()));
    }
    let point = &spki[spki.len() - 65..];
    if point[0] != 0x04 {
        return Err(GatewayError::Internal("kms SPKI not an uncompressed point".into()));
    }
    let digest = Keccak256::digest(&point[1..]);
    Ok(H160::from_slice(&digest[12..]))
}

// ── Encrypted-file signer (DEV / TESTNET custody) ───────────────────
//
// Loads a secp256k1 key from a standard Ethereum **V3 keystore** (scrypt +
// AES-128-CTR + keccak MAC — interops with `cast wallet` / geth). The key is
// encrypted at rest; it is decrypted into memory at runtime. This is the
// handoff's MVP custody for **dev/testnet only** — mainnet must use AWS KMS
// (`--features aws-kms`), enforced by the from_env precedence + the CI tripwire.

/// A dev/testnet operator signer backed by an encrypted V3 keystore file.
/// Wraps a [`LocalSigner`] once decrypted; the key never appears in plaintext
/// on disk or in an env var.
pub struct EncryptedFileSigner {
    inner: x402_axum::sign_tx::LocalSigner,
}

impl EncryptedFileSigner {
    /// Decrypt the V3 keystore at `path` with `password` and build the signer.
    pub fn from_keystore(
        path: impl AsRef<std::path::Path>,
        password: &str,
    ) -> Result<Self, GatewayError> {
        let secret_vec = eth_keystore::decrypt_key(path.as_ref(), password)
            .map_err(|e| GatewayError::Internal(format!("keystore decrypt: {e}")))?;
        if secret_vec.len() != 32 {
            return Err(GatewayError::Internal("keystore key is not 32 bytes".into()));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_vec);
        let inner = x402_axum::sign_tx::LocalSigner::from_secret(secret)
            .map_err(|e| GatewayError::Internal(format!("keystore key invalid: {e}")))?;
        Ok(Self { inner })
    }

    /// The operator EOA address.
    pub fn address(&self) -> H160 {
        self.inner.address()
    }
}

#[async_trait::async_trait]
impl Signer for EncryptedFileSigner {
    fn address(&self) -> H160 {
        self.inner.address()
    }
    async fn sign_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<x402_axum::sign_tx::RecoverableSignature, x402_axum::error::X402Error> {
        self.inner.sign_hash(hash).await
    }
}

// ── AWS KMS signer (production custody, feature `aws-kms`) ───────────
//
// Calls KMS's JSON API directly over the gateway's existing reqwest (rustls
// 0.23, audit-clean) with SigV4 request signing — NOT the `aws-sdk-kms` HTTP
// client, which transitively pulls a vulnerable legacy rustls the audit gate
// denies. The private key stays in KMS; KMS returns only `(r, s)` (DER), and we
// derive the EIP-155 `v` by recovery against the KMS public key.
#[cfg(feature = "aws-kms")]
pub use aws_kms::AwsKmsSigner;

#[cfg(feature = "aws-kms")]
mod aws_kms {
    use super::{address_from_spki, parse_kms_der_signature};
    use crate::error::GatewayError;
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
    use aws_sigv4::sign::v4;
    use aws_smithy_runtime_api::client::identity::Identity;
    use base64::Engine;
    use ethereum_types::H160;
    use serde_json::{json, Value};
    use std::time::SystemTime;
    use x402_axum::error::X402Error;
    use x402_axum::sign_tx::{recover_id, RecoverableSignature, Signer};

    const KMS_JSON: &str = "application/x-amz-json-1.1";

    /// AWS KMS-backed operator signer over SigV4 + reqwest. Credentials + region
    /// come from the standard AWS env vars; the key never leaves KMS.
    pub struct AwsKmsSigner {
        http: reqwest::Client,
        endpoint: String,
        host: String,
        region: String,
        key_id: String,
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
        address: H160,
    }

    impl AwsKmsSigner {
        /// Load from env (`AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
        /// optional `AWS_SESSION_TOKEN`) + `key_id`, then `GetPublicKey` to derive
        /// the operator address. The IAM principal needs `kms:Sign` +
        /// `kms:GetPublicKey` on an asymmetric `ECC_SECG_P256K1` SIGN_VERIFY key.
        pub async fn from_env(key_id: String) -> Result<Self, GatewayError> {
            let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
            let region = env("AWS_REGION")
                .or_else(|| env("AWS_DEFAULT_REGION"))
                .ok_or_else(|| GatewayError::Internal("set AWS_REGION for the KMS signer".into()))?;
            let access_key = env("AWS_ACCESS_KEY_ID")
                .ok_or_else(|| GatewayError::Internal("set AWS_ACCESS_KEY_ID".into()))?;
            let secret_key = env("AWS_SECRET_ACCESS_KEY")
                .ok_or_else(|| GatewayError::Internal("set AWS_SECRET_ACCESS_KEY".into()))?;
            let session_token = env("AWS_SESSION_TOKEN");
            let host = format!("kms.{region}.amazonaws.com");
            let endpoint = format!("https://{host}/");
            let mut signer = Self {
                http: reqwest::Client::new(),
                endpoint,
                host,
                region,
                key_id,
                access_key,
                secret_key,
                session_token,
                address: H160::zero(),
            };
            let resp = signer
                .kms_call("TrentService.GetPublicKey", json!({ "KeyId": signer.key_id }))
                .await?;
            let spki_b64 = resp
                .get("PublicKey")
                .and_then(|v| v.as_str())
                .ok_or_else(|| GatewayError::Internal("kms GetPublicKey: no PublicKey".into()))?;
            let spki = base64::engine::general_purpose::STANDARD
                .decode(spki_b64)
                .map_err(|e| GatewayError::Internal(format!("kms PublicKey base64: {e}")))?;
            signer.address = address_from_spki(&spki)?;
            tracing::info!(
                operator = %format!("0x{}", hex::encode(signer.address.as_bytes())),
                region = %signer.region,
                "AWS KMS operator signer loaded (sigv4)"
            );
            Ok(signer)
        }

        /// SigV4-sign + POST a KMS JSON call (`X-Amz-Target: TrentService.<op>`).
        async fn kms_call(&self, target: &str, body: Value) -> Result<Value, GatewayError> {
            let body_bytes = serde_json::to_vec(&body)
                .map_err(|e| GatewayError::Internal(format!("kms body encode: {e}")))?;

            let creds = Credentials::new(
                &self.access_key,
                &self.secret_key,
                self.session_token.clone(),
                None,
                "citrate-gateway-env",
            );
            let identity = Identity::from(creds);
            let params = v4::SigningParams::builder()
                .identity(&identity)
                .region(&self.region)
                .name("kms")
                .time(SystemTime::now())
                .settings(SigningSettings::default())
                .build()
                .map_err(|e| GatewayError::Internal(format!("sigv4 params: {e}")))?;
            let params = aws_sigv4::http_request::SigningParams::from(params);

            // Sign exactly the headers we then send; SigV4 only validates these.
            let signed_headers = [
                ("host", self.host.as_str()),
                ("x-amz-target", target),
                ("content-type", KMS_JSON),
            ];
            let signable = SignableRequest::new(
                "POST",
                &self.endpoint,
                signed_headers.iter().map(|(k, v)| (*k, *v)),
                SignableBody::Bytes(&body_bytes),
            )
            .map_err(|e| GatewayError::Internal(format!("sigv4 signable: {e}")))?;
            let (instructions, _sig) = sign(signable, &params)
                .map_err(|e| GatewayError::Internal(format!("sigv4 sign: {e}")))?
                .into_parts();

            let mut req = self
                .http
                .post(&self.endpoint)
                .header("x-amz-target", target)
                .header("content-type", KMS_JSON)
                .body(body_bytes);
            let (sig_headers, _query) = instructions.into_parts();
            for h in sig_headers {
                req = req.header(h.name(), h.value());
            }

            let resp = req
                .send()
                .await
                .map_err(|e| GatewayError::ChainUnavailable(format!("kms transport: {e}")))?;
            let status = resp.status();
            let text = resp
                .text()
                .await
                .map_err(|e| GatewayError::ChainUnavailable(format!("kms body: {e}")))?;
            if !status.is_success() {
                return Err(GatewayError::Internal(format!("kms {target} {status}: {text}")));
            }
            serde_json::from_str(&text)
                .map_err(|e| GatewayError::Internal(format!("kms response decode: {e}")))
        }
    }

    #[async_trait::async_trait]
    impl Signer for AwsKmsSigner {
        fn address(&self) -> H160 {
            self.address
        }

        async fn sign_hash(&self, hash: &[u8; 32]) -> Result<RecoverableSignature, X402Error> {
            let msg = base64::engine::general_purpose::STANDARD.encode(hash);
            let body = json!({
                "KeyId": self.key_id,
                "Message": msg,
                "MessageType": "DIGEST",
                "SigningAlgorithm": "ECDSA_SHA_256",
            });
            let resp = self
                .kms_call("TrentService.Sign", body)
                .await
                .map_err(|e| X402Error::Internal(format!("{e}")))?;
            let sig_b64 = resp
                .get("Signature")
                .and_then(|v| v.as_str())
                .ok_or_else(|| X402Error::Internal("kms Sign: no Signature".into()))?;
            let der = base64::engine::general_purpose::STANDARD
                .decode(sig_b64)
                .map_err(|e| X402Error::Internal(format!("kms Signature base64: {e}")))?;
            let (r, s) = parse_kms_der_signature(&der).map_err(|e| X402Error::Internal(format!("{e}")))?;
            let recovery_id = recover_id(hash, &r, &s, self.address)
                .ok_or_else(|| X402Error::Internal("kms signature did not recover operator".into()))?;
            Ok(RecoverableSignature { recovery_id, r, s })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x402_axum::sign_tx::LocalSigner;

    fn any_secret() -> [u8; 32] {
        [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ]
    }

    #[test]
    fn calldata_encodes_request_pool_compute_layout() {
        let data = encode_request_pool_compute(U256::from(7u64), b"spec", U256::from(100u64));
        // selector(4) + 4 head/tail words(128) + padded "spec"(32) = 164
        assert_eq!(data.len(), 4 + 32 * 4 + 32);
        // poolId word
        assert_eq!(data[4 + 31], 7);
        // offset word = 0x60
        assert_eq!(data[4 + 32 + 31], 0x60);
        // maxPrice word
        assert_eq!(data[4 + 64 + 31], 100);
        // length word = 4
        assert_eq!(data[4 + 96 + 31], 4);
        // jobSpec bytes
        assert_eq!(&data[4 + 128..4 + 128 + 4], b"spec");
    }

    #[test]
    fn calldata_encodes_reclaim_expired_job() {
        let data = encode_reclaim_expired_job(U256::from(42u64));
        assert_eq!(data.len(), 4 + 32, "selector + one word");
        assert_eq!(data[4 + 31], 42, "jobId word");
        assert_eq!(&data[..4], &Keccak256::digest(b"reclaimExpiredJob(uint256)")[..4]);
    }

    #[tokio::test]
    async fn nonce_manager_serializes_and_increments() {
        let mgr = NonceManager::new();
        // First reserve seeds from the closure (here: 5).
        let a = mgr.reserve(|| async { Ok(5u64) }).await.expect("a");
        // Subsequent reserves never call the seed again (would panic here).
        let b = mgr.reserve(|| async { panic!("must not re-seed") }).await.expect("b");
        let c = mgr.reserve(|| async { panic!("must not re-seed") }).await.expect("c");
        assert_eq!((a, b, c), (5, 6, 7));
        mgr.resync(20).await;
        let d = mgr.reserve(|| async { panic!("seeded") }).await.expect("d");
        assert_eq!(d, 20);
    }

    #[tokio::test]
    async fn spend_cap_bounds_per_epoch_and_rolls_over() {
        let cap = SpendCap::new(U256::from(100u64), 10); // 100 wei / 10 blocks
        cap.try_spend(U256::from(60u64), 3).await.expect("60 ok");
        cap.try_spend(U256::from(40u64), 5).await.expect("40 ok (=100)");
        // 1 more in the same epoch breaches the ceiling.
        assert!(matches!(
            cap.try_spend(U256::from(1u64), 9).await,
            Err(GatewayError::SpendCapExceeded { .. })
        ));
        // next epoch (block 10..) resets the window.
        cap.try_spend(U256::from(100u64), 10).await.expect("new epoch ok");
    }

    /// WP-C: with no KMS key configured, no operator wallet is loaded (pool
    /// dispatch stays unavailable until WP-D + custody review).
    #[tokio::test]
    async fn from_env_is_none_when_unconfigured() {
        std::env::remove_var("CITRATE_GATEWAY_KMS_KEY_ID");
        let w = OperatorWallet::from_env("http://127.0.0.1:8545", 31337).await.expect("ok");
        assert!(w.is_none());
    }

    /// WP-C: the KMS DER-signature decode (DER → low-S `(r,s)`) the future
    /// adapter will use — verified by signing with k256, DER-encoding, parsing
    /// back, and recovering the operator address.
    #[test]
    fn parse_kms_der_signature_decodes_and_recovers() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use k256::ecdsa::{Signature, SigningKey};
        let sk = SigningKey::from_bytes((&any_secret()).into()).expect("sk");
        let hash = [0xcd; 32];
        let sig: Signature = sk.sign_prehash(&hash).expect("sign");
        let der = sig.to_der();
        let (r, s) = parse_kms_der_signature(der.as_bytes()).expect("parse");
        let signer = LocalSigner::from_secret(any_secret()).expect("signer");
        // The decoded (r,s) recover the operator — proving DER decode + low-S.
        assert!(x402_axum::sign_tx::recover_id(&hash, &r, &s, signer.address()).is_some());
    }

    /// WP-C: the SPKI→address extraction matches the canonical derivation —
    /// proven without AWS by building an SPKI tail from a known key.
    #[test]
    fn address_from_spki_matches_key_derivation() {
        // Uncompressed SEC1 point for the known secret, via the LocalSigner.
        let signer = LocalSigner::from_secret(any_secret()).expect("signer");
        let expected = signer.address();
        // Reconstruct the 65-byte point from k256 and wrap it as an SPKI tail.
        use k256::ecdsa::{SigningKey, VerifyingKey};
        let sk = SigningKey::from_bytes((&any_secret()).into()).expect("sk");
        let vk = VerifyingKey::from(&sk);
        let point = vk.to_encoded_point(false); // 0x04 || X || Y
        let mut spki = vec![0x30, 0x59, 0xAB, 0xCD]; // arbitrary SPKI header bytes
        spki.extend_from_slice(point.as_bytes());
        assert_eq!(address_from_spki(&spki).expect("addr"), expected);
    }
}
