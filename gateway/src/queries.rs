//! Chain-query trait abstracting the read-only RPC calls the
//! gateway needs.
//!
//! Three operations:
//! 1. `resolve_model_name` — name → modelHash via ModelRegistry
//!    (v1: pinned hash only; name-registry off-chain is future work)
//! 2. `estimate_cost` — token + tier → wei via ComputePricingOracle
//! 3. `list_providers` — modelHash → registered providers via
//!    InferenceRouter
//!
//! Default `HttpChainQueries` impl backed by reqwest + hand-rolled
//! ABI encode/decode. Tests inject `MockChainQueries` to drive the
//! gateway without a live chain.

use async_trait::async_trait;
use ethereum_types::{H160, H256, U256};
use serde::Serialize;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

use crate::config::ContractAddresses;
use crate::error::GatewayError;

/// One provider listing returned by `list_providers`.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    /// On-chain provider address (the EVM-style 20-byte form).
    pub address: H160,
    /// HTTPS endpoint URL the gateway dispatches to.
    pub endpoint: String,
    /// Reputation in basis points (10000 = 100%). InferenceRouter
    /// doesn't surface this directly today, so the HTTP impl
    /// computes a stable proxy from `(totalInferences, isActive)`.
    pub reputation_bps: u32,
    /// Current active jobs.
    pub current_load: u32,
    /// Configured cap.
    pub max_concurrent: u32,
}

impl ProviderInfo {
    /// Capacity headroom — `max_concurrent - current_load`. Used by
    /// the selector to filter out at-capacity providers.
    pub fn capacity_remaining(&self) -> u32 {
        self.max_concurrent.saturating_sub(self.current_load)
    }
}

/// Read-only chain queries.
#[async_trait]
pub trait ChainQueries: Send + Sync {
    /// Resolve a model identifier to its on-chain modelHash.
    ///
    /// v1 accepts only a pinned hex hash (0x-prefixed, 32 bytes).
    /// On-chain ModelRegistry doesn't expose a name→hash lookup
    /// (the hash is `keccak256(creator || name || timestamp ||
    /// nonce)` per ModelRegistry.sol:109-116, so it's not derivable
    /// from name alone). A future off-chain name registry — or an
    /// on-chain `getModelByName` view — will close the gap.
    async fn resolve_model_name(&self, name: &str) -> Result<H256, GatewayError>;

    /// Estimate the SALT cost (in wei) for a job with the given
    /// token counts and verification tier. Calls
    /// `ComputePricingOracle.estimateJobCost`.
    async fn estimate_cost(
        &self,
        model_hash: H256,
        input_tokens: u32,
        output_tokens: u32,
        tier: u8,
    ) -> Result<U256, GatewayError>;

    /// List providers registered for the given model. Empty vec
    /// (NOT an error) when no providers are registered — the
    /// caller decides what to do.
    async fn list_providers(
        &self,
        model_hash: H256,
    ) -> Result<Vec<ProviderInfo>, GatewayError>;
}

// ── HttpChainQueries — real ABI calls via eth_call ───────────────

/// Reqwest-backed default. Talks to a JSON-RPC endpoint via
/// `eth_call` for each query.
pub struct HttpChainQueries {
    rpc_url: String,
    contracts: ContractAddresses,
    http: reqwest::Client,
}

impl HttpChainQueries {
    /// Construct with a JSON-RPC URL + the contract address book.
    pub fn new(rpc_url: impl Into<String>, contracts: ContractAddresses) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            contracts,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
        }
    }

    async fn eth_call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>, GatewayError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [
                { "to": to, "data": format!("0x{}", hex::encode(data)) },
                "latest"
            ],
            "id": 1,
        });
        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| GatewayError::ChainUnavailable(format!("rpc transport: {}", e)))?;
        let value: Value = resp
            .json()
            .await
            .map_err(|e| GatewayError::ChainUnavailable(format!("rpc decode: {}", e)))?;
        if let Some(err) = value.get("error") {
            return Err(GatewayError::ChainUnavailable(format!(
                "rpc error: {}",
                err
            )));
        }
        let hex_str = value
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GatewayError::ChainUnavailable("rpc missing result".into()))?;
        hex::decode(hex_str.trim_start_matches("0x"))
            .map_err(|e| GatewayError::ChainUnavailable(format!("bad hex: {}", e)))
    }
}

#[async_trait]
impl ChainQueries for HttpChainQueries {
    async fn resolve_model_name(&self, name: &str) -> Result<H256, GatewayError> {
        // v1: only pinned hash form — `0x` + 64 hex chars.
        let stripped = name.strip_prefix("0x").unwrap_or(name);
        if stripped.len() != 64 {
            return Err(GatewayError::UnknownModel(format!(
                "{} (v1 requires pinned hex hash; bare names not yet supported)",
                name
            )));
        }
        let bytes = hex::decode(stripped)
            .map_err(|_| GatewayError::UnknownModel(name.to_string()))?;
        if bytes.len() != 32 {
            return Err(GatewayError::UnknownModel(name.to_string()));
        }
        Ok(H256::from_slice(&bytes))
    }

    async fn estimate_cost(
        &self,
        model_hash: H256,
        input_tokens: u32,
        output_tokens: u32,
        tier: u8,
    ) -> Result<U256, GatewayError> {
        // estimateJobCost(bytes32,uint256,uint256,uint8) — 4 + 4*32 = 132 bytes
        let mut data = Vec::with_capacity(132);
        data.extend_from_slice(&selector("estimateJobCost(bytes32,uint256,uint256,uint8)"));
        data.extend_from_slice(model_hash.as_bytes());
        data.extend_from_slice(&u256_word(U256::from(input_tokens)));
        data.extend_from_slice(&u256_word(U256::from(output_tokens)));
        // uint8 right-padded to 32 bytes
        let mut tier_word = [0u8; 32];
        tier_word[31] = tier;
        data.extend_from_slice(&tier_word);

        let result = self.eth_call(&self.contracts.pricing_oracle, &data).await?;
        if result.len() != 32 {
            return Err(GatewayError::PricingUnavailable(format!(
                "expected 32-byte uint256, got {} bytes",
                result.len()
            )));
        }
        Ok(U256::from_big_endian(&result))
    }

    async fn list_providers(
        &self,
        model_hash: H256,
    ) -> Result<Vec<ProviderInfo>, GatewayError> {
        // Step 1: getProviders(bytes32) -> address[]
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&selector("getProviders(bytes32)"));
        data.extend_from_slice(model_hash.as_bytes());
        let result = self
            .eth_call(&self.contracts.inference_router, &data)
            .await?;
        let addrs = decode_address_array(&result)?;

        // Step 2: getProviderInfo per address. Sequential to keep
        // the implementation simple; v2 can parallelize via
        // join_all if N providers per model gets large.
        let mut providers = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let mut data = Vec::with_capacity(36);
            data.extend_from_slice(&selector("getProviderInfo(address)"));
            data.extend_from_slice(&pad_address_left(addr));
            let result = self
                .eth_call(&self.contracts.inference_router, &data)
                .await?;
            let info = decode_provider_info(addr, &result)?;
            // Filter out inactive providers — they shouldn't be
            // candidates for dispatch.
            if info.is_active {
                providers.push(info.into_provider_info());
            }
        }
        Ok(providers)
    }
}

// ── ABI helpers (private) ────────────────────────────────────────

fn selector(sig: &str) -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(sig.as_bytes());
    let out = h.finalize();
    [out[0], out[1], out[2], out[3]]
}

fn u256_word(v: U256) -> [u8; 32] {
    let mut buf = [0u8; 32];
    v.to_big_endian(&mut buf);
    buf
}

fn pad_address_left(addr: H160) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr.as_bytes());
    buf
}

/// Decode a `address[]` ABI return: 32-byte offset (always 0x20)
/// + 32-byte length + N × 32-byte left-padded addresses.
fn decode_address_array(bytes: &[u8]) -> Result<Vec<H160>, GatewayError> {
    if bytes.len() < 64 {
        // 32 (offset) + 32 (length) minimum
        return Err(GatewayError::ChainUnavailable(format!(
            "address[] return too short: {} bytes",
            bytes.len()
        )));
    }
    // Skip offset (bytes 0..32). Length at bytes 32..64.
    let len_bytes = &bytes[32..64];
    let len = U256::from_big_endian(len_bytes).as_usize();
    let expected = 64 + len * 32;
    if bytes.len() < expected {
        return Err(GatewayError::ChainUnavailable(format!(
            "address[] truncated: said len={} need {} bytes have {}",
            len,
            expected,
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let start = 64 + i * 32;
        let word = &bytes[start..start + 32];
        // Address is the last 20 bytes of the 32-byte word.
        out.push(H160::from_slice(&word[12..32]));
    }
    Ok(out)
}

/// Intermediate decode struct for `getProviderInfo` return.
struct ProviderInfoRaw {
    address: H160,
    endpoint: String,
    #[allow(dead_code)]
    stake: U256,
    current_load: u32,
    #[allow(dead_code)]
    total_inferences: U256,
    is_active: bool,
}

impl ProviderInfoRaw {
    fn into_provider_info(self) -> ProviderInfo {
        ProviderInfo {
            address: self.address,
            endpoint: self.endpoint,
            // InferenceRouter doesn't expose explicit reputation;
            // proxy: active providers get 5000 bps baseline. Future
            // sprint can pull a real reputation from
            // ContributionAccounting or a dedicated registry.
            reputation_bps: if self.is_active { 5000 } else { 0 },
            current_load: self.current_load,
            // No max_concurrent on InferenceRouter; pick a sane
            // default that capacity_remaining can subtract from.
            // Future: read from a per-provider config or add the
            // field to InferenceRouter.
            max_concurrent: 100,
        }
    }
}

/// Decode `(string endpoint, uint256 stake, uint256 currentLoad,
/// uint256 totalInferences, bool isActive)` ABI tuple return.
///
/// ABI layout for tuple with one dynamic field:
///   [0..32]   endpoint offset (= 0xa0 = 160 = 5 * 32)
///   [32..64]  stake
///   [64..96]  currentLoad
///   [96..128] totalInferences
///   [128..160] isActive (bool padded to 32)
///   [160..192] endpoint length
///   [192..]    endpoint bytes (padded to 32-byte alignment)
fn decode_provider_info(addr: H160, bytes: &[u8]) -> Result<ProviderInfoRaw, GatewayError> {
    if bytes.len() < 192 {
        return Err(GatewayError::ChainUnavailable(format!(
            "provider info return too short: {} bytes",
            bytes.len()
        )));
    }
    let stake = U256::from_big_endian(&bytes[32..64]);
    let current_load_u256 = U256::from_big_endian(&bytes[64..96]);
    let total_inferences = U256::from_big_endian(&bytes[96..128]);
    let is_active = bytes[159] != 0;

    let str_len = U256::from_big_endian(&bytes[160..192]).as_usize();
    if bytes.len() < 192 + str_len {
        return Err(GatewayError::ChainUnavailable(format!(
            "endpoint string truncated: declared {} bytes, have {}",
            str_len,
            bytes.len() - 192
        )));
    }
    let endpoint = String::from_utf8(bytes[192..192 + str_len].to_vec())
        .map_err(|e| GatewayError::ChainUnavailable(format!("non-utf8 endpoint: {}", e)))?;

    // Clamp current_load to u32 — provider with > 4B active jobs
    // is not realistic.
    let current_load = if current_load_u256 > U256::from(u32::MAX) {
        u32::MAX
    } else {
        current_load_u256.as_u32()
    };

    Ok(ProviderInfoRaw {
        address: addr,
        endpoint,
        stake,
        current_load,
        total_inferences,
        is_active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_remaining_handles_underflow() {
        let p = ProviderInfo {
            address: H160::zero(),
            endpoint: "http://x".into(),
            reputation_bps: 0,
            current_load: 100,
            max_concurrent: 10,
        };
        assert_eq!(p.capacity_remaining(), 0);
    }

    #[test]
    fn capacity_remaining_normal() {
        let p = ProviderInfo {
            address: H160::zero(),
            endpoint: "http://x".into(),
            reputation_bps: 0,
            current_load: 3,
            max_concurrent: 10,
        };
        assert_eq!(p.capacity_remaining(), 7);
    }

    #[test]
    fn selector_is_keccak_first_4_bytes() {
        let s = selector("getProviders(bytes32)");
        // keccak256("getProviders(bytes32)")[0..4] — verifiable
        // against `cast sig "getProviders(bytes32)"` if needed.
        assert_eq!(s.len(), 4);
        // Determinism check.
        assert_eq!(s, selector("getProviders(bytes32)"));
        // And it must DIFFER from a similar but wrong sig.
        assert_ne!(s, selector("getProviders(bytes16)"));
    }

    #[test]
    fn pad_address_left_zeros_high_12() {
        let a = H160::from([0x42; 20]);
        let p = pad_address_left(a);
        assert!(p[..12].iter().all(|&b| b == 0));
        assert_eq!(&p[12..32], &[0x42u8; 20]);
    }

    #[test]
    fn decode_address_array_empty() {
        // offset (32) + length=0 (32) = 64 bytes total
        let mut buf = vec![0u8; 64];
        buf[31] = 0x20; // offset = 0x20
        let addrs = decode_address_array(&buf).expect("decode");
        assert!(addrs.is_empty());
    }

    #[test]
    fn decode_address_array_two_addresses() {
        // offset (32) + length=2 (32) + 2 × 32 (addrs) = 128 bytes
        let mut buf = vec![0u8; 128];
        buf[31] = 0x20; // offset
        buf[63] = 2; // length
        // First addr 0xaa…aa in last 20 bytes of word at [64..96]
        buf[64 + 12..64 + 32].copy_from_slice(&[0xaa; 20]);
        // Second addr 0xbb…bb in last 20 bytes of word at [96..128]
        buf[96 + 12..96 + 32].copy_from_slice(&[0xbb; 20]);
        let addrs = decode_address_array(&buf).expect("decode");
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], H160::from([0xaa; 20]));
        assert_eq!(addrs[1], H160::from([0xbb; 20]));
    }

    #[test]
    fn decode_address_array_rejects_truncated() {
        // length says 2 but we only provided 1 word
        let mut buf = vec![0u8; 96];
        buf[31] = 0x20;
        buf[63] = 2;
        let err = decode_address_array(&buf).expect_err("should fail");
        assert!(matches!(err, GatewayError::ChainUnavailable(_)));
    }

    #[test]
    fn decode_provider_info_round_trip() {
        // Build a fake getProviderInfo return.
        // Layout: offset(32)=0xa0 + stake(32) + load(32) +
        //         total(32) + isActive(32) + len(32) + bytes
        let endpoint = "https://provider.example/infer";
        let mut buf = vec![0u8; 192];
        buf[31] = 0xa0; // offset to dynamic string
                        // stake = 100
        buf[63] = 100;
        // load = 3
        buf[95] = 3;
        // total = 5
        buf[127] = 5;
        // isActive = true
        buf[159] = 1;
        // length
        buf[191] = endpoint.len() as u8;
        // append string bytes
        buf.extend_from_slice(endpoint.as_bytes());
        // pad to 32-byte alignment
        let pad = (32 - (endpoint.len() % 32)) % 32;
        buf.extend(std::iter::repeat_n(0u8, pad));

        let info = decode_provider_info(H160::from([0xaa; 20]), &buf).expect("decode");
        assert_eq!(info.endpoint, endpoint);
        assert_eq!(info.current_load, 3);
        assert_eq!(info.stake, U256::from(100u64));
        assert_eq!(info.total_inferences, U256::from(5u64));
        assert!(info.is_active);
    }

    #[tokio::test]
    async fn resolve_model_name_accepts_pinned_hash() {
        let q = HttpChainQueries::new("http://unused", ContractAddresses::default());
        let hash =
            "0xabababababababababababababababababababababababababababababababab";
        let h = q.resolve_model_name(hash).await.expect("ok");
        assert_eq!(h.as_bytes(), &[0xab; 32]);
    }

    #[tokio::test]
    async fn resolve_model_name_rejects_bare_name() {
        let q = HttpChainQueries::new("http://unused", ContractAddresses::default());
        let err = q.resolve_model_name("llama-3.1-8b").await.expect_err("fail");
        assert!(matches!(err, GatewayError::UnknownModel(_)));
    }

    #[tokio::test]
    async fn resolve_model_name_rejects_short_hex() {
        let q = HttpChainQueries::new("http://unused", ContractAddresses::default());
        let err = q.resolve_model_name("0xdeadbeef").await.expect_err("fail");
        assert!(matches!(err, GatewayError::UnknownModel(_)));
    }
}
