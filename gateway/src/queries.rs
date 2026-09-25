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
use once_cell::sync::Lazy;
use serde::Serialize;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};

use crate::config::ContractAddresses;
use crate::error::GatewayError;

/// PIL-47c: how long a model-name → hash lookup stays valid before we
/// re-enumerate ModelRegistry. New models get registered rarely; 30s is
/// short enough that a freshly-registered model surfaces within one
/// human-noticeable retry, long enough that bursts of chat traffic
/// don't hammer the chain.
const MODEL_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// PIL-47c / IGW-B-007: process-wide cache of name → modelHash, populated
/// lazily on first miss in `resolve_model_name`. `None` values are short-lived
/// negative entries, so repeated unknown names do not re-enumerate the chain.
/// Held under a tokio RwLock so reads are non-blocking when the cache is warm.
/// A cache slot: when it was filled, and what with.
type Cached<T> = RwLock<Option<(std::time::Instant, T)>>;

static MODEL_NAME_CACHE: Lazy<Cached<HashMap<String, Option<H256>>>> =
    Lazy::new(|| RwLock::new(None));

/// IGW-B-007: only one cache refresh may enumerate ModelRegistry at a time.
/// Callers arriving during a refresh re-check the cache after acquiring this
/// guard and observe the result from that refresh.
static MODEL_CACHE_REFRESH_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// IGW-B-007: `/v1/models` is unauthenticated, so retain its complete model
/// listing for the same short TTL and serialize refreshes with name lookups.
static MODEL_LIST_CACHE: Lazy<Cached<Vec<ModelInfo>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedModelLookup {
    Hit(H256),
    Negative,
    Miss,
}

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

/// One model returned by [`ChainQueries::list_models`]. Shape mirrors
/// the subset of `ModelRegistry.getModel(bytes32)` that the gateway's
/// `/v1/models` endpoint needs — name (becomes the OpenAI model id),
/// owner (becomes `owned_by`), and the active flag so callers can
/// filter out deactivated entries.
#[derive(Debug, Clone, Serialize)]
pub struct ModelInfo {
    /// 32-byte on-chain identifier — `keccak256(owner ‖ name ‖
    /// timestamp ‖ nonce)` per `ModelRegistry.sol`.
    pub model_hash: H256,
    /// Human-readable name as registered on chain
    /// (e.g. `"gemma-4-E4B-it-Q4_K_M"`). What SDK callers send back
    /// as the OpenAI `model` field. The gateway's
    /// `resolve_model_name` accepts either this string or a 0x-pinned
    /// hash.
    pub name: String,
    /// EOA that registered the model.
    pub owner: H160,
    /// `false` after the owner has called
    /// `ModelRegistry.updateModelStatus(false)` — caller should skip
    /// inactive entries when populating user-facing model lists.
    pub is_active: bool,
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
    async fn list_providers(&self, model_hash: H256) -> Result<Vec<ProviderInfo>, GatewayError>;

    /// List ComputePool entries that can serve `model_hash` (CM-05
    /// WP-05.4). Default impl returns empty so HttpChainQueries
    /// (which doesn't yet read ComputePool) compiles unchanged; the
    /// real on-chain ABI call lands in WP-05.4 slice 2 alongside
    /// the gateway wallet for `requestPoolCompute` tx submission.
    /// Mock implementations override this to drive integration tests.
    async fn list_pools(&self, _model_hash: H256) -> Result<Vec<PoolEntry>, GatewayError> {
        Ok(Vec::new())
    }

    /// List every model registered on `ModelRegistry`. Powers the
    /// `/v1/models` endpoint so SDK auto-discovery can target
    /// individual models by their human-readable on-chain name.
    ///
    /// Default impl returns empty so existing mock implementations
    /// keep compiling — they can opt in by overriding when they want
    /// to drive `/v1/models` tests.
    async fn list_models(&self) -> Result<Vec<ModelInfo>, GatewayError> {
        Ok(Vec::new())
    }
}

/// One ComputePool entry returned by `list_pools` (CM-05 WP-05.4).
///
/// Pools are scored against individual providers by
/// `pool_score = min_member_reputation_bps × total_stake_grains` so a
/// pool only wins when its weakest member is reputable AND the
/// pool's collective stake is large enough to cover the buyer's
/// risk. See `select_dispatch_target` for the comparison.
#[derive(Debug, Clone, Serialize)]
pub struct PoolEntry {
    /// On-chain ComputePool.pools[poolId].id.
    pub pool_id: u64,
    /// Pool's display name. Surfaced in `/v1/models` prefixed with
    /// `pool-` so SDK users can target it like any other model id.
    pub name: String,
    /// Sum of all members' bonded stake, in grains.
    pub total_stake_grains: U256,
    /// Member count — informational; not used in the score.
    pub member_count: u32,
    /// Minimum across the pool's members. A buyer is exposed to the
    /// weakest member, so this caps the pool's reliability score.
    pub min_member_reputation_bps: u32,
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

    /// PIL-47c: look up `name` in the in-memory model-name cache. Returns
    /// `None` on miss or expiry; the caller is expected to re-populate via
    /// [`Self::refresh_model_cache`]. Positive and negative cache entries are
    /// distinguished so a known miss is not treated as a refresh request.
    async fn cached_model_hash(&self, name: &str) -> CachedModelLookup {
        let guard = MODEL_NAME_CACHE.read().await;
        let Some((fetched_at, map)) = guard.as_ref() else {
            return CachedModelLookup::Miss;
        };
        if fetched_at.elapsed() >= MODEL_CACHE_TTL {
            return CachedModelLookup::Miss;
        }
        match map.get(name) {
            Some(Some(hash)) => CachedModelLookup::Hit(*hash),
            Some(None) => CachedModelLookup::Negative,
            None => CachedModelLookup::Miss,
        }
    }

    /// PIL-47c: replace the cache with a freshly-built map. Holds the
    /// write lock only for the swap.
    async fn refresh_model_cache(&self, name_to_hash: HashMap<String, Option<H256>>) {
        let mut guard = MODEL_NAME_CACHE.write().await;
        *guard = Some((std::time::Instant::now(), name_to_hash));
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
        // Fast path: the caller already pinned the hash. `0x` + 64 hex chars.
        let stripped = name.strip_prefix("0x").unwrap_or(name);
        if stripped.len() == 64 {
            if let Ok(bytes) = hex::decode(stripped) {
                if bytes.len() == 32 {
                    return Ok(H256::from_slice(&bytes));
                }
            }
            // Fell through — looked hashy but didn't decode. Treat as a
            // friendly name and fall through to the ModelRegistry lookup.
        }

        // PIL-47c: bare name path. The on-chain `modelHash` is
        // `keccak256(abi.encodePacked(msg.sender, name, block.timestamp,
        // totalModels))` — not derivable from the name alone. Enumerate
        // the registry instead: `getAllModelHashes()` returns every
        // registered hash, then for each we `getModel(hash)` and match
        // the `name` field.
        //
        // Cached on the gateway side via [`MODEL_NAME_CACHE`] so we don't
        // hammer the chain RPC on every chat request; cache TTL is
        // `MODEL_CACHE_TTL` (30 s). Negative entries are cached too.
        match self.cached_model_hash(name).await {
            CachedModelLookup::Hit(h) => return Ok(h),
            CachedModelLookup::Negative => {
                return Err(GatewayError::UnknownModel(name.to_string()))
            }
            CachedModelLookup::Miss => {}
        }

        // Cache miss or expired — serialize the refresh and re-check after
        // waiting so concurrent callers cannot each enumerate the registry.
        let _refresh_guard = MODEL_CACHE_REFRESH_LOCK.lock().await;
        match self.cached_model_hash(name).await {
            CachedModelLookup::Hit(h) => return Ok(h),
            CachedModelLookup::Negative => {
                return Err(GatewayError::UnknownModel(name.to_string()))
            }
            CachedModelLookup::Miss => {}
        }

        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&selector("getAllModelHashes()"));
        let result = self
            .eth_call(&self.contracts.model_registry, &data)
            .await
            .map_err(|e| GatewayError::UnknownModel(format!("{} ({})", name, e)))?;
        let hashes = decode_bytes32_array(&result)?;

        let mut name_to_hash: HashMap<String, Option<H256>> =
            HashMap::with_capacity(hashes.len() + 1);
        for h in hashes {
            // getModel(bytes32) returns (address, string name, string framework,
            // string version, string ipfsCID, uint256 inferencePrice,
            // uint256 totalInferences, bool isActive). The `name` field sits
            // at word 1's offset in the return tuple.
            let mut data = Vec::with_capacity(36);
            data.extend_from_slice(&selector("getModel(bytes32)"));
            data.extend_from_slice(h.as_bytes());
            let result = match self.eth_call(&self.contracts.model_registry, &data).await {
                Ok(b) => b,
                Err(_) => continue, // skip; one bad model shouldn't break lookup
            };
            if let Ok(model_name) = decode_string_at_offset_word(&result, 1) {
                // Empty name = uninitialized slot (model deleted / never set).
                if !model_name.is_empty() {
                    name_to_hash.insert(model_name, Some(h));
                }
            }
        }

        let resolved = name_to_hash.get(name).copied().flatten();
        if resolved.is_none() {
            name_to_hash.insert(name.to_string(), None);
        }
        self.refresh_model_cache(name_to_hash).await;
        resolved.ok_or_else(|| GatewayError::UnknownModel(name.to_string()))
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

    async fn list_providers(&self, model_hash: H256) -> Result<Vec<ProviderInfo>, GatewayError> {
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

    /// Enumerate every registered model in `ModelRegistry`.
    ///
    /// Implementation walks `getAllModelHashes() -> bytes32[]` then
    /// pulls each model's `name`, `owner`, and `isActive` flag via
    /// `getModel(bytes32)`. Sequential — the registry is small enough
    /// (target: low hundreds of entries at most) that fan-out via
    /// `join_all` would be overkill; revisit if the chain ever has
    /// thousands of registered models per gateway scrape.
    ///
    /// A failed `getModel(hash)` for any individual entry is skipped
    /// (one corrupt entry shouldn't blank out the whole listing). A
    /// failed `getAllModelHashes` bubbles up — the caller decides
    /// whether to surface 503 or degrade to an empty list.
    async fn list_models(&self) -> Result<Vec<ModelInfo>, GatewayError> {
        {
            let guard = MODEL_LIST_CACHE.read().await;
            if let Some((fetched_at, models)) = guard.as_ref() {
                if fetched_at.elapsed() < MODEL_CACHE_TTL {
                    return Ok(models.clone());
                }
            }
        }

        let _refresh_guard = MODEL_CACHE_REFRESH_LOCK.lock().await;
        {
            let guard = MODEL_LIST_CACHE.read().await;
            if let Some((fetched_at, models)) = guard.as_ref() {
                if fetched_at.elapsed() < MODEL_CACHE_TTL {
                    return Ok(models.clone());
                }
            }
        }

        // Step 1: enumerate hashes.
        let mut data = Vec::with_capacity(4);
        data.extend_from_slice(&selector("getAllModelHashes()"));
        let result = self.eth_call(&self.contracts.model_registry, &data).await?;
        let hashes = decode_bytes32_array(&result)?;

        // Step 2: fetch each model's name + owner + isActive.
        // `getModel(bytes32)` returns the 8-tuple:
        //   (address owner, string name, string framework, string version,
        //    string ipfsCID, uint256 inferencePrice, uint256 totalInferences,
        //    bool isActive)
        // Static head = 8 words = 256 bytes. Owner sits at word 0
        // (left-padded address); isActive at word 7 (last byte of the
        // 32-byte word); name's payload offset lives at word 1.
        let mut out = Vec::with_capacity(hashes.len());
        for h in hashes {
            let mut data = Vec::with_capacity(36);
            data.extend_from_slice(&selector("getModel(bytes32)"));
            data.extend_from_slice(h.as_bytes());
            let result = match self.eth_call(&self.contracts.model_registry, &data).await {
                Ok(b) => b,
                Err(_) => continue, // skip the one bad entry, keep the rest
            };
            if result.len() < 256 {
                continue;
            }
            let owner = H160::from_slice(&result[12..32]);
            let name = match decode_string_at_offset_word(&result, 1) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if name.is_empty() {
                continue; // uninitialised slot / deleted model
            }
            // isActive is the bool at word 7 (bytes 224..256); last byte non-zero = true.
            let is_active = result[255] != 0;
            out.push(ModelInfo {
                model_hash: h,
                name,
                owner,
                is_active,
            });
        }
        let mut guard = MODEL_LIST_CACHE.write().await;
        *guard = Some((std::time::Instant::now(), out.clone()));
        Ok(out)
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

/// 2026-05-31 audit -002 (SECREM-02 6.4a): bounded conversion of an
/// attacker-influenced ABI length word. `U256::as_usize()` panics on
/// anything above `usize::MAX`, and even an in-range giant overflows
/// downstream `head + len * unit` arithmetic — so the word is checked
/// against the number of items the actual buffer can hold BEFORE any
/// native-width conversion. Mirrors the hardening already applied to
/// `decode_string_at_offset_word`.
fn abi_len_bounded(word: &[u8], max_items: usize, what: &str) -> Result<usize, GatewayError> {
    let v = U256::from_big_endian(word);
    if v > U256::from(max_items as u64) {
        return Err(GatewayError::ChainUnavailable(format!(
            "{what}: declared length {v} exceeds buffer capacity ({max_items} items)"
        )));
    }
    Ok(v.as_u64() as usize)
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
    // Skip offset (bytes 0..32). Length at bytes 32..64. Bounded by
    // the element count the remaining buffer can actually hold
    // (audit -002: no as_usize, no unchecked `64 + len * 32`).
    let len = abi_len_bounded(&bytes[32..64], (bytes.len() - 64) / 32, "address[]")?;
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

/// PIL-47c: ABI-decode a `bytes32[]` return tuple. Layout:
/// `[offset_word=0x20, length, b0, b1, ...]` (each 32 bytes).
fn decode_bytes32_array(bytes: &[u8]) -> Result<Vec<H256>, GatewayError> {
    if bytes.len() < 64 {
        return Err(GatewayError::ChainUnavailable(format!(
            "bytes32[] return too short: {} bytes",
            bytes.len()
        )));
    }
    // Audit -002: bounded conversion — see `abi_len_bounded`.
    let len = abi_len_bounded(&bytes[32..64], (bytes.len() - 64) / 32, "bytes32[]")?;
    let expected = 64 + len * 32;
    if bytes.len() < expected {
        return Err(GatewayError::ChainUnavailable(format!(
            "bytes32[] truncated: said len={} need {} have {}",
            len,
            expected,
            bytes.len()
        )));
    }
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let start = 64 + i * 32;
        out.push(H256::from_slice(&bytes[start..start + 32]));
    }
    Ok(out)
}

/// PIL-47c: ABI-decode the dynamic `string` sitting at the `word_idx`-th
/// word of a returndata tuple. The word at `word_idx * 32` contains the
/// *offset* (relative to the start of returndata) to the string's
/// length-prefixed payload.
///
/// Used to pull the `name` field out of `ModelRegistry.getModel(...)`'s
/// 8-tuple return without decoding the whole struct.
fn decode_string_at_offset_word(bytes: &[u8], word_idx: usize) -> Result<String, GatewayError> {
    let off_start = word_idx * 32;
    if bytes.len() < off_start + 32 {
        return Err(GatewayError::ChainUnavailable(format!(
            "string-at-word: offset word {} out of range ({} bytes)",
            word_idx,
            bytes.len()
        )));
    }
    // Guard against giant offsets: U256::as_usize() panics on overflow,
    // so route through a bounded conversion.
    let offset_u256 = U256::from_big_endian(&bytes[off_start..off_start + 32]);
    let offset = usize::try_from(offset_u256.low_u128())
        .ok()
        // Reject anything that doesn't fit in the low 64 bits — no
        // ABI string offset will exceed the buffer length anyway.
        .filter(|_| offset_u256 <= U256::from(u64::MAX))
        .ok_or_else(|| {
            GatewayError::ChainUnavailable(format!(
                "string-at-word: offset overflows usize at word {}",
                word_idx
            ))
        })?;
    if bytes.len() < offset.saturating_add(32) || bytes.len() < offset + 32 {
        return Err(GatewayError::ChainUnavailable(format!(
            "string-at-word: length at {} out of range ({} bytes)",
            offset,
            bytes.len()
        )));
    }
    let len_u256 = U256::from_big_endian(&bytes[offset..offset + 32]);
    let len = if len_u256 > U256::from(u32::MAX) {
        return Err(GatewayError::ChainUnavailable(format!(
            "string-at-word: declared length too large ({:?})",
            len_u256
        )));
    } else {
        len_u256.as_u64() as usize
    };
    if bytes.len() < offset + 32 + len {
        return Err(GatewayError::ChainUnavailable(format!(
            "string-at-word: declared {} bytes at offset {}, have {}",
            len,
            offset + 32,
            bytes.len()
        )));
    }
    String::from_utf8(bytes[offset + 32..offset + 32 + len].to_vec())
        .map_err(|e| GatewayError::ChainUnavailable(format!("non-utf8 string: {}", e)))
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

    // Audit -002: bounded conversion — see `abi_len_bounded`. The
    // endpoint string can occupy at most the bytes after the 192-byte
    // static head.
    let str_len = abi_len_bounded(&bytes[160..192], bytes.len() - 192, "provider endpoint")?;
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

    /// PIL-47c: `bytes32[]` is one tighter than `address[]` (no
    /// padding within each element). Round-trip a 3-element array.
    #[test]
    fn decode_bytes32_array_three_hashes() {
        let mut buf = vec![0u8; 32 + 32 + 3 * 32];
        buf[31] = 0x20; // offset
        buf[63] = 3; // length
        buf[64..96].copy_from_slice(&[0xaa; 32]);
        buf[96..128].copy_from_slice(&[0xbb; 32]);
        buf[128..160].copy_from_slice(&[0xcc; 32]);
        let hashes = decode_bytes32_array(&buf).expect("decode");
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0], H256::from([0xaa; 32]));
        assert_eq!(hashes[2], H256::from([0xcc; 32]));
    }

    #[test]
    fn decode_bytes32_array_rejects_truncated() {
        // length says 2 but we only have 1 element
        let mut buf = vec![0u8; 96];
        buf[31] = 0x20;
        buf[63] = 2;
        let err = decode_bytes32_array(&buf).expect_err("should fail");
        assert!(matches!(err, GatewayError::ChainUnavailable(_)));
    }

    /// PIL-47c: pull the `name` string out of a fake `getModel(bytes32)`
    /// return tuple where word 1 points at the name's payload.
    #[test]
    fn decode_string_at_offset_word_extracts_name() {
        // Pretend layout: word 0 = address, word 1 = offset to name,
        // word 2..N = other static fields filled with zeros, then name.
        // Static head = 8 words (address + 4 string-offsets + 3 statics
        // = 8 × 32 = 256 bytes). Name string offset = 0x100 (256).
        let name = "gemma-4-E4B-it-Q4_K_M";
        let mut buf = vec![0u8; 256];
        // word 1: offset to name = 256 (0x100)
        buf[32 + 30] = 0x01;
        buf[32 + 31] = 0x00;
        // length-prefixed name at offset 256
        let mut len_word = [0u8; 32];
        len_word[31] = name.len() as u8;
        buf.extend_from_slice(&len_word);
        // Pad name to multiple of 32 bytes
        let mut name_bytes = name.as_bytes().to_vec();
        while !name_bytes.len().is_multiple_of(32) {
            name_bytes.push(0);
        }
        buf.extend_from_slice(&name_bytes);

        let decoded = decode_string_at_offset_word(&buf, 1).expect("decode");
        assert_eq!(decoded, name);
    }

    #[test]
    fn decode_string_at_offset_word_rejects_out_of_range_offset() {
        // Offset word points way past the buffer.
        let mut buf = vec![0u8; 64];
        buf[32..64].copy_from_slice(&[0xff; 32]);
        let err = decode_string_at_offset_word(&buf, 1).expect_err("should fail");
        assert!(matches!(err, GatewayError::ChainUnavailable(_)));
    }

    // ── 2026-05-31 audit -002 (SECREM-02 6.4a) ──────────────────
    // ABI length words come from whatever contract the gateway
    // eth_calls — attacker-influenced on a malicious/compromised RPC
    // or a hostile registry entry. A length word > usize::MAX made
    // `U256::as_usize()` panic (DoS); even in-range giants overflowed
    // the `64 + len * 32` arithmetic. All three decoders must return
    // an error, never panic.

    #[test]
    fn hostile_address_array_length_word_errors_not_panics() {
        // offset + length word of all 0xff (≫ usize::MAX).
        let mut buf = vec![0u8; 64];
        buf[31] = 0x20;
        buf[32..64].copy_from_slice(&[0xff; 32]);
        let err = decode_address_array(&buf).expect_err("hostile length must error");
        assert!(matches!(err, GatewayError::ChainUnavailable(_)));
    }

    #[test]
    fn hostile_address_array_length_overflowing_expected_errors() {
        // Length fits in u64 but 64 + len*32 overflows usize.
        let mut buf = vec![0u8; 64];
        buf[31] = 0x20;
        // len = 2^60
        buf[63 - 7] = 0x10;
        let err = decode_address_array(&buf).expect_err("overflowing length must error");
        assert!(matches!(err, GatewayError::ChainUnavailable(_)));
    }

    #[test]
    fn hostile_bytes32_array_length_word_errors_not_panics() {
        let mut buf = vec![0u8; 64];
        buf[31] = 0x20;
        buf[32..64].copy_from_slice(&[0xff; 32]);
        let err = decode_bytes32_array(&buf).expect_err("hostile length must error");
        assert!(matches!(err, GatewayError::ChainUnavailable(_)));
    }

    #[test]
    fn hostile_provider_info_string_length_errors_not_panics() {
        // Well-formed 192-byte static head, then a hostile endpoint
        // length word of all 0xff.
        let mut buf = vec![0u8; 192];
        buf[31] = 0xa0; // endpoint offset = 160
        buf[160..192].copy_from_slice(&[0xff; 32]);
        let res = decode_provider_info(H160::from([0x11; 20]), &buf);
        assert!(
            matches!(res, Err(GatewayError::ChainUnavailable(_))),
            "hostile endpoint length must error"
        );
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
        let hash = "0xabababababababababababababababababababababababababababababababab";
        let h = q.resolve_model_name(hash).await.expect("ok");
        assert_eq!(h.as_bytes(), &[0xab; 32]);
    }

    #[tokio::test]
    async fn resolve_model_name_rejects_bare_name() {
        let q = HttpChainQueries::new("http://unused", ContractAddresses::default());
        let err = q
            .resolve_model_name("llama-3.1-8b")
            .await
            .expect_err("fail");
        assert!(matches!(err, GatewayError::UnknownModel(_)));
    }

    #[tokio::test]
    async fn resolve_model_name_rejects_short_hex() {
        let q = HttpChainQueries::new("http://unused", ContractAddresses::default());
        let err = q.resolve_model_name("0xdeadbeef").await.expect_err("fail");
        assert!(matches!(err, GatewayError::UnknownModel(_)));
    }
}
