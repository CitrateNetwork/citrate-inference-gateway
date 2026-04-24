//! Chain-query trait abstracting the read-only RPC calls the
//! gateway needs.
//!
//! Three operations:
//! 1. `resolve_model_name` — name → modelHash via ModelRegistry
//! 2. `estimate_cost` — token + tier → wei via ComputePricingOracle
//! 3. `list_providers` — modelHash → registered providers via
//!    InferenceRouter
//!
//! Default `HttpChainQueries` impl backed by reqwest is wired in
//! `build_router` for production. Tests inject `MockChainQueries`
//! to drive the gateway without a live chain.

use async_trait::async_trait;
use ethereum_types::{H160, H256, U256};
use serde::Serialize;

use crate::error::GatewayError;

/// One provider listing returned by `list_providers`.
///
/// `endpoint` is the HTTPS URL the gateway POSTs to (per the
/// upcoming Provider Protocol v1 ADR). `current_load` /
/// `max_concurrent` come from `ComputeMarketplace.providers`'s
/// `currentActiveJobs` / `maxConcurrentJobs` fields.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    /// On-chain provider address (the EVM-style 20-byte form).
    pub address: H160,
    /// HTTPS endpoint URL the gateway dispatches to.
    pub endpoint: String,
    /// Reputation in basis points (10000 = 100%).
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
    /// Resolve a model name (e.g. "llama-3.1-8b") or a pinned
    /// hash (e.g. "llama-3.1-8b@0xabcd...") to its on-chain
    /// modelHash. Returns `UnknownModel` if neither resolves.
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

/// Reqwest-backed default. Wired in production builds; tests
/// inject `MockChainQueries`.
///
/// WP-03.2 ships a STUB that errors on every method — sufficient
/// to satisfy `Arc<dyn ChainQueries>` plumbing. The real ABI
/// encode + eth_call wiring lands in WP-03.2's follow-up commit
/// (or WP-03.3, whichever needs live chain queries first). Until
/// then, production gateway runs are gated by integration tests
/// that always inject a mock.
pub struct HttpChainQueries {
    #[allow(dead_code)]
    rpc_url: String,
    #[allow(dead_code)]
    chain_id: u64,
    #[allow(dead_code)]
    http: reqwest::Client,
}

impl HttpChainQueries {
    /// Construct with a JSON-RPC URL.
    pub fn new(rpc_url: impl Into<String>, chain_id: u64) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            chain_id,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl ChainQueries for HttpChainQueries {
    async fn resolve_model_name(&self, name: &str) -> Result<H256, GatewayError> {
        Err(GatewayError::ChainUnavailable(format!(
            "HttpChainQueries::resolve_model_name not yet wired (WP-03.2 follow-up); name = {}",
            name
        )))
    }

    async fn estimate_cost(
        &self,
        _model_hash: H256,
        _input_tokens: u32,
        _output_tokens: u32,
        _tier: u8,
    ) -> Result<U256, GatewayError> {
        Err(GatewayError::ChainUnavailable(
            "HttpChainQueries::estimate_cost not yet wired (WP-03.2 follow-up)".into(),
        ))
    }

    async fn list_providers(
        &self,
        _model_hash: H256,
    ) -> Result<Vec<ProviderInfo>, GatewayError> {
        Err(GatewayError::ChainUnavailable(
            "HttpChainQueries::list_providers not yet wired (WP-03.2 follow-up)".into(),
        ))
    }
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
        assert_eq!(p.capacity_remaining(), 0); // saturating
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
}
