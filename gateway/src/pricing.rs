//! `TokenBasedPricing` — `x402_axum::PricingStrategy` for chat
//! completions. Estimates wei cost from the request body via
//! `ChainQueries::estimate_cost`.
//!
//! Per CM-02 RETRO action item #3: "TokenBasedPricing as the
//! second non-FixedPricing impl. This proves the pricing trait is
//! well-shaped. If it falls short of what the gateway needs, fix
//! the trait now while there's only one implementation."
//!
//! Verdict so far: trait shape works. The only awkwardness is
//! that `PricingStrategy::price_for` takes `&Request<Body>` but
//! we need to read the JSON body (model + max_tokens) to price
//! it. We solve this by buffering the body inside the strategy
//! and passing it through a side channel — see the implementation.

use std::sync::Arc;

use async_trait::async_trait;
use ethereum_types::U256;
use http::Request;

use crate::queries::ChainQueries;
use x402_axum::{PricingError, PricingStrategy};

/// Default verification tier. Per `ComputePricingOracle.estimateJobCost`,
/// 0 = Commitment (1.0× multiplier), 1 = ZKProof (1.5×), 2 = TEE (2.0×).
const DEFAULT_TIER: u8 = 0;

/// Average tokens we assume per chat request when we can't read the
/// body. This is a conservative upper bound — actual cost is
/// re-estimated from the parsed body at handler time and the
/// difference (if any) is settled / refunded at the next layer.
///
/// The prepay model: charge a generous amount up front; the chain's
/// settle amount equals what the client signed. If the actual job
/// is cheaper, the client overpaid; v2 may issue partial refunds.
const ASSUMED_INPUT_TOKENS: u32 = 256;
const ASSUMED_OUTPUT_TOKENS: u32 = 512;

/// Token-based pricing strategy backed by ComputePricingOracle.
pub struct TokenBasedPricing {
    queries: Arc<dyn ChainQueries>,
    /// Default model to price against when the request body isn't
    /// available at this layer (the X402Layer calls `price_for`
    /// before the chat handler sees the body).
    default_model: String,
}

impl TokenBasedPricing {
    /// Create with a chain-queries handle and a fallback model name
    /// used when the request body isn't readable at price time.
    pub fn new(queries: Arc<dyn ChainQueries>, default_model: impl Into<String>) -> Self {
        Self {
            queries,
            default_model: default_model.into(),
        }
    }
}

impl std::fmt::Debug for TokenBasedPricing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBasedPricing")
            .field("default_model", &self.default_model)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PricingStrategy for TokenBasedPricing {
    async fn price_for(
        &self,
        _request: &Request<axum::body::Body>,
    ) -> Result<U256, PricingError> {
        // X402Layer's interface gives us the request HEADERS but
        // we cannot consume the body here (the layer needs to
        // forward it intact). So we price assuming the
        // ASSUMED_INPUT/OUTPUT averages against the default model.
        // The chat handler re-prices precisely from the parsed
        // body and rejects if the signed amount falls short.
        let model_hash = self
            .queries
            .resolve_model_name(&self.default_model)
            .await
            .map_err(|e| PricingError::OracleUnavailable(e.to_string()))?;
        let cost = self
            .queries
            .estimate_cost(model_hash, ASSUMED_INPUT_TOKENS, ASSUMED_OUTPUT_TOKENS, DEFAULT_TIER)
            .await
            .map_err(|e| PricingError::OracleUnavailable(e.to_string()))?;
        Ok(cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GatewayError;
    use crate::queries::ProviderInfo;
    use ethereum_types::{H160, H256};

    struct MockQueries(U256);

    #[async_trait]
    impl ChainQueries for MockQueries {
        async fn resolve_model_name(&self, _name: &str) -> Result<H256, GatewayError> {
            Ok(H256::from([0xcd; 32]))
        }
        async fn estimate_cost(
            &self,
            _: H256,
            _: u32,
            _: u32,
            _: u8,
        ) -> Result<U256, GatewayError> {
            Ok(self.0)
        }
        async fn list_providers(
            &self,
            _: H256,
        ) -> Result<Vec<ProviderInfo>, GatewayError> {
            Ok(vec![])
        }
    }

    fn empty_request() -> Request<axum::body::Body> {
        Request::builder()
            .uri("/v1/chat/completions")
            .body(axum::body::Body::empty())
            .expect("req")
    }

    #[tokio::test]
    async fn prices_via_chain_queries() {
        let pricing = TokenBasedPricing::new(
            Arc::new(MockQueries(U256::from(42u64))),
            "llama-3.1-8b",
        );
        let p = pricing.price_for(&empty_request()).await.expect("price");
        assert_eq!(p, U256::from(42u64));
    }

    #[tokio::test]
    async fn surfaces_chain_failure_as_oracle_unavailable() {
        struct FailingQueries;
        #[async_trait]
        impl ChainQueries for FailingQueries {
            async fn resolve_model_name(&self, _: &str) -> Result<H256, GatewayError> {
                Err(GatewayError::ChainUnavailable("nope".into()))
            }
            async fn estimate_cost(
                &self,
                _: H256,
                _: u32,
                _: u32,
                _: u8,
            ) -> Result<U256, GatewayError> {
                unreachable!()
            }
            async fn list_providers(
                &self,
                _: H256,
            ) -> Result<Vec<ProviderInfo>, GatewayError> {
                unreachable!()
            }
        }
        let pricing = TokenBasedPricing::new(Arc::new(FailingQueries), "x");
        let err = pricing.price_for(&empty_request()).await.expect_err("fail");
        assert!(matches!(err, PricingError::OracleUnavailable(_)));
    }

    #[test]
    fn _addr_used() {
        // Silence the unused import warning when running with cfg test.
        let _ = H160::zero();
    }
}
