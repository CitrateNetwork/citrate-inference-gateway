//! `TokenBasedPricing` — `x402_axum::PricingStrategy` for chat
//! completions and batches. Estimates wei cost from the buffered
//! request body via `ChainQueries::estimate_cost`.
//!
//! Per CM-02 RETRO action item #3: "TokenBasedPricing as the
//! second non-FixedPricing impl. This proves the pricing trait is
//! well-shaped. If it falls short of what the gateway needs, fix
//! the trait now while there's only one implementation."
//!
//! The pricing trait receives a send-safe `Request<Bytes>` view so the
//! middleware can buffer the body once, restore it for the handler, and let
//! this strategy price the exact model and requested output budget.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use ethereum_types::U256;
use http::Request;

use crate::queries::ChainQueries;
use x402_axum::{PricingError, PricingStrategy};

/// Default verification tier. Per `ComputePricingOracle.estimateJobCost`,
/// 0 = Commitment (1.0× multiplier), 1 = ZKProof (1.5×), 2 = TEE (2.0×).
const DEFAULT_TIER: u8 = 0;

/// Default verification tier exposed for handler-side recharge.
pub const DEFAULT_VERIFICATION_TIER: u8 = DEFAULT_TIER;

/// Caller-side input-token assumption. Exposed so the chat handler
/// can recompute the actual cost against the caller's real
/// `max_tokens` value. RM-B1 / WP-D2.4 (audit F-2).
pub const ASSUMED_INPUT_TOKENS: u32 = 256;
const ASSUMED_OUTPUT_TOKENS: u32 = 512;

/// Token-based pricing strategy backed by ComputePricingOracle.
pub struct TokenBasedPricing {
    queries: Arc<dyn ChainQueries>,
    /// Legacy model label retained for constructor compatibility and
    /// diagnostics. Pricing uses the model in the buffered request body.
    default_model: String,
}

impl TokenBasedPricing {
    /// Create with a chain-queries handle and a fallback model name
    /// used only as a diagnostic label; the request body is authoritative.
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
    async fn price_for(&self, request: &Request<axum::body::Bytes>) -> Result<U256, PricingError> {
        let body = request.body();
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
            PricingError::NotPriceable(format!("request body is not valid JSON: {e}"))
        })?;

        if let Ok(chat) =
            serde_json::from_value::<crate::openai::ChatCompletionRequest>(value.clone())
        {
            return self.quote_chat(&chat).await;
        }

        let batch =
            serde_json::from_value::<crate::batch::BatchSubmitRequest>(value).map_err(|e| {
                PricingError::NotPriceable(format!("request shape is not priceable: {e}"))
            })?;
        if batch.requests.is_empty() {
            // Preserve the established x402 flow for structurally valid but
            // handler-invalid requests: issue a challenge, then let the
            // paid handler return its documented 400. Invalid requests must
            // never be settled because the layer settles only after 2xx.
            return self.fallback_quote().await;
        }
        if batch.requests.len() > crate::batch::MAX_BATCH_SIZE {
            return self.fallback_quote().await;
        }
        let distinct_models: HashSet<&str> = batch
            .requests
            .iter()
            .map(|request| request.model.as_str())
            .collect();
        if distinct_models.len() > crate::batch::MAX_DISTINCT_BATCH_MODELS {
            return Err(PricingError::NotPriceable(format!(
                "max {} distinct models per batch (got {})",
                crate::batch::MAX_DISTINCT_BATCH_MODELS,
                distinct_models.len()
            )));
        }

        let mut total = U256::zero();
        for chat in &batch.requests {
            if chat.messages.is_empty()
                || chat
                    .max_tokens
                    .is_some_and(|value| value > crate::chat::max_tokens_ceiling())
            {
                return self.fallback_quote().await;
            }
            total = total
                .checked_add(self.quote_chat(chat).await?)
                .ok_or_else(|| PricingError::NotPriceable("quoted cost overflow".into()))?;
        }
        Ok(total)
    }
}

impl TokenBasedPricing {
    async fn fallback_quote(&self) -> Result<U256, PricingError> {
        let model_hash = self
            .queries
            .resolve_model_name(&self.default_model)
            .await
            .map_err(|e| PricingError::OracleUnavailable(e.to_string()))?;
        self.queries
            .estimate_cost(
                model_hash,
                ASSUMED_INPUT_TOKENS,
                ASSUMED_OUTPUT_TOKENS,
                DEFAULT_TIER,
            )
            .await
            .map_err(|e| PricingError::OracleUnavailable(e.to_string()))
    }

    async fn quote_chat(
        &self,
        request: &crate::openai::ChatCompletionRequest,
    ) -> Result<U256, PricingError> {
        // Keep malformed-but-deserializable chat requests challengeable so
        // the existing x402 contract remains intact; the paid handler then
        // returns its normal 400 without settling. The estimator's floor
        // supplies the bounded quote for an empty message list.
        let model_hash = self
            .queries
            .resolve_model_name(&request.model)
            .await
            .map_err(|e| PricingError::OracleUnavailable(e.to_string()))?;
        let input_tokens = crate::chat::estimate_input_tokens(&request.messages);
        let output_tokens =
            crate::chat::clamp_max_tokens(request.max_tokens, crate::chat::max_tokens_ceiling())
                .unwrap_or(crate::chat::DEFAULT_MAX_TOKENS);
        self.queries
            .estimate_cost(model_hash, input_tokens, output_tokens, DEFAULT_TIER)
            .await
            .map_err(|e| PricingError::OracleUnavailable(e.to_string()))
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
        async fn list_providers(&self, _: H256) -> Result<Vec<ProviderInfo>, GatewayError> {
            Ok(vec![])
        }
    }

    fn request() -> Request<axum::body::Bytes> {
        Request::builder()
            .uri("/v1/chat/completions")
            .body(axum::body::Bytes::from_static(
                br#"{"model":"llama-3.1-8b","messages":[{"role":"user","content":"hi"}]}"#,
            ))
            .expect("req")
    }

    #[tokio::test]
    async fn prices_via_chain_queries() {
        let pricing =
            TokenBasedPricing::new(Arc::new(MockQueries(U256::from(42u64))), "llama-3.1-8b");
        let p = pricing.price_for(&request()).await.expect("price");
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
            async fn list_providers(&self, _: H256) -> Result<Vec<ProviderInfo>, GatewayError> {
                unreachable!()
            }
        }
        let pricing = TokenBasedPricing::new(Arc::new(FailingQueries), "x");
        let err = pricing.price_for(&request()).await.expect_err("fail");
        assert!(matches!(err, PricingError::OracleUnavailable(_)));
    }

    #[test]
    fn _addr_used() {
        // Silence the unused import warning when running with cfg test.
        let _ = H160::zero();
    }
}
