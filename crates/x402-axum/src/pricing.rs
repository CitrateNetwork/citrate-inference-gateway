//! Pricing strategies: how much wei the server charges per request.
//!
//! A [`PricingStrategy`] maps an incoming [`http::Request`] to a wei
//! amount. Keeping pricing pluggable lets the same `X402Layer` serve
//! a gateway that prices per-token, a paywall that prices per-path,
//! or a demo service with a flat rate.
//!
//! The CM-03 Batch Inference Gateway will provide a
//! `TokenBasedPricing` that calls `ComputePricingOracle.estimateJobCost`.
//! For this scaffold we ship only the trivial flat-rate strategy.

use async_trait::async_trait;
use ethereum_types::U256;
use thiserror::Error;

/// Errors a pricing strategy can raise.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PricingError {
    /// The request is structurally unpriceable (wrong method, wrong
    /// path, missing required field). Server responds 400, not 402.
    #[error("request not priceable: {0}")]
    NotPriceable(String),

    /// Pricing oracle unreachable or returned stale data.
    #[error("oracle unavailable: {0}")]
    OracleUnavailable(String),
}

/// Trait for things that can tell the layer what a request costs.
///
/// Implementors should be cheap on the happy path — this is called
/// once per request before any payment parsing. Heavy work (oracle
/// calls, per-model cost estimation) should be cached at the
/// strategy level, not recomputed per invocation.
#[async_trait]
pub trait PricingStrategy: Send + Sync + std::fmt::Debug {
    /// Return the wei amount this request costs, or an error if the
    /// request cannot be priced.
    async fn price_for(
        &self,
        request: &http::Request<axum::body::Body>,
    ) -> Result<U256, PricingError>;
}

/// A strategy that charges the same wei amount for every request.
/// Useful for a paywalled resource or a demo service.
#[derive(Debug, Clone)]
pub struct FixedPricing {
    /// The fixed wei amount, stored as a decimal string (handles
    /// values above u128).
    amount_wei: String,
}

impl FixedPricing {
    /// Create a flat-rate strategy.
    ///
    /// `amount_wei` is a decimal string — caller's responsibility
    /// to have converted from SALT via
    /// `citrate_wallet_core::format::salt_to_wei` when appropriate.
    pub fn new(amount_wei: impl Into<String>) -> Self {
        Self {
            amount_wei: amount_wei.into(),
        }
    }
}

#[async_trait]
impl PricingStrategy for FixedPricing {
    async fn price_for(
        &self,
        _request: &http::Request<axum::body::Body>,
    ) -> Result<U256, PricingError> {
        U256::from_dec_str(&self.amount_wei)
            .map_err(|e| PricingError::NotPriceable(format!("invalid amount: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fixed_pricing_returns_configured_amount() {
        let strat = FixedPricing::new("1000000000000000000"); // 1 SALT
        let req = http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .expect("build request");
        let price = strat.price_for(&req).await.expect("price");
        assert_eq!(price, U256::from(1_000_000_000_000_000_000u128));
    }

    #[tokio::test]
    async fn fixed_pricing_rejects_invalid_amount() {
        let strat = FixedPricing::new("not-a-number");
        let req = http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .expect("build request");
        let err = strat.price_for(&req).await.expect_err("should fail");
        assert!(matches!(err, PricingError::NotPriceable(_)));
    }
}
