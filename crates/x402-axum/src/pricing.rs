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
use axum::body::{Body, Bytes};
use ethereum_types::U256;
use thiserror::Error;

/// Maximum request body buffered for request-aware pricing and authorization
/// binding. Inference JSON requests are small compared with this ceiling, and
/// bounding the buffer prevents the payment middleware from becoming a body
/// amplification surface.
pub const MAX_PRICING_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Buffer a request body once and make it available to the pricing strategy
/// without consuming the body that the downstream handler must receive.
pub async fn buffer_request_body(request: &mut http::Request<Body>) -> Result<Bytes, String> {
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = axum::body::to_bytes(body, MAX_PRICING_BODY_BYTES)
        .await
        .map_err(|e| format!("request body cannot be buffered: {e}"))?;
    *request.body_mut() = Body::from(bytes.clone());
    Ok(bytes)
}

/// Build the send-safe, body-buffered request view passed to a pricing
/// strategy. The original request body remains restored for the downstream
/// handler, while `Bytes` lets a strategy inspect it across async awaits.
pub fn request_for_pricing(request: &http::Request<Body>, body: Bytes) -> http::Request<Bytes> {
    let mut view = http::Request::new(body);
    *view.method_mut() = request.method().clone();
    *view.uri_mut() = request.uri().clone();
    *view.headers_mut() = request.headers().clone();
    view
}

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
    /// Return the wei amount this body-buffered request costs, or an error if
    /// the request cannot be priced. `Bytes` is intentional: strategies may
    /// perform async oracle calls without holding a non-`Sync` streaming body.
    async fn price_for(&self, request: &http::Request<Bytes>) -> Result<U256, PricingError>;
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
    async fn price_for(&self, _request: &http::Request<Bytes>) -> Result<U256, PricingError> {
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
            .body(Bytes::new())
            .expect("build request");
        let price = strat.price_for(&req).await.expect("price");
        assert_eq!(price, U256::from(1_000_000_000_000_000_000u128));
    }

    #[tokio::test]
    async fn fixed_pricing_rejects_invalid_amount() {
        let strat = FixedPricing::new("not-a-number");
        let req = http::Request::builder()
            .uri("/")
            .body(Bytes::new())
            .expect("build request");
        let err = strat.price_for(&req).await.expect_err("should fail");
        assert!(matches!(err, PricingError::NotPriceable(_)));
    }
}
