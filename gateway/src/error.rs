//! Gateway errors.
//!
//! Three tiers, mapped to HTTP status by [`GatewayError::http_status`]:
//!
//! - 400 Bad Request — caller sent something we can't parse (bad
//!   model name, malformed body, unknown chain ID).
//! - 503 Service Unavailable — chain or providers unreachable.
//! - 500 Internal — bugs we'd rather not have happen.

use thiserror::Error;

/// Error surface for the gateway crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GatewayError {
    /// Caller supplied a model name we can't resolve via ModelRegistry.
    #[error("unknown model: {0}")]
    UnknownModel(String),

    /// No providers registered for the requested model.
    #[error("no providers available for model")]
    NoProviders,

    /// Provider HTTPS call failed (timeout, 5xx, malformed body).
    #[error("provider call failed: {0}")]
    ProviderUnavailable(String),

    /// Chain RPC unreachable or returned an error.
    #[error("chain unavailable: {0}")]
    ChainUnavailable(String),

    /// Pricing oracle stale or unresponsive.
    #[error("pricing unavailable: {0}")]
    PricingUnavailable(String),

    /// Caller's request was malformed.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Internal bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl GatewayError {
    /// HTTP status this error maps to.
    pub fn http_status(&self) -> u16 {
        use GatewayError::*;
        match self {
            UnknownModel(_) | BadRequest(_) => 400,
            NoProviders | ProviderUnavailable(_) | ChainUnavailable(_) | PricingUnavailable(_) => 503,
            Internal(_) => 500,
        }
    }
}
