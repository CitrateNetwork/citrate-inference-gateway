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

    /// CM-05 WP-05.4 slice 1 marker: dispatch selection picked a
    /// pool, but on-chain `requestPoolCompute` requires a gateway
    /// wallet that lands in slice 2. The pool name is included so
    /// operators / dashboards can flag which pool is currently
    /// "selectable but not dispatchable."
    #[error("pool dispatch not implemented yet (slice 2): {0}")]
    PoolDispatchUnimplemented(String),

    /// The amount the caller authorized via x402 falls short of the
    /// actual cost computed from `req.max_tokens`. Maps to HTTP 402.
    /// Pre-fix the gateway priced against assumed defaults (see
    /// `pricing::ASSUMED_OUTPUT_TOKENS`); a caller could request
    /// `max_tokens = 65535` while only paying for the default 512,
    /// receiving up to 128× the work they paid for.
    /// RM-B1 / WP-D2.4 (audit F-2).
    #[error("payment underfunded: paid {paid_wei} wei < required {required_wei} wei (max_tokens={max_tokens})")]
    Underfunded {
        /// Decimal-string of the amount the caller authorized.
        paid_wei: String,
        /// Decimal-string of the cost computed against `max_tokens`.
        required_wei: String,
        /// The `max_tokens` value the caller declared.
        max_tokens: u32,
    },
    /// The key's per-model spend budget for this model is exhausted
    /// (INFER-S3 / WP-E). The overall balance may still have funds and other
    /// models still work — only this model's sub-budget is spent.
    #[error("model budget exhausted for {model}: {remaining_grains} grains remaining")]
    ModelBudgetExceeded {
        /// The model whose per-model budget is exhausted.
        model: String,
        /// Decimal-string of the remaining budget for this model.
        remaining_grains: String,
    },
}

impl GatewayError {
    /// HTTP status this error maps to.
    pub fn http_status(&self) -> u16 {
        use GatewayError::*;
        match self {
            UnknownModel(_) | BadRequest(_) => 400,
            Underfunded { .. } | ModelBudgetExceeded { .. } => 402,
            NoProviders
            | ProviderUnavailable(_)
            | ChainUnavailable(_)
            | PricingUnavailable(_)
            | PoolDispatchUnimplemented(_) => 503,
            Internal(_) => 500,
        }
    }
}
