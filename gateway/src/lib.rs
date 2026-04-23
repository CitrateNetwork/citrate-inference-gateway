//! Citrate Inference Gateway — library entry point.
//!
//! `build_router(config)` returns the axum router that the binary
//! serves. Exposed as a library so integration tests can drive the
//! router directly via `tower::ServiceExt::oneshot` without
//! spawning a separate process.
//!
//! # Architecture
//!
//! - `health` module — `/health` endpoint (chain-independent)
//! - `models` module — `/v1/models` endpoint (queries
//!   ModelRegistry.listModels via eth_call; degrades to empty
//!   list on RPC failure)
//! - WP-03.2 will add `chat` module (`/v1/chat/completions`)
//! - WP-03.3 will add `batch` module (`/v1/batch`)
//! - WP-03.4 will add `auth` module (API key layer)
//! - WP-03.5 will add `usage` module (`/v1/usage`)
//!
//! # Specs
//!
//! - `.agentile/formal/specs/compute/GatewayBatchLifecycle.tla`
//! - `citrate_v0.01.1/specs/gherkin/gateway_inference.feature`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;

pub mod config;
pub mod health;
pub mod models;

pub use config::GatewayConfig;

/// Build the full axum router for the gateway. Wires all routes
/// for the WPs that have shipped; future WPs add to this function.
///
/// Returns immediately — does not spawn a server. Caller (the
/// binary) calls `axum::serve(listener, router)`. Tests drive
/// `router.oneshot(req)` directly.
pub async fn build_router(config: GatewayConfig) -> Router {
    let state = std::sync::Arc::new(state::AppState::new(config));

    Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/models", get(models::models_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

mod state {
    use std::sync::Arc;
    use crate::config::GatewayConfig;

    /// Shared state passed to every handler. Cheap to clone (Arc).
    pub struct AppState {
        pub config: GatewayConfig,
        pub http: reqwest::Client,
    }

    impl AppState {
        pub fn new(config: GatewayConfig) -> Self {
            Self {
                config,
                http: reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap_or_default(),
            }
        }
    }

    pub type SharedState = Arc<AppState>;
}

pub(crate) use state::SharedState;
