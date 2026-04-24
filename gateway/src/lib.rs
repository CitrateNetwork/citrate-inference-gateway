//! Citrate Inference Gateway — library entry point.
//!
//! `build_router(config)` returns the production axum router.
//! `build_router_with(...)` is the test-injection variant that
//! takes mocked `ChainQueries` + `ChainClient` so integration
//! tests can drive the gateway without a live chain.
//!
//! # Architecture
//!
//! - `health` / `models` — free endpoints (no x402)
//! - `chat` — `/v1/chat/completions` gated by `X402Layer`
//! - `pricing` — `TokenBasedPricing` strategy backed by ChainQueries
//! - `provider` — selection + dispatch to provider HTTPS endpoint
//! - `queries` — ChainQueries trait + HTTP impl
//!
//! WP-03.3 will add `batch`, WP-03.4 `auth`, WP-03.5 `usage`.
//!
//! # Specs
//!
//! - `.agentile/formal/specs/compute/GatewayBatchLifecycle.tla`
//! - `citrate_v0.01.1/specs/gherkin/gateway_inference.feature`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::sync::Arc;

use axum::{routing::{get, post}, Router};
use ethereum_types::H160;
use tower_http::trace::TraceLayer;

pub mod chat;
pub mod config;
pub mod error;
pub mod health;
pub mod models;
pub mod openai;
pub mod pricing;
pub mod provider;
pub mod queries;

pub use config::GatewayConfig;
pub use error::GatewayError;
pub use provider::{ProviderProtocolRequest, ProviderProtocolResponse};
pub use queries::{ChainQueries, HttpChainQueries, ProviderInfo};

use x402_axum::{ChainClient, X402Layer};

/// Production router builder. Wires `HttpChainQueries` and
/// `HttpChainClient` from the configured `rpc_url`.
///
/// **Note**: `HttpChainQueries` is currently a stub returning
/// `ChainUnavailable` for all methods (see queries.rs). Live
/// integration with `ModelRegistry` / `ComputePricingOracle` /
/// `InferenceRouter` is the WP-03.2 follow-up. For real chain
/// queries, prefer building directly with `build_router_with` and
/// supplying your own implementation.
pub async fn build_router(config: GatewayConfig) -> Router {
    // For the production code path we need an operator wallet and
    // facilitator address — these live in env vars / TOML. For
    // WP-03.1 + smoke this binary doesn't actually serve x402-gated
    // endpoints; we ship without them and the chat path errors
    // gracefully if invoked. Operators wire the full
    // build_router_with path.
    let queries: Arc<dyn ChainQueries> =
        Arc::new(HttpChainQueries::new(&config.rpc_url, config.chain_id));
    Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/models", get(models::models_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state::AppState {
            config,
            http: reqwest::Client::new(),
            queries,
        }))
}

/// Test-injection router builder. Production callers use
/// [`build_router`]; integration tests use this to inject mock
/// chain queries + mock x402 chain client.
pub async fn build_router_with(
    config: GatewayConfig,
    queries: Arc<dyn ChainQueries>,
    chain: Arc<dyn ChainClient>,
    operator_secret: [u8; 32],
    facilitator_address: H160,
) -> Router {
    let state = Arc::new(state::AppState {
        config: config.clone(),
        http: reqwest::Client::new(),
        queries: queries.clone(),
    });

    let pricing = pricing::TokenBasedPricing::new(queries, "llama-3.1-8b");

    let layer = X402Layer::builder()
        .chain_id(config.chain_id)
        .facilitator_address(&format!("0x{}", hex::encode(facilitator_address.as_bytes())))
        // WSALT and treasury aren't critical for the smoke test —
        // the digest only needs to be self-consistent across
        // server-issue and client-sign.
        .wsalt_address("0x8951ae72e5479cae28ef7bb3caa4207d5719e24b")
        .treasury("0x8951ae72e5479cae28ef7bb3caa4207d5719e24b")
        .rpc_url(&config.rpc_url)
        .pricing(pricing)
        .operator_secret_bytes(operator_secret)
        .chain_client(Arc::clone(&chain) as Arc<dyn ChainClient>)
        .build()
        .expect("X402Layer build (smoke config valid)");

    let chat_router = Router::new()
        .route("/v1/chat/completions", post(chat::chat_completions_handler))
        .layer(layer)
        .with_state(state.clone());

    Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/models", get(models::models_handler))
        .with_state(state)
        .merge(chat_router)
        .layer(TraceLayer::new_for_http())
}

mod state {
    use std::sync::Arc;
    use crate::config::GatewayConfig;
    use crate::queries::ChainQueries;

    /// Shared state passed to every handler. Cheap to clone (Arc).
    pub struct AppState {
        pub config: GatewayConfig,
        pub http: reqwest::Client,
        pub queries: Arc<dyn ChainQueries>,
    }
}

/// Type alias for the shared-state Arc handlers receive.
pub type SharedState = Arc<state::AppState>;
