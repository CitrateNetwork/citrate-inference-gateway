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

pub mod auth;
pub mod batch;
pub mod chat;
pub mod config;
pub mod error;
pub mod health;
pub mod metrics;
pub mod models;
pub mod openai;
pub mod pricing;
pub mod provider;
pub mod queries;
pub mod usage;

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
    // Production path: free endpoints only (`/health`, `/v1/models`).
    // Operators who want to expose `/v1/chat/completions` MUST call
    // `build_router_with` and supply their operator wallet secret +
    // x402 facilitator address — those live in env vars and aren't
    // safe defaults.
    metrics::install_recorder();
    let queries: Arc<dyn ChainQueries> = Arc::new(HttpChainQueries::new(
        &config.rpc_url,
        config.contracts.clone(),
    ));
    Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/models", get(models::models_handler))
        .route("/metrics", get(metrics::metrics_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::new(state::AppState {
            config,
            http: reqwest::Client::new(),
            queries,
            batches: Arc::new(batch::BatchStore::new()),
            keys: Arc::new(auth::ApiKeyStore::new()),
            usage: Arc::new(usage::UsageStore::new()),
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
    metrics::install_recorder();
    let state = Arc::new(state::AppState {
        config: config.clone(),
        http: reqwest::Client::new(),
        queries: queries.clone(),
        batches: Arc::new(batch::BatchStore::new()),
        keys: Arc::new(auth::ApiKeyStore::new()),
        usage: Arc::new(usage::UsageStore::new()),
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

    // Both /v1/chat/completions and /v1/batch sit behind the same
    // X402Layer — one settlement covers each route's payment.
    // /v1/batch/{id} (poll) and /v1/batch/{id}/output are FREE: the
    // payment was made at submit time; subsequent polls are public
    // reads of state the payer already owns.
    let paid_router = Router::new()
        .route("/v1/chat/completions", post(chat::chat_completions_handler))
        .route("/v1/batch", post(batch::submit_batch_handler))
        .layer(layer)
        .with_state(state.clone());

    let free_batch_reads = Router::new()
        .route("/v1/batch/:id", get(batch::get_batch_handler))
        .route("/v1/batch/:id/output", get(batch::get_batch_output_handler))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/models", get(models::models_handler))
        .route("/v1/usage", get(usage::usage_handler))
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(state)
        .merge(paid_router)
        .merge(free_batch_reads)
        .layer(TraceLayer::new_for_http())
}

/// Test/injection router builder with API-key auth layered on top of
/// x402. The `ApiKeyLayer` sits *in front of* the x402 layer: a valid,
/// funded Bearer key debits balance and injects a synthetic `X402Paid`
/// so the x402 layer's bypass forwards directly; an exhausted key
/// falls through to x402's 402 challenge and the auth layer patches
/// the body with a `deposit_instructions` pointer.
pub async fn build_router_with_auth(
    config: GatewayConfig,
    queries: Arc<dyn ChainQueries>,
    chain: Arc<dyn ChainClient>,
    operator_secret: [u8; 32],
    facilitator_address: H160,
    keys: Arc<auth::ApiKeyStore>,
) -> Router {
    metrics::install_recorder();
    let state = Arc::new(state::AppState {
        config: config.clone(),
        http: reqwest::Client::new(),
        queries: queries.clone(),
        batches: Arc::new(batch::BatchStore::new()),
        keys: keys.clone(),
        usage: Arc::new(usage::UsageStore::new()),
    });

    // Two pricing instances (cheap; both wrap the same Arc<dyn
    // ChainQueries>). One drives X402Layer's challenge amount, the
    // other tells ApiKeyLayer how much to debit from a key — they
    // must agree, which is why they share queries + default model.
    let pricing_x402 = pricing::TokenBasedPricing::new(queries.clone(), "llama-3.1-8b");
    let pricing_key: Arc<dyn x402_axum::PricingStrategy> =
        Arc::new(pricing::TokenBasedPricing::new(queries, "llama-3.1-8b"));

    let x402 = X402Layer::builder()
        .chain_id(config.chain_id)
        .facilitator_address(&format!("0x{}", hex::encode(facilitator_address.as_bytes())))
        .wsalt_address("0x8951ae72e5479cae28ef7bb3caa4207d5719e24b")
        .treasury("0x8951ae72e5479cae28ef7bb3caa4207d5719e24b")
        .rpc_url(&config.rpc_url)
        .pricing(pricing_x402)
        .operator_secret_bytes(operator_secret)
        .chain_client(Arc::clone(&chain) as Arc<dyn ChainClient>)
        .build()
        .expect("X402Layer build (smoke config valid)");

    let api_key = auth::ApiKeyLayer::new(keys, pricing_key);

    // Layer ordering: api_key OUTSIDE x402. A request first hits the
    // API-key layer (which may short-circuit 401 / attach synthetic
    // X402Paid / fall through to x402), then the x402 layer (which
    // honors the synthetic X402Paid via its extensions bypass).
    let paid_router = Router::new()
        .route("/v1/chat/completions", post(chat::chat_completions_handler))
        .route("/v1/batch", post(batch::submit_batch_handler))
        .layer(x402)
        .layer(api_key)
        .with_state(state.clone());

    let free_batch_reads = Router::new()
        .route("/v1/batch/:id", get(batch::get_batch_handler))
        .route("/v1/batch/:id/output", get(batch::get_batch_output_handler))
        .with_state(state.clone());

    Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/models", get(models::models_handler))
        .route("/v1/usage", get(usage::usage_handler))
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(state)
        .merge(paid_router)
        .merge(free_batch_reads)
        .layer(TraceLayer::new_for_http())
}

mod state {
    use std::sync::Arc;
    use crate::auth::ApiKeyStore;
    use crate::batch::BatchStore;
    use crate::config::GatewayConfig;
    use crate::queries::ChainQueries;
    use crate::usage::UsageStore;

    /// Shared state passed to every handler. Cheap to clone (Arc).
    pub struct AppState {
        pub config: GatewayConfig,
        pub http: reqwest::Client,
        pub queries: Arc<dyn ChainQueries>,
        pub batches: Arc<BatchStore>,
        pub keys: Arc<ApiKeyStore>,
        pub usage: Arc<UsageStore>,
    }
}

/// Type alias for the shared-state Arc handlers receive.
pub type SharedState = Arc<state::AppState>;
