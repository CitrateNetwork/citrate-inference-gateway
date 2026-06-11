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
use axum::http::{header, Method};
use ethereum_types::H160;
use tower_http::cors::{Any, CorsLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

/// Permissive CORS for the public gateway so browser SPAs (e.g. the
/// buyer webapp) can call /v1/* cross-origin. Allows any origin, the
/// REST methods we serve, and any request header (covers the x402
/// `x-payment` header). No credentials are used, so `Any` is safe.
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
}

/// RM-G2.3 / audit F-3: every request flowing through the gateway
/// runs `Authorization: Bearer ...` through this redaction layer
/// BEFORE the TraceLayer sees it, so structured logs / OTel spans
/// never carry the bearer token. Pre-fix `TraceLayer::new_for_http`
/// captured the raw header into the request span; a routed log
/// drain or a stuck debug build dumping spans was a free credential
/// leak.
fn redact_authorization() -> SetSensitiveRequestHeadersLayer {
    SetSensitiveRequestHeadersLayer::new([header::AUTHORIZATION])
}

pub mod auth;
pub mod batch;
pub mod chat;
pub mod config;
pub mod error;
pub mod health;
pub mod keystore;
pub mod local_proxy;
pub mod metrics;
pub mod models;
pub mod openai;
pub mod pricing;
pub mod provider;
pub mod queries;
pub mod selection;
pub mod signer;
pub mod usage;

pub use config::GatewayConfig;
pub use error::GatewayError;
pub use provider::{ProviderProtocolRequest, ProviderProtocolResponse};
pub use queries::{ChainQueries, HttpChainQueries, ModelInfo, PoolEntry, ProviderInfo};

use x402_axum::{ChainClient, X402Layer};

/// 2026-05-31 audit -005 part b (SECREM-02 6.4a): outcome of the
/// marketplace money-store resolution. Pure decision — env reads and
/// side effects live in `open_marketplace_store`.
#[derive(Debug, PartialEq, Eq)]
pub enum MarketplaceStoreDecision {
    /// `CITRATE_GATEWAY_KEYSTORE_PATH` set — durable RocksDB store.
    Durable(String),
    /// No keystore path, but the explicit dev profile
    /// (`CITRATE_GATEWAY_DEV_MODE=1`) is on — volatile in-memory store
    /// allowed, loudly.
    VolatileDevAllowed,
    /// No keystore path and NO dev profile — a production boot must not
    /// serve money paths against volatile state (balances/escrow would
    /// vanish on restart). Refused: the caller fails closed.
    RefusedProdVolatile,
}

/// Pure resolver for the marketplace money-store policy (audit -005
/// part b). Mirrors the WP 5.2 `resolve_open_chat` pattern: production
/// is the *absence* of `CITRATE_GATEWAY_DEV_MODE=1`.
pub fn resolve_marketplace_store(
    keystore_path: Option<&str>,
    dev_mode: Option<&str>,
) -> MarketplaceStoreDecision {
    match keystore_path {
        Some(p) if !p.is_empty() => MarketplaceStoreDecision::Durable(p.to_string()),
        _ if dev_mode == Some("1") => MarketplaceStoreDecision::VolatileDevAllowed,
        _ => MarketplaceStoreDecision::RefusedProdVolatile,
    }
}

/// Build the marketplace API-key (money) store for the production router.
///
/// Durable RocksDB store when `CITRATE_GATEWAY_KEYSTORE_PATH` is set —
/// production MUST set it so balances survive a restart (INFER-S4 / WP-F /
/// TD-22). If set but unopenable, that's a fatal misconfiguration of a money
/// store, so we panic rather than silently bill against volatile state.
///
/// 2026-05-31 audit -005 part b (SECREM-02 6.4a): when the path is unset,
/// the in-memory fallback is now allowed ONLY under the explicit dev
/// profile (`CITRATE_GATEWAY_DEV_MODE=1`). A production boot (no dev
/// profile) with no keystore path REFUSES TO START instead of silently
/// serving money paths on volatile state — pre-fix this was a `warn!`.
fn open_marketplace_store() -> Option<Arc<keystore::PersistentKeyStore>> {
    let path = std::env::var("CITRATE_GATEWAY_KEYSTORE_PATH").ok();
    let dev_mode = std::env::var("CITRATE_GATEWAY_DEV_MODE").ok();
    match resolve_marketplace_store(path.as_deref(), dev_mode.as_deref()) {
        MarketplaceStoreDecision::Durable(path) => match keystore::PersistentKeyStore::open(&path) {
            Ok(store) => {
                tracing::info!(keystore = %path, "marketplace stores: durable (RocksDB, shared by keys + batches)");
                Some(store)
            }
            Err(e) => panic!("failed to open durable gateway store at {path}: {e}"),
        },
        MarketplaceStoreDecision::VolatileDevAllowed => {
            tracing::warn!(
                "CITRATE_GATEWAY_KEYSTORE_PATH unset — API-key balances + in-flight batches are \
                 IN-MEMORY and will be LOST on restart (INFER-S4/WP-F/TD-22). Allowed only \
                 because CITRATE_GATEWAY_DEV_MODE=1."
            );
            None
        }
        MarketplaceStoreDecision::RefusedProdVolatile => panic!(
            "REFUSING TO START: CITRATE_GATEWAY_KEYSTORE_PATH is unset and the dev profile \
             (CITRATE_GATEWAY_DEV_MODE=1) is not active. A production marketplace boot must \
             not serve money paths on a volatile in-memory store — balances and batch escrow \
             would be destroyed by a restart. Set CITRATE_GATEWAY_KEYSTORE_PATH, or set \
             CITRATE_GATEWAY_DEV_MODE=1 for a non-production run. \
             (2026-05-31 audit -005 part b / SECREM-02 6.4a)"
        ),
    }
}

/// FUA-GATEWAY-01: outcome of the open-chat gate.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenChatDecision {
    /// `CITRATE_GATEWAY_OPEN_CHAT` unset — free endpoints only.
    Off,
    /// Open-chat requested AND the dev profile is explicitly on.
    On,
    /// Open-chat requested WITHOUT the dev profile — refused
    /// (fail closed; this is what a production deploy hits).
    RefusedNotDev,
}

/// FUA-GATEWAY-01: the unauthenticated open-chat pilot routes mount only
/// when `CITRATE_GATEWAY_OPEN_CHAT=1` AND `CITRATE_GATEWAY_DEV_MODE=1`.
/// Any other combination fails closed. `main.rs` additionally refuses a
/// non-loopback bind while the open profile is active (see
/// [`open_chat_bind_allowed`]).
pub fn resolve_open_chat(open_chat: Option<&str>, dev_mode: Option<&str>) -> OpenChatDecision {
    match (open_chat == Some("1"), dev_mode == Some("1")) {
        (false, _) => OpenChatDecision::Off,
        (true, true) => OpenChatDecision::On,
        (true, false) => OpenChatDecision::RefusedNotDev,
    }
}

/// FUA-GATEWAY-01 (bind half): while the open-chat dev profile is active,
/// only loopback binds are permitted — an unauthenticated, unpaid inference
/// surface must never be remotely reachable.
pub fn open_chat_bind_allowed(addr: &std::net::SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// The literal that used to be baked into the x402 wiring as both the
/// wSALT token and the treasury (2026-05-31 audit -007). Kept ONLY so
/// [`validate_money_address`] can reject it if anyone passes it back in.
const RETIRED_PLACEHOLDER_ADDR: &str = "8951ae72e5479cae28ef7bb3caa4207d5719e24b";

/// 2026-05-31 audit -007 (SECREM-02 6.4a): money-path addresses must be
/// explicit. Pre-fix, `build_router_with*` hardcoded the placeholder
/// `0x8951…e24b` as BOTH the wSALT contract and the treasury — any
/// deployment wired through those builders silently signed challenges
/// against a placeholder domain and directed payment to a placeholder
/// recipient. This validator rejects, fail-closed:
///
/// - unset / empty / non-hex / wrong-length input,
/// - the zero address,
/// - the retired placeholder literal itself.
pub fn validate_money_address(name: &str, addr: &str) -> Result<H160, String> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{name} is not configured — the x402 money path requires an explicit address \
             (audit -007: no placeholder defaults)"
        ));
    }
    let hex_part = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_part)
        .map_err(|e| format!("{name} is not valid hex ({e}): {trimmed:?}"))?;
    let arr: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{name} must be 20 bytes, got {}: {trimmed:?}", bytes.len()))?;
    let parsed = H160::from(arr);
    if parsed == H160::zero() {
        return Err(format!("{name} is the zero address — refusing the money path"));
    }
    if hex_part.eq_ignore_ascii_case(RETIRED_PLACEHOLDER_ADDR) {
        return Err(format!(
            "{name} is the retired placeholder 0x{RETIRED_PLACEHOLDER_ADDR} — supply the real \
             deployment address (audit -007)"
        ));
    }
    Ok(parsed)
}

/// Production router builder. Wires `HttpChainQueries` and
/// `HttpChainClient` from the configured `rpc_url`.
///
/// **Note**: `HttpChainQueries` is currently a stub returning
/// `ChainUnavailable` for all methods (see queries.rs). Live
/// integration with `ModelRegistry` / `ComputePricingOracle` /
/// `InferenceRouter` is the WP-03.2 follow-up. For real chain
/// queries, prefer building directly with `build_router_with` and
/// supplying your own implementation. The API-key money store is
/// durable when `CITRATE_GATEWAY_KEYSTORE_PATH` is set (WP-F).
pub async fn build_router(config: GatewayConfig) -> Router {
    // Production path: free endpoints only (`/health`, `/v1/models`).
    // Operators who want to expose `/v1/chat/completions` MUST call
    // `build_router_with` and supply their operator wallet secret +
    // x402 facilitator address — those live in env vars and aren't
    // safe defaults.
    //
    // PIL-47 / pilot exception: if `CITRATE_GATEWAY_OPEN_CHAT=1`,
    // also mount `/v1/chat/completions` and `/v1/batch` *without*
    // x402 auth. The chat handler tolerates `paid: None` by skipping
    // payment validation entirely, so dispatching just falls through
    // to provider selection + forward. This is a pilot-stage toggle
    // for showing end-to-end routing (chatbot → gateway → on-chain
    // InferenceRouter lookup → DGX shim) without standing up a
    // facilitator first. Do NOT enable on a public, broadly-exposed
    // gateway.
    metrics::install_recorder();
    let queries: Arc<dyn ChainQueries> = Arc::new(HttpChainQueries::new(
        &config.rpc_url,
        config.contracts.clone(),
    ));
    // FUA-GATEWAY-01: OPEN_CHAT alone no longer mounts the unauthenticated
    // routes — it additionally requires the explicit dev-profile opt-in.
    // A deploy that sets OPEN_CHAT=1 without DEV_MODE=1 gets free endpoints
    // only (fail closed) and a loud error explaining why. main.rs adds the
    // second half of the gate: an active open-chat profile refuses to start
    // on a non-loopback bind.
    let open_chat = match resolve_open_chat(
        std::env::var("CITRATE_GATEWAY_OPEN_CHAT").ok().as_deref(),
        std::env::var("CITRATE_GATEWAY_DEV_MODE").ok().as_deref(),
    ) {
        OpenChatDecision::Off => false,
        OpenChatDecision::On => true,
        OpenChatDecision::RefusedNotDev => {
            tracing::error!(
                "CITRATE_GATEWAY_OPEN_CHAT=1 REFUSED: the unauthenticated open-chat \
                 pilot routes additionally require the explicit dev profile \
                 (CITRATE_GATEWAY_DEV_MODE=1) and a loopback bind. Production \
                 traffic must use build_router_with (x402 payment) or the \
                 local-proxy cgk_ key wall. (FUA-GATEWAY-01)"
            );
            false
        }
    };

    // One shared durable store backs both the API-key balances and the
    // in-flight batch state (WP-F) — so a batch refund + its balance credit
    // commit atomically. When unconfigured, both fall back to in-memory.
    let store = open_marketplace_store();
    let keys = Arc::new(match &store {
        Some(s) => auth::ApiKeyStore::with_persistent(s.clone()),
        None => auth::ApiKeyStore::new(),
    });
    let batches = Arc::new(match &store {
        Some(s) => batch::BatchStore::with_persistence(s.clone()),
        None => batch::BatchStore::new(),
    });
    if store.is_some() {
        // Boot recovery: re-hydrate persisted batches and refund any escrow a
        // crash left unsettled (exactly-once).
        let (rehydrated, settled) = batches.recover().await;
        if rehydrated > 0 {
            tracing::info!(rehydrated, settled, "recovered in-flight batches on boot (WP-F)");
        }
    }

    let state = Arc::new(state::AppState {
        config,
        http: reqwest::Client::new(),
        queries,
        batches,
        keys,
        usage: Arc::new(usage::UsageStore::new()),
    });
    let mut router = Router::new()
        .route("/health", get(health::health_handler))
        .route("/v1/models", get(models::models_handler))
        .route("/metrics", get(metrics::metrics_handler));
    if open_chat {
        tracing::warn!(
            "CITRATE_GATEWAY_OPEN_CHAT=1 — exposing /v1/chat/completions without x402 auth. \
             Acceptable for pilot demo; disable before broad public exposure."
        );
        router = router
            .route("/v1/chat/completions", post(chat::chat_completions_handler))
            .route("/v1/batch", post(batch::submit_batch_handler))
            .route("/v1/batch/:id", get(batch::get_batch_handler))
            .route("/v1/batch/:id/output", get(batch::get_batch_output_handler));
    }
    router
        .layer(cors_layer())
        .layer(redact_authorization())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Test-injection router builder. Production callers use
/// [`build_router`]; integration tests use this to inject mock
/// chain queries + mock x402 chain client.
///
/// 2026-05-31 audit -007 (SECREM-02 6.4a): `wsalt_address` and
/// `treasury` are now REQUIRED explicit arguments — pre-fix both were
/// the baked-in placeholder `0x8951…e24b`, and these builders are the
/// only x402-wired boot paths, so a real money deployment inherited
/// the placeholder silently. Validated by [`validate_money_address`];
/// an unset/zero/placeholder address panics at startup (fail closed).
pub async fn build_router_with(
    config: GatewayConfig,
    queries: Arc<dyn ChainQueries>,
    chain: Arc<dyn ChainClient>,
    operator_secret: [u8; 32],
    facilitator_address: H160,
    wsalt_address: &str,
    treasury: &str,
) -> Router {
    let wsalt = validate_money_address("wsalt_address", wsalt_address)
        .unwrap_or_else(|e| panic!("build_router_with: {e}"));
    let treasury_addr = validate_money_address("treasury", treasury)
        .unwrap_or_else(|e| panic!("build_router_with: {e}"));
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
        .wsalt_address(&format!("0x{}", hex::encode(wsalt.as_bytes())))
        .treasury(&format!("0x{}", hex::encode(treasury_addr.as_bytes())))
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
        .layer(cors_layer())
        .layer(redact_authorization())
        .layer(TraceLayer::new_for_http())
}

/// Test/injection router builder with API-key auth layered on top of
/// x402. The `ApiKeyLayer` sits *in front of* the x402 layer: a valid,
/// funded Bearer key debits balance and injects a synthetic `X402Paid`
/// so the x402 layer's bypass forwards directly; an exhausted key
/// falls through to x402's 402 challenge and the auth layer patches
/// the body with a `deposit_instructions` pointer.
/// 2026-05-31 audit -007 (SECREM-02 6.4a): like [`build_router_with`],
/// `wsalt_address` + `treasury` are required, validated, fail-closed.
pub async fn build_router_with_auth(
    config: GatewayConfig,
    queries: Arc<dyn ChainQueries>,
    chain: Arc<dyn ChainClient>,
    operator_secret: [u8; 32],
    facilitator_address: H160,
    wsalt_address: &str,
    treasury: &str,
    keys: Arc<auth::ApiKeyStore>,
) -> Router {
    let wsalt = validate_money_address("wsalt_address", wsalt_address)
        .unwrap_or_else(|e| panic!("build_router_with_auth: {e}"));
    let treasury_addr = validate_money_address("treasury", treasury)
        .unwrap_or_else(|e| panic!("build_router_with_auth: {e}"));
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
        .wsalt_address(&format!("0x{}", hex::encode(wsalt.as_bytes())))
        .treasury(&format!("0x{}", hex::encode(treasury_addr.as_bytes())))
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
        .layer(cors_layer())
        .layer(redact_authorization())
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

#[cfg(test)]
mod open_chat_gate_tests {
    use super::*;

    // FUA-GATEWAY-01 red tests: a production deploy (OPEN_CHAT=1, no dev
    // profile) must be REFUSED; only the explicit dev profile + loopback
    // combination may mount the unauthenticated routes.

    #[test]
    fn open_chat_without_dev_profile_is_refused() {
        assert_eq!(
            resolve_open_chat(Some("1"), None),
            OpenChatDecision::RefusedNotDev
        );
        assert_eq!(
            resolve_open_chat(Some("1"), Some("0")),
            OpenChatDecision::RefusedNotDev
        );
    }

    #[test]
    fn open_chat_with_dev_profile_is_on() {
        assert_eq!(resolve_open_chat(Some("1"), Some("1")), OpenChatDecision::On);
    }

    #[test]
    fn open_chat_unset_is_off_regardless_of_dev_profile() {
        assert_eq!(resolve_open_chat(None, Some("1")), OpenChatDecision::Off);
        assert_eq!(resolve_open_chat(Some("0"), Some("1")), OpenChatDecision::Off);
        assert_eq!(resolve_open_chat(None, None), OpenChatDecision::Off);
    }

    #[test]
    fn open_chat_bind_requires_loopback() {
        let loopback: std::net::SocketAddr = "127.0.0.1:9800".parse().unwrap();
        let loopback6: std::net::SocketAddr = "[::1]:9800".parse().unwrap();
        let public: std::net::SocketAddr = "0.0.0.0:9800".parse().unwrap();
        let lan: std::net::SocketAddr = "10.0.0.5:9800".parse().unwrap();
        assert!(open_chat_bind_allowed(&loopback));
        assert!(open_chat_bind_allowed(&loopback6));
        assert!(!open_chat_bind_allowed(&public));
        assert!(!open_chat_bind_allowed(&lan));
    }
}

#[cfg(test)]
mod money_address_tests {
    use super::*;

    // 2026-05-31 audit -007 (SECREM-02 6.4a) red tests: the retired
    // placeholder, the zero address, and unset/garbage input must all
    // be REJECTED by the x402 wiring path.

    #[test]
    fn placeholder_address_is_rejected() {
        for form in [
            "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b",
            "8951ae72e5479cae28ef7bb3caa4207d5719e24b",
            "0x8951AE72E5479CAE28EF7BB3CAA4207D5719E24B",
        ] {
            let err = validate_money_address("treasury", form)
                .expect_err("placeholder must be rejected in every case form");
            assert!(err.contains("placeholder"), "got: {err}");
        }
    }

    #[test]
    fn zero_and_unset_addresses_are_rejected() {
        assert!(validate_money_address("wsalt_address", "").is_err());
        assert!(validate_money_address("wsalt_address", "   ").is_err());
        assert!(validate_money_address(
            "wsalt_address",
            "0x0000000000000000000000000000000000000000"
        )
        .is_err());
    }

    #[test]
    fn garbage_addresses_are_rejected() {
        assert!(validate_money_address("treasury", "not-hex").is_err());
        assert!(validate_money_address("treasury", "0x1234").is_err()); // wrong length
    }

    #[test]
    fn real_address_is_accepted() {
        let parsed = validate_money_address(
            "wsalt_address",
            "0x61bc737f67b430fe2567630823694032a049253e",
        )
        .expect("real address accepted");
        assert_ne!(parsed, H160::zero());
    }
}

#[cfg(test)]
mod marketplace_store_policy_tests {
    use super::*;

    // 2026-05-31 audit -005 part b (SECREM-02 6.4a) red tests: with no
    // keystore path and no dev profile, the marketplace boot must be
    // REFUSED — pre-fix it warn!'d and served money paths in-memory.

    #[test]
    fn prod_without_keystore_is_refused() {
        assert_eq!(
            resolve_marketplace_store(None, None),
            MarketplaceStoreDecision::RefusedProdVolatile
        );
        assert_eq!(
            resolve_marketplace_store(Some(""), None),
            MarketplaceStoreDecision::RefusedProdVolatile
        );
        assert_eq!(
            resolve_marketplace_store(None, Some("0")),
            MarketplaceStoreDecision::RefusedProdVolatile
        );
    }

    #[test]
    fn dev_profile_allows_volatile_store_loudly() {
        assert_eq!(
            resolve_marketplace_store(None, Some("1")),
            MarketplaceStoreDecision::VolatileDevAllowed
        );
    }

    #[test]
    fn keystore_path_is_durable_regardless_of_profile() {
        assert_eq!(
            resolve_marketplace_store(Some("/var/lib/gw"), None),
            MarketplaceStoreDecision::Durable("/var/lib/gw".into())
        );
        assert_eq!(
            resolve_marketplace_store(Some("/var/lib/gw"), Some("1")),
            MarketplaceStoreDecision::Durable("/var/lib/gw".into())
        );
    }
}
