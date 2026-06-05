//! Citrate Inference Gateway — binary entry point.
//!
//! Picks one of two router builds at boot based on `CITRATE_GATEWAY_MODE`:
//!
//! - **`local-proxy`** (WP-5 of 2026-06-04 planset): the lean
//!   `cgk_`-gated OpenAI passthrough that fronts a resident llama-server.
//!   Reads `CITRATE_GATEWAY_UPSTREAM_URL` + `CITRATE_GATEWAY_KEYSTORE_PATH`.
//!   No chain RPC, no x402.
//! - **`marketplace`** (default — pre-existing behavior): the on-chain
//!   marketplace gateway with `ModelRegistry` / `InferenceRouter` dispatch.
//!   Reads `CITRATE_GATEWAY_RPC_URL` + contract addresses.
//!
//! Defaulting to the existing marketplace mode keeps `gateway.citrate.ai`
//! unchanged while letting `infer.citrate.ai` flip to the local-proxy
//! build independently. (See PLANSET.md §"Target topology".)

use std::env;
use std::sync::Arc;

use citrate_gateway::config::ContractAddresses;
use citrate_gateway::keystore::PersistentKeyStore;
use citrate_gateway::local_proxy::{build_local_proxy_router, LocalProxyState};
use citrate_gateway::{build_router, GatewayConfig};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Structured logging — JSON in production via LOG_FORMAT=json,
    // pretty otherwise.
    let format = env::var("LOG_FORMAT").unwrap_or_else(|_| "pretty".to_string());
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,citrate_gateway=debug"));
    if format == "json" {
        fmt().with_env_filter(filter).json().init();
    } else {
        fmt().with_env_filter(filter).init();
    }

    let mode = env::var("CITRATE_GATEWAY_MODE").unwrap_or_else(|_| "marketplace".to_string());
    match mode.as_str() {
        "local-proxy" => run_local_proxy().await,
        "marketplace" | "" => run_marketplace().await,
        other => Err(format!(
            "unknown CITRATE_GATEWAY_MODE={other:?}; expected 'local-proxy' or 'marketplace'"
        )
        .into()),
    }
}

async fn run_local_proxy() -> Result<(), Box<dyn std::error::Error>> {
    // Comma-separated list — tried in order on connection / 5xx failure.
    // Mirrors Caddy's `lb_policy first` so cutover preserves the existing
    // "DGX primary, local-CPU fallback" availability profile.
    let upstream_raw = env::var("CITRATE_GATEWAY_UPSTREAM_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8181".to_string());
    let upstreams: Vec<String> = upstream_raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if upstreams.is_empty() {
        return Err("CITRATE_GATEWAY_UPSTREAM_URL must list at least one upstream".into());
    }
    let keystore_path = env::var("CITRATE_GATEWAY_KEYSTORE_PATH")
        .unwrap_or_else(|_| "/var/lib/citrate-gateway/keystore".to_string());
    // Default to loopback in local-proxy mode — Caddy terminates TLS and
    // forwards in over loopback. Binding 0.0.0.0 would re-expose the open
    // path we're trying to close.
    let listen_addr = env::var("CITRATE_GATEWAY_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9800".to_string());

    let store: Arc<PersistentKeyStore> = PersistentKeyStore::open(&keystore_path)?;
    let state = LocalProxyState::new(store, upstreams.clone());
    let app = build_local_proxy_router(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        addr = %listener.local_addr()?,
        upstreams = ?upstreams,
        keystore = %keystore_path,
        mode = "local-proxy",
        "gateway listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_marketplace() -> Result<(), Box<dyn std::error::Error>> {
    let config = GatewayConfig {
        chain_id: env::var("CITRATE_GATEWAY_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(40204),
        rpc_url: env::var("CITRATE_GATEWAY_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18545".to_string()),
        listen_addr: env::var("CITRATE_GATEWAY_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9800".to_string()),
        contracts: ContractAddresses {
            model_registry: env::var("CITRATE_GATEWAY_MODEL_REGISTRY")
                .unwrap_or_else(|_| ContractAddresses::default().model_registry),
            pricing_oracle: env::var("CITRATE_GATEWAY_PRICING_ORACLE")
                .unwrap_or_else(|_| ContractAddresses::default().pricing_oracle),
            inference_router: env::var("CITRATE_GATEWAY_INFERENCE_ROUTER")
                .unwrap_or_else(|_| ContractAddresses::default().inference_router),
        },
    };

    tracing::info!(
        chain_id = config.chain_id,
        rpc_url = %config.rpc_url,
        listen_addr = %config.listen_addr,
        mode = "marketplace",
        "citrate-inference-gateway starting"
    );

    let listen_addr = config.listen_addr.clone();
    let app = build_router(config).await;
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;

    tracing::info!(addr = %listener.local_addr()?, "gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}
