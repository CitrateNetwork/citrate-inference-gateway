//! Citrate Inference Gateway — binary entry point.
//!
//! Loads config from environment variables (with sensible defaults
//! for local dev) and starts the axum server.
//!
//! WP-03.1 ships health + /v1/models. Subsequent WPs add chat,
//! batch, auth, and usage routes — all wired through
//! `citrate_gateway::build_router`.

use std::env;
use std::sync::Arc;

use citrate_gateway::auth::ApiKeyStore;
use citrate_gateway::{build_local_proxy_router, build_router, GatewayConfig};
use tracing_subscriber::{fmt, EnvFilter};

/// Open the (optionally persistent) API-key store. INFER WP-B: when
/// `CITRATE_GATEWAY_KEYSTORE_PATH` is set, back it with RocksDB (records
/// keyed by `sha256(key_id)`, dir/files locked to `0700`/`0600`,
/// reloaded on boot); otherwise an in-memory store (tests / dev).
fn open_keystore() -> Result<Arc<ApiKeyStore>, Box<dyn std::error::Error>> {
    match env::var("CITRATE_GATEWAY_KEYSTORE_PATH").ok().filter(|s| !s.is_empty()) {
        Some(path) => {
            tracing::info!(path = %path, "opening persistent RocksDB API-key store");
            Ok(Arc::new(ApiKeyStore::open_rocksdb(&path)?))
        }
        None => {
            tracing::info!("no CITRATE_GATEWAY_KEYSTORE_PATH set — using in-memory API-key store");
            Ok(Arc::new(ApiKeyStore::new()))
        }
    }
}

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

    // INFER WP-A: mode selection. The default (and unchanged) mode is
    // the on-chain marketplace router. `local-proxy` mounts the API-key
    // wall over an OpenAI passthrough to the resident llama-server,
    // closing the open-GPU-endpoint risk.
    let mode = env::var("CITRATE_GATEWAY_MODE").unwrap_or_else(|_| "marketplace".to_string());
    if mode == "local-proxy" {
        return run_local_proxy().await;
    }

    use citrate_gateway::config::ContractAddresses;
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
        "citrate-inference-gateway starting"
    );

    let listen_addr = config.listen_addr.clone();
    let app = build_router(config).await;
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;

    tracing::info!(addr = %listener.local_addr()?, "gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// INFER WP-A — `CITRATE_GATEWAY_MODE=local-proxy` entry point.
///
/// Mounts the API-key wall over an OpenAI passthrough to
/// `CITRATE_GATEWAY_UPSTREAM_URL` (default `http://127.0.0.1:8081`).
/// `/health` is open; every `/v1/*` route requires a valid `cgk_` key.
async fn run_local_proxy() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = env::var("CITRATE_GATEWAY_UPSTREAM_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());
    let listen_addr = env::var("CITRATE_GATEWAY_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9800".to_string());

    let keys = open_keystore()?;

    tracing::info!(
        upstream = %upstream,
        listen_addr = %listen_addr,
        "citrate-inference-gateway starting (local-proxy mode — API-key wall over OpenAI passthrough)"
    );

    let app = build_local_proxy_router(keys, upstream);
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "local-proxy gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}
