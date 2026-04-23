//! Citrate Inference Gateway — binary entry point.
//!
//! Loads config from environment variables (with sensible defaults
//! for local dev) and starts the axum server.
//!
//! WP-03.1 ships health + /v1/models. Subsequent WPs add chat,
//! batch, auth, and usage routes — all wired through
//! `citrate_gateway::build_router`.

use std::env;

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

    let config = GatewayConfig {
        chain_id: env::var("CITRATE_GATEWAY_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(40204),
        rpc_url: env::var("CITRATE_GATEWAY_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18545".to_string()),
        listen_addr: env::var("CITRATE_GATEWAY_LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9800".to_string()),
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
