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

    // ENCRYPT-S1 / WP-2: encrypted at rest; master key via the keyvault
    // sourcing chain (GATEWAY_STORE_KEY env → key file → generate).
    let (store, key_source): (Arc<PersistentKeyStore>, _) =
        citrate_gateway::keyvault::open_store(&keystore_path)?;
    tracing::info!(key_source = %key_source, "money-store master key sourced");
    let state = LocalProxyState::new(store, upstreams.clone());
    let app = build_local_proxy_router(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    // SECREM-01 SVC-5 (pre-audit 2026-06-09): same non-loopback warning as
    // marketplace mode — local-proxy enforces cgk_ bearer auth, but a public
    // bind still widens the attack surface beyond the loopback default.
    warn_if_non_loopback(&listener);
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
        // SECREM-01 SVC-5 (pre-audit 2026-06-09): default to loopback.
        // Marketplace mode's only request gate is x402 payment on /v1/*;
        // /models + /healthz are unauthenticated. In production this runs
        // behind Caddy over loopback (see packaging/*.service), so the
        // safe default is 127.0.0.1. Operators who genuinely need a remote
        // bind (e.g. a container) set CITRATE_GATEWAY_LISTEN_ADDR=0.0.0.0:9800
        // explicitly; that path logs a warning below.
        listen_addr: env::var("CITRATE_GATEWAY_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9800".to_string()),
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

    // FUA-GATEWAY-01 (bind half): when the open-chat dev profile is active
    // (OPEN_CHAT=1 + DEV_MODE=1), the gateway refuses to start on anything
    // but loopback — an unauthenticated, unpaid inference surface must never
    // be remotely reachable, dev profile or not.
    let open_chat_active = citrate_gateway::resolve_open_chat(
        env::var("CITRATE_GATEWAY_OPEN_CHAT").ok().as_deref(),
        env::var("CITRATE_GATEWAY_DEV_MODE").ok().as_deref(),
    ) == citrate_gateway::OpenChatDecision::On;
    if open_chat_active {
        let bound = listener.local_addr()?;
        if !citrate_gateway::open_chat_bind_allowed(&bound) {
            tracing::error!(
                addr = %bound,
                "REFUSING TO START: open-chat dev profile is active on a \
                 non-loopback bind. Bind to 127.0.0.1, or drop \
                 CITRATE_GATEWAY_OPEN_CHAT/CITRATE_GATEWAY_DEV_MODE. (FUA-GATEWAY-01)"
            );
            return Err("open-chat dev profile on non-loopback bind (FUA-GATEWAY-01)".into());
        }
    }

    // SECREM-01 SVC-5 (pre-audit 2026-06-09): warn loudly if the operator
    // intentionally exposed the gateway off loopback. Marketplace mode has
    // no bearer auth (x402 gates /v1/* only; /models + /healthz are open),
    // so a non-loopback bind without a fronting reverse proxy is a public
    // unauthenticated surface.
    warn_if_non_loopback(&listener);

    tracing::info!(addr = %listener.local_addr()?, "gateway listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// SECREM-01 SVC-5 (pre-audit 2026-06-09): emit a warning when the gateway
/// is bound to a non-loopback address. Loopback binds (127.0.0.0/8, ::1)
/// are silent — that's the safe default and the production topology (Caddy
/// forwards over loopback). A `0.0.0.0` / public bind means the operator
/// opted into a remotely reachable, only-payment-gated surface; surface it.
fn warn_if_non_loopback(listener: &tokio::net::TcpListener) {
    if let Ok(addr) = listener.local_addr() {
        if !addr.ip().is_loopback() {
            tracing::warn!(
                addr = %addr,
                "gateway bound to a NON-LOOPBACK address: this exposes /models \
                 and /healthz unauthenticated and /v1/* behind x402 payment only. \
                 Ensure a fronting reverse proxy / firewall is in place, or set \
                 CITRATE_GATEWAY_LISTEN_ADDR to a loopback address."
            );
        }
    }
}
