//! The production `build_router` (marketplace mode, what `main.rs` builds) at
//! its entry point: which routes it mounts, and how it boots its money store.
//!
//! The helpers behind these decisions (`resolve_marketplace_store`,
//! `resolve_open_chat`) have unit tests; these tests pin the wiring inside
//! `build_router` itself, so swapping a helper's outcome for a different
//! action at the call site is caught too.
//!
//! `build_router` reads its gates from process env, so every test takes
//! `ENV_LOCK` and sets the exact env it needs. Durable stores live in a
//! per-test temp dir (the store master key is generated beside the store,
//! inside that dir). The chain RPC is a closed loopback port; nothing here
//! touches the network.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use citrate_gateway::{build_router, GatewayConfig};

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const GATE_VARS: &[&str] = &[
    "CITRATE_GATEWAY_KEYSTORE_PATH",
    "CITRATE_GATEWAY_DEV_MODE",
    "CITRATE_GATEWAY_OPEN_CHAT",
    "GATEWAY_STORE_KEY",
    "GATEWAY_STORE_KEY_FILE",
];

fn clear_gates() {
    for v in GATE_VARS {
        std::env::remove_var(v);
    }
}

fn config() -> GatewayConfig {
    GatewayConfig {
        chain_id: 40204,
        rpc_url: "http://127.0.0.1:1".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        contracts: citrate_gateway::config::ContractAddresses::default(),
    }
}

/// Point the production store at a fresh temp dir (the production setting).
fn durable_store_in(dir: &tempfile::TempDir) {
    let path = dir.path().join("keystore");
    std::env::set_var(
        "CITRATE_GATEWAY_KEYSTORE_PATH",
        path.to_str().expect("utf8 path"),
    );
}

async fn status_of(app: &axum::Router, method: &str, uri: &str) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .expect("request");
    app.clone()
        .oneshot(req)
        .await
        .expect("service call")
        .status()
}

#[tokio::test]
async fn production_boot_without_a_keystore_refuses_to_start() {
    let _g = ENV_LOCK.lock().await;
    clear_gates();
    // No keystore path and no dev profile: a production boot must not come
    // up serving money paths on a volatile in-memory store.
    let joined = tokio::spawn(build_router(config())).await;
    let err = match joined {
        Ok(_) => panic!("build_router came up on a volatile money store outside the dev profile"),
        Err(e) => e,
    };
    assert!(err.is_panic(), "expected a refusal panic, got {err:?}");
    let msg = err.into_panic();
    let msg = msg
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| msg.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(
        msg.contains("REFUSING TO START"),
        "refusal must explain itself, got: {msg}"
    );
    clear_gates();
}

#[tokio::test]
async fn dev_profile_without_a_keystore_boots_volatile() {
    // Control for the refusal above: the same boot under the explicit dev
    // profile comes up (so the refusal is about the profile, not the config).
    let _g = ENV_LOCK.lock().await;
    clear_gates();
    std::env::set_var("CITRATE_GATEWAY_DEV_MODE", "1");
    let app = build_router(config()).await;
    assert_eq!(status_of(&app, "GET", "/health").await, StatusCode::OK);
    clear_gates();
}

#[tokio::test]
async fn production_router_mounts_no_paid_or_unauthenticated_inference_routes() {
    let _g = ENV_LOCK.lock().await;
    clear_gates();
    let dir = tempfile::tempdir().expect("tempdir");
    durable_store_in(&dir);
    let app = build_router(config()).await;

    // The configured keystore path is really opened as the durable store
    // (RocksDB dir + its master key beside it), not silently ignored.
    let store_dir = dir.path().join("keystore");
    assert!(
        store_dir.join("CURRENT").is_file(),
        "the production money store must be opened durably at the configured path"
    );
    assert!(dir.path().join("keystore.master.key").is_file());

    assert_eq!(status_of(&app, "GET", "/health").await, StatusCode::OK);
    assert_eq!(status_of(&app, "GET", "/v1/models").await, StatusCode::OK);
    for (method, uri) in [
        ("POST", "/v1/chat/completions"),
        ("POST", "/v1/batch"),
        ("GET", "/v1/batch/some-id"),
        ("GET", "/v1/usage"),
    ] {
        assert_eq!(
            status_of(&app, method, uri).await,
            StatusCode::NOT_FOUND,
            "{method} {uri} must not be mounted on the production router"
        );
    }
    drop(app);
    clear_gates();
}

#[tokio::test]
async fn open_chat_without_the_dev_profile_does_not_mount_chat() {
    let _g = ENV_LOCK.lock().await;
    clear_gates();
    let dir = tempfile::tempdir().expect("tempdir");
    durable_store_in(&dir);
    std::env::set_var("CITRATE_GATEWAY_OPEN_CHAT", "1");
    let app = build_router(config()).await;
    for (method, uri) in [("POST", "/v1/chat/completions"), ("POST", "/v1/batch")] {
        assert_eq!(
            status_of(&app, method, uri).await,
            StatusCode::NOT_FOUND,
            "OPEN_CHAT=1 without DEV_MODE=1 must leave {uri} unmounted"
        );
    }
    drop(app);
    clear_gates();
}

#[tokio::test]
async fn open_chat_with_the_dev_profile_mounts_chat() {
    // Control for the test above: with both opt-ins the route exists, so a
    // 404 there really means "not mounted" and not "probe is wrong".
    let _g = ENV_LOCK.lock().await;
    clear_gates();
    std::env::set_var("CITRATE_GATEWAY_DEV_MODE", "1");
    std::env::set_var("CITRATE_GATEWAY_OPEN_CHAT", "1");
    let app = build_router(config()).await;
    assert_ne!(
        status_of(&app, "POST", "/v1/chat/completions").await,
        StatusCode::NOT_FOUND
    );
    clear_gates();
}

#[tokio::test]
async fn production_metrics_are_closed_unless_the_operator_token_matches() {
    let _g = ENV_LOCK.lock().await;
    clear_gates();
    let dir = tempfile::tempdir().expect("tempdir");
    durable_store_in(&dir);
    let app = build_router(config()).await;

    let scrape = |bearer: Option<&'static str>| {
        let app = app.clone();
        async move {
            let mut b = Request::builder().uri("/metrics");
            if let Some(t) = bearer {
                b = b.header("authorization", format!("Bearer {t}"));
            }
            app.oneshot(b.body(Body::empty()).expect("request"))
                .await
                .expect("service call")
                .status()
        }
    };

    // No operator token configured: closed, whatever the caller presents.
    std::env::remove_var("CITRATE_GATEWAY_METRICS_TOKEN");
    assert_eq!(scrape(None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(scrape(Some("anything")).await, StatusCode::UNAUTHORIZED);

    // Token configured: a wrong or same-length-wrong bearer is refused.
    std::env::set_var("CITRATE_GATEWAY_METRICS_TOKEN", "prod-surface-secret");
    assert_eq!(scrape(None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        scrape(Some("prod-surface-secrex")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(scrape(Some("prod")).await, StatusCode::UNAUTHORIZED);
    assert_eq!(scrape(Some("prod-surface-secret")).await, StatusCode::OK);
    std::env::remove_var("CITRATE_GATEWAY_METRICS_TOKEN");
    drop(app);
    clear_gates();
}
