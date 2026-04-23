//! `/health` endpoint.
//!
//! Returns 200 with `{"ok": true}` unconditionally. Does NOT
//! depend on chain RPC reachability — load balancers must not
//! take the gateway out of rotation on transient chain blips.
//!
//! Future enhancements (post-v1):
//! - `/health/ready` that DOES check chain reachability for
//!   slow-startup orchestrators.
//! - `/health/version` returning the gateway's build SHA.

use axum::Json;

/// `GET /health` handler. Trivial liveness probe.
pub async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_ok_true() {
        let resp = health_handler().await;
        assert_eq!(resp.0["ok"].as_bool(), Some(true));
    }

    #[tokio::test]
    async fn body_is_minimal() {
        let resp = health_handler().await;
        let s = serde_json::to_string(&resp.0).expect("ser");
        // Operational sanity: hammered by load balancers; keep tiny.
        assert!(s.len() < 100, "got {} bytes: {}", s.len(), s);
    }
}
