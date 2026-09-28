//! `/health` endpoint.
//!
//! Returns 200 with `{"ok": true, "sha": "<git commit>"}` unconditionally. Does NOT
//! depend on chain RPC reachability — load balancers must not
//! take the gateway out of rotation on transient chain blips.
//!
//! `sha` is the deployed git commit (audit rescore #10, dim 8) so a deploy can be
//! *probed* rather than attested. It is resolved from a runtime env var (`GIT_SHA`
//! then `SOURCE_COMMIT`), falling back to the value `build.rs` bakes in; `"unknown"`
//! when nothing is available. Not a secret.
//!
//! Future enhancements (post-v1):
//! - `/health/ready` that DOES check chain reachability for
//!   slow-startup orchestrators.

use axum::Json;

/// The deployed git commit, for the `/health` probe. Runtime env override first
/// (`GIT_SHA`, then `SOURCE_COMMIT`), else the commit baked in at build time.
fn git_sha() -> String {
    for key in ["GIT_SHA", "SOURCE_COMMIT"] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    env!("GIT_SHA").to_string()
}

/// `GET /health` handler. Trivial liveness probe + the deployed git commit.
pub async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "sha": git_sha() }))
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
