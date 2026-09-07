//! Prometheus metrics surface (WP-03.6).
//!
//! Counters and gauges exposed on `/metrics` in the standard
//! text-exposition format. Production operators should:
//!
//! 1. Point Prometheus at `http://<gateway>/metrics`
//! 2. Import `gateway/ops/grafana/gateway-dashboard.json` into Grafana
//! 3. Wire alerts on the thresholds documented in `gateway/RUNBOOK.md`
//!
//! # Metrics catalogue
//!
//! | Metric | Type | Labels | Meaning |
//! |--------|------|--------|---------|
//! | `gateway_chat_requests_total` | counter | `outcome={success,error}` | `/v1/chat/completions` handled |
//! | `gateway_batch_submissions_total` | counter | — | `/v1/batch` accepted |
//! | `gateway_api_key_requests_total` | counter | `outcome={funded,exhausted,unknown,revoked}` | API-key path decisions |
//! | `gateway_usage_rows_emitted_total` | counter | — | usage rows written |
//! | `gateway_provider_dispatch_failures_total` | counter | — | provider HTTPS errors during failover |
//!
//! Anything not listed here is out of scope for WP-03.6. Adding a
//! metric requires updating this table so operators have a single
//! source of truth.

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use metrics::describe_counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;

/// IGW-B-012: operator bearer token that gates `/metrics`. The Prometheus
/// surface publishes per-outcome request volumes and key-path decision
/// counts (`gateway_api_key_requests_total{outcome=unknown|revoked|…}`,
/// batch/refund/provider counters). Left open it is a live oracle for
/// credential-guessing feedback and business volume to anyone who can reach
/// the listener. The endpoint now requires `Authorization: Bearer <token>`
/// matching this env var; with no token configured it is fail-closed (401),
/// so a default deploy never leaks the catalogue.
pub const ENV_METRICS_TOKEN: &str = "CITRATE_GATEWAY_METRICS_TOKEN";

// Metric names are string literals at every call site because
// `metrics::counter!` requires a literal for the key. These constants
// exist only as the runbook-visible catalogue — DO NOT reference them
// from the macros; if you rename one, grep the crate for the literal.
/// `gateway_chat_requests_total` — labelled by `outcome={success,error}`
pub const CHAT_REQUESTS: &str = "gateway_chat_requests_total";
/// `gateway_batch_submissions_total`
pub const BATCH_SUBMISSIONS: &str = "gateway_batch_submissions_total";
/// `gateway_api_key_requests_total` — labelled by `outcome={funded,exhausted,unknown,revoked}`
pub const API_KEY_REQUESTS: &str = "gateway_api_key_requests_total";
/// `gateway_usage_rows_emitted_total`
pub const USAGE_ROWS: &str = "gateway_usage_rows_emitted_total";
/// `gateway_provider_dispatch_failures_total`
pub const PROVIDER_FAILURES: &str = "gateway_provider_dispatch_failures_total";

/// Initialised once at process start via [`install_recorder`]. The
/// `/metrics` handler renders through this handle.
static HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

/// Install the Prometheus recorder. Safe to call repeatedly — first
/// install wins, subsequent calls are no-ops. Used by router builders
/// so test processes that construct multiple routers don't panic on
/// global-recorder collisions.
pub fn install_recorder() {
    let _ = HANDLE.get_or_try_init(|| {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // Best-effort global install — if another crate has already
        // installed one, we still keep our handle for local rendering
        // and swallow the error. This is fine for tests; production
        // runs the gateway as a single binary with a single installer.
        let boxed: Box<dyn metrics::Recorder> = Box::new(recorder);
        let _ = metrics::set_boxed_recorder(boxed);
        describe_metrics();
        // IGW-B-012: surface loudly if the operator token is unset — the
        // /metrics endpoint is fail-closed (401) until it is configured, so
        // an operator expecting a Prometheus scrape gets a clear reason.
        if std::env::var(ENV_METRICS_TOKEN)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_none()
        {
            tracing::warn!(
                "/metrics is DISABLED (fail-closed): set {ENV_METRICS_TOKEN} to a secret \
                 operator bearer token to enable Prometheus scraping. Leaving it unset \
                 keeps per-outcome request/decision counters off the public surface \
                 (IGW-B-012)."
            );
        }
        Ok::<_, std::convert::Infallible>(handle)
    });
}

fn describe_metrics() {
    describe_counter!(
        "gateway_chat_requests_total",
        "Chat completion requests handled, labelled by outcome"
    );
    describe_counter!(
        "gateway_batch_submissions_total",
        "/v1/batch submissions accepted"
    );
    describe_counter!(
        "gateway_api_key_requests_total",
        "API-key layer decisions, labelled by outcome"
    );
    describe_counter!(
        "gateway_usage_rows_emitted_total",
        "Usage rows emitted to UsageStore"
    );
    describe_counter!(
        "gateway_provider_dispatch_failures_total",
        "Provider dispatch failures (pre-failover)"
    );
    // The Prometheus exposer only emits TYPE/HELP lines for metrics
    // that have been registered via the recorder — `describe_*` alone
    // isn't enough in metrics-exporter-prometheus 0.12. Increment each
    // counter by 0 at startup so the HELP text and the initial 0 value
    // show up on the first scrape, giving operators a consistent
    // catalogue from t=0 onward.
    metrics::counter!("gateway_chat_requests_total", 0, "outcome" => "success");
    metrics::counter!("gateway_chat_requests_total", 0, "outcome" => "error");
    metrics::counter!("gateway_batch_submissions_total", 0);
    metrics::counter!("gateway_api_key_requests_total", 0, "outcome" => "funded");
    metrics::counter!("gateway_api_key_requests_total", 0, "outcome" => "exhausted");
    metrics::counter!("gateway_api_key_requests_total", 0, "outcome" => "unknown");
    metrics::counter!("gateway_api_key_requests_total", 0, "outcome" => "revoked");
    metrics::counter!("gateway_usage_rows_emitted_total", 0);
    metrics::counter!("gateway_provider_dispatch_failures_total", 0);
}

/// Authorization outcome for a `/metrics` request. Kept as a pure,
/// side-effect-free decision so it is unit-testable without env or a live
/// server (IGW-B-012).
#[derive(Debug, PartialEq, Eq)]
pub enum MetricsAuth {
    /// Token configured and the presented bearer matched — serve.
    Serve,
    /// No token configured — fail closed (the surface is disabled).
    Unconfigured,
    /// Token configured but the bearer was missing or wrong.
    Unauthorized,
}

/// Constant-time byte-equality so a wrong token can't be recovered by
/// timing the comparison. Defense-in-depth on an operator secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decide whether a `/metrics` request may be served, given the configured
/// operator token (from [`ENV_METRICS_TOKEN`]) and the bearer the caller
/// presented. Fail-closed: an unset/blank token disables the surface.
pub fn metrics_auth_decision(expected: Option<&str>, presented: Option<&str>) -> MetricsAuth {
    match expected.map(str::trim).filter(|s| !s.is_empty()) {
        None => MetricsAuth::Unconfigured,
        Some(tok) => match presented {
            Some(p) if ct_eq(p.as_bytes(), tok.as_bytes()) => MetricsAuth::Serve,
            _ => MetricsAuth::Unauthorized,
        },
    }
}

/// Extract the `Authorization: Bearer <token>` value, if present.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// `GET /metrics` handler. IGW-B-012: gated behind an operator bearer token
/// ([`ENV_METRICS_TOKEN`]). Returns Prometheus text-exposition format only
/// when the recorder is installed AND the caller presents the configured
/// token; a missing/wrong token is 401, and an unconfigured token is 401
/// (fail-closed — the metrics surface must be explicitly enabled).
pub async fn metrics_handler(headers: HeaderMap) -> Response {
    let expected = std::env::var(ENV_METRICS_TOKEN).ok();
    let presented = extract_bearer(&headers);
    match metrics_auth_decision(expected.as_deref(), presented.as_deref()) {
        MetricsAuth::Serve => match HANDLE.get() {
            Some(h) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
                h.render(),
            )
                .into_response(),
            None => (
                StatusCode::SERVICE_UNAVAILABLE,
                "metrics recorder not installed",
            )
                .into_response(),
        },
        MetricsAuth::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            "Authorization: Bearer <operator metrics token> required",
        )
            .into_response(),
        MetricsAuth::Unconfigured => (
            StatusCode::UNAUTHORIZED,
            "/metrics is disabled: set CITRATE_GATEWAY_METRICS_TOKEN to enable it",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_recorder_is_idempotent() {
        install_recorder();
        install_recorder();
        assert!(HANDLE.get().is_some());
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header"),
        );
        h
    }

    #[tokio::test]
    async fn handler_renders_text_exposition_with_token() {
        install_recorder();
        metrics::counter!("gateway_chat_requests_total", 1, "outcome" => "success");
        std::env::set_var(ENV_METRICS_TOKEN, "unit-secret");
        let resp = metrics_handler(bearer("unit-secret")).await;
        std::env::remove_var(ENV_METRICS_TOKEN);
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/plain"));
    }

    // IGW-B-012: the pure decision is fail-closed and constant-time.
    #[test]
    fn metrics_auth_is_fail_closed_and_bound() {
        // No token configured → disabled, regardless of what is presented.
        assert_eq!(
            metrics_auth_decision(None, Some("anything")),
            MetricsAuth::Unconfigured
        );
        assert_eq!(
            metrics_auth_decision(Some("  "), Some("anything")),
            MetricsAuth::Unconfigured
        );
        // Configured but missing / wrong bearer → unauthorized.
        assert_eq!(
            metrics_auth_decision(Some("secret"), None),
            MetricsAuth::Unauthorized
        );
        assert_eq!(
            metrics_auth_decision(Some("secret"), Some("wrong")),
            MetricsAuth::Unauthorized
        );
        // Correct bearer → serve.
        assert_eq!(
            metrics_auth_decision(Some("secret"), Some("secret")),
            MetricsAuth::Serve
        );
    }

    // IGW-B-012 tripwire: an unauthenticated GET /metrics must NOT render
    // the Prometheus catalogue — it is 401, not 200. This is the RED case
    // (pre-fix the handler always returned 200 with the exposition).
    #[tokio::test]
    async fn unauthenticated_metrics_is_rejected() {
        install_recorder();
        std::env::remove_var(ENV_METRICS_TOKEN);
        // No token configured → fail closed even with no auth header.
        let resp = metrics_handler(HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Token configured but caller presents none / a wrong one → 401.
        std::env::set_var(ENV_METRICS_TOKEN, "unit-secret");
        let resp = metrics_handler(HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = metrics_handler(bearer("nope")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        std::env::remove_var(ENV_METRICS_TOKEN);
    }
}
