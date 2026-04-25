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

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use metrics::describe_counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;

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

/// `GET /metrics` handler. Returns Prometheus text-exposition format
/// if the recorder is installed; otherwise a 503 so monitors page us
/// loudly instead of silently scraping nothing.
pub async fn metrics_handler() -> Response {
    match HANDLE.get() {
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

    #[tokio::test]
    async fn handler_renders_text_exposition() {
        install_recorder();
        metrics::counter!("gateway_chat_requests_total", 1, "outcome" => "success");
        let resp = metrics_handler().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/plain"));
    }
}
