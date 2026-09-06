//! Local-proxy mode (WP-1 + WP-4 of 2026-06-04 planset).
//!
//! Wraps an existing OpenAI-shaped HTTP server (in production: the resident
//! `llama-server` on `127.0.0.1:8081`) behind a `cgk_` bearer-key gate.
//! Distinct from [`crate::build_router`] and [`crate::build_router_with_auth`]:
//! no chain RPC, no x402 settlement, no marketplace dispatch — just an
//! authenticated, rate-limited, SSE-preserving passthrough.
//!
//! # Endpoints
//!
//! - `GET /health` — open; returns `{"ok": true}`.
//! - Anything under `/v1/*` — requires a valid `cgk_` bearer; proxied
//!   verbatim to `CITRATE_GATEWAY_UPSTREAM_URL`. SSE responses stream
//!   through chunk-by-chunk (no buffering).
//!
//! # Outcomes
//!
//! - Missing / malformed `Authorization` → **401**.
//! - Unknown or revoked key → **401**.
//! - Per-second rate exceeded → **429** + `Retry-After: 1`.
//! - Daily quota exceeded → **429** + `Retry-After: <seconds-until-UTC-midnight>`.
//! - Upstream unreachable / 5xx → **502**.
//! - Otherwise → upstream's status + body forwarded.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, Method, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use futures_util::TryStreamExt;
use tower_http::cors::{Any as CorsAny, CorsLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;

use crate::keystore::{ConsumeError, PersistentKeyStore};

/// Hop-by-hop headers per RFC 7230 §6.1 — strip in both directions so we
/// don't accidentally forward them between the client connection and the
/// upstream connection.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Cap on request bodies the proxy will accept. 8 MiB is generous for chat
/// completions (system + user messages plus a few JSON-shape fields) and
/// stops a malformed client from forcing the proxy to buffer megabytes.
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// Shared state for the local-proxy router. Cheap to clone (all Arc / Client).
#[derive(Clone)]
pub struct LocalProxyState {
    /// Persistent key/quota store.
    pub store: Arc<PersistentKeyStore>,
    /// One or more OpenAI-compatible upstreams. Tried in order on
    /// connection / 5xx failure (mirrors Caddy's `lb_policy first`); the
    /// first successful response is returned. Singleton is the common
    /// case (`http://127.0.0.1:8181`). On the production droplet this
    /// is `<DGX-tailscale>, <local-CPU>`.
    pub upstreams: Vec<String>,
    /// HTTP client used to talk to the upstream(s).
    pub http: reqwest::Client,
}

impl LocalProxyState {
    /// Construct from the env-driven values main.rs assembles.
    /// `upstreams` must be non-empty.
    pub fn new(store: Arc<PersistentKeyStore>, upstreams: Vec<String>) -> Self {
        assert!(
            !upstreams.is_empty(),
            "LocalProxyState requires at least one upstream"
        );
        let http = reqwest::Client::builder()
            // Long enough to cover an uncached system prompt on the CPU
            // box (~70s cold) plus generation; mirrors the chatbot
            // route's 300s maxDuration from TLS_Handoff.md §2.
            .timeout(Duration::from_secs(300))
            .build()
            .expect("reqwest::Client builds with rustls defaults");
        Self {
            store,
            upstreams,
            http,
        }
    }
}

/// Assemble the axum router for local-proxy mode. The TraceLayer goes
/// **after** the redaction layer so `Authorization` is already marked
/// sensitive before spans are recorded.
pub fn build_local_proxy_router(state: LocalProxyState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(CorsAny)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(CorsAny);

    let redact = SetSensitiveRequestHeadersLayer::new([header::AUTHORIZATION]);

    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/*rest", any(proxy_handler))
        .layer(cors)
        .layer(redact)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "ok": true }))
}

/// Authenticates + meters the request, then forwards to upstream
/// preserving the response stream.
async fn proxy_handler(
    State(state): State<LocalProxyState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    let key_id = match extract_bearer(&headers) {
        Some(k) => k,
        None => return json_error(StatusCode::UNAUTHORIZED, "missing api key"),
    };

    // The proxy is mounted under /v1/, but the outbound URL builder and
    // upstream HTTP stack may normalize dot segments. Reject them at this
    // boundary before quota consumption or forwarding so neither raw nor
    // percent-encoded traversal can escape the intended route prefix.
    if contains_dot_segment(uri.path()) {
        return json_error(StatusCode::BAD_REQUEST, "dot-segment path is not allowed");
    }

    let consumed = match state.store.try_consume(&key_id) {
        Ok(c) => c,
        Err(ConsumeError::Unknown) => {
            return json_error(StatusCode::UNAUTHORIZED, "unknown api key")
        }
        Err(ConsumeError::Revoked) => {
            return json_error(StatusCode::UNAUTHORIZED, "api key revoked")
        }
        Err(ConsumeError::RateLimited { retry_after_secs }) => {
            return rate_limited(retry_after_secs, "rate limit exceeded");
        }
        Err(ConsumeError::DailyQuotaExceeded { retry_after_secs }) => {
            return rate_limited(retry_after_secs, "daily quota exceeded");
        }
        Err(ConsumeError::Store(e)) => {
            tracing::error!(error = %e, "keystore unavailable");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
        // ENCRYPT-S1: an undecryptable record is a store-integrity problem
        // (wrong key / tampering), never an auth verdict — 500, not 401.
        Err(ConsumeError::Crypt(e)) => {
            tracing::error!(error = %e, "keystore crypto failure");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal");
        }
    };

    tracing::info!(
        key_label = %consumed.label,
        key_hash_prefix = %&consumed.hash[..16.min(consumed.hash.len())],
        %method,
        path = %uri.path(),
        "proxy"
    );

    // Build the request shape once; we'll retry it across upstreams on
    // failure. `uri.path_and_query` includes `?…` if present
    // (e.g. `/v1/models?limit=100`).
    let path_q = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_else(|| uri.path());

    // Strip hop-by-hop + our bearer before forwarding. The bearer is OURS;
    // the upstream llama-server doesn't need it (and shouldn't see it).
    let mut forward = headers.clone();
    forward.remove(header::AUTHORIZATION);
    forward.remove(header::HOST);
    strip_hop_by_hop(&mut forward);

    let body_bytes = match axum::body::to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, &format!("body read: {e}")),
    };

    let reqw_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);

    // Try each upstream in order. Connection-level failure or a 5xx
    // status falls over to the next. 2xx/3xx/4xx from an upstream is
    // authoritative — return immediately.
    let mut last_err: Option<String> = None;
    let mut upstream_resp = None;
    for upstream in &state.upstreams {
        let url = format!("{}{}", upstream.trim_end_matches('/'), path_q);
        let attempt = state
            .http
            .request(reqw_method.clone(), &url)
            .headers(forward.clone())
            .body(body_bytes.to_vec())
            .send()
            .await;
        match attempt {
            Ok(r) if r.status().is_server_error() => {
                tracing::warn!(upstream = %url, status = %r.status(), "upstream 5xx, trying next");
                last_err = Some(format!("upstream 5xx: {}", r.status()));
                continue;
            }
            Ok(r) => {
                upstream_resp = Some(r);
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, upstream = %url, "upstream request failed, trying next");
                last_err = Some(e.to_string());
                continue;
            }
        }
    }
    let upstream_resp = match upstream_resp {
        Some(r) => r,
        None => {
            tracing::error!(error = ?last_err, "all upstreams failed");
            return json_error(StatusCode::BAD_GATEWAY, "upstream unreachable");
        }
    };

    let status = upstream_resp.status();
    let mut resp_headers = upstream_resp.headers().clone();
    strip_hop_by_hop(&mut resp_headers);
    // Let axum recompute content-length when we re-stream the body.
    resp_headers.remove(header::CONTENT_LENGTH);

    // SSE preserved: bytes_stream() yields chunks as they arrive without
    // buffering the whole response. This is the streaming-critical path —
    // never collect() / bytes() / text() the upstream response.
    let stream = upstream_resp
        .bytes_stream()
        .map_ok(Bytes::from)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    let body = Body::from_stream(stream);

    let mut out = Response::new(body);
    *out.status_mut() = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK);
    *out.headers_mut() = resp_headers;
    out
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn contains_dot_segment(path: &str) -> bool {
    let decoded = percent_decode_path(path);
    decoded
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
}

fn percent_decode_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (
                hex_value(bytes[index + 1]),
                hex_value(bytes[index + 2]),
            ) {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn strip_hop_by_hop(h: &mut HeaderMap) {
    for name in HOP_BY_HOP {
        if let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) {
            h.remove(hn);
        }
    }
}

fn json_error(code: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": { "message": msg } }).to_string();
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = code;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("static"),
    );
    r
}

fn rate_limited(retry_after_secs: u64, msg: &str) -> Response<Body> {
    let mut r = json_error(StatusCode::TOO_MANY_REQUESTS, msg);
    if let Ok(v) = retry_after_secs.to_string().parse() {
        r.headers_mut().insert(header::RETRY_AFTER, v);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test master key for the at-rest store encryption (ENCRYPT-S1).
    const TEST_MASTER: [u8; 32] = [7u8; 32];
    use axum::http::Request;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tempfile::tempdir;
    use tower::ServiceExt;

    /// Spin up an in-process upstream that mimics llama-server's
    /// `/v1/chat/completions`, with optional SSE.
    async fn spawn_upstream(sse: bool) -> SocketAddr {
        use axum::extract::Query;
        use axum::routing::post;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Q {}

        let app = Router::new().route(
            "/v1/chat/completions",
            post(move |Query(_q): Query<Q>, body: Bytes| async move {
                if sse {
                    let mut r = Response::new(Body::from(
                        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n\
                         data: [DONE]\n\n",
                    ));
                    r.headers_mut().insert(
                        header::CONTENT_TYPE,
                        "text/event-stream".parse().unwrap(),
                    );
                    r
                } else {
                    let _ = body; // suppress unused
                    let mut r = Response::new(Body::from(
                        r#"{"choices":[{"message":{"role":"assistant","content":"OK"}}]}"#,
                    ));
                    r.headers_mut().insert(
                        header::CONTENT_TYPE,
                        "application/json".parse().unwrap(),
                    );
                    r
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        addr
    }

    async fn spawn_recording_upstream(paths: Arc<Mutex<Vec<String>>>) -> SocketAddr {
        let app = Router::new().fallback(any(move |uri: Uri| {
            let paths = paths.clone();
            async move {
                paths.lock().expect("paths mutex").push(uri.path().to_string());
                (StatusCode::OK, "ok")
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind recording upstream");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("recording upstream serve");
        });
        addr
    }

    fn router_with(store: Arc<PersistentKeyStore>, upstream: String) -> Router {
        let state = LocalProxyState::new(store, vec![upstream]);
        build_local_proxy_router(state)
    }

    #[tokio::test]
    async fn health_is_open() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let app = router_with(store, "http://127.0.0.1:1".into());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_bearer_is_401() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let app = router_with(store, "http://127.0.0.1:1".into());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_bearer_is_401() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let app = router_with(store, "http://127.0.0.1:1".into());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(header::AUTHORIZATION, "Bearer cgk_does_not_exist")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoked_bearer_is_401() {
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let id = store.create_key("t", 0, 0).unwrap();
        store.revoke(&id).unwrap();
        let app = router_with(store, "http://127.0.0.1:1".into());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(header::AUTHORIZATION, format!("Bearer {id}"))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_key_proxies_to_upstream() {
        let upstream_addr = spawn_upstream(false).await;
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let id = store.create_key("ok", 0, 0).unwrap();
        let app = router_with(store, format!("http://{upstream_addr}"));

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(header::AUTHORIZATION, format!("Bearer {id}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""content":"OK""#), "got: {s}");
    }

    #[tokio::test]
    async fn sse_response_is_forwarded() {
        let upstream_addr = spawn_upstream(true).await;
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let id = store.create_key("sse", 0, 0).unwrap();
        let app = router_with(store, format!("http://{upstream_addr}"));

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(header::AUTHORIZATION, format!("Bearer {id}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .map(|v| v.to_str().unwrap()),
            Some("text/event-stream"),
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("[DONE]"));
    }

    /// First upstream is unreachable / 5xx → gateway transparently
    /// falls over to the second. Mirrors the production deploy's DGX-
    /// primary / CPU-fallback shape.
    #[tokio::test]
    async fn upstream_failover_returns_second_response() {
        // First "upstream" is just a bogus port nothing listens on.
        let dead = "http://127.0.0.1:1";
        let live_addr = spawn_upstream(false).await;
        let live = format!("http://{live_addr}");

        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let id = store.create_key("failover", 0, 0).unwrap();
        let state = LocalProxyState::new(store, vec![dead.into(), live]);
        let app = build_local_proxy_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(header::AUTHORIZATION, format!("Bearer {id}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""content":"OK""#), "got: {s}");
    }

    #[tokio::test]
    async fn rate_limit_returns_429_with_retry_after() {
        let upstream_addr = spawn_upstream(false).await;
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let id = store.create_key("rl", 2, 0).unwrap(); // 2 rps
        let upstream = format!("http://{upstream_addr}");

        // First two succeed.
        for _ in 0..2 {
            let app = router_with(store.clone(), upstream.clone());
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/chat/completions")
                        .header(header::AUTHORIZATION, format!("Bearer {id}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        // Third in the same second is 429.
        let app = router_with(store, upstream);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(header::AUTHORIZATION, format!("Bearer {id}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get(header::RETRY_AFTER).is_some());
    }

    /// IGW-B-005 RC-8 tripwire: an authenticated local-proxy request must not
    /// use raw or percent-encoded dot segments to escape the `/v1/` prefix.
    #[tokio::test]
    async fn dot_segments_are_rejected_before_upstream() {
        let paths = Arc::new(Mutex::new(Vec::new()));
        let upstream_addr = spawn_recording_upstream(paths.clone()).await;
        let dir = tempdir().unwrap();
        let store = PersistentKeyStore::open(dir.path(), TEST_MASTER).unwrap();
        let id = store.create_key("dot-segments", 0, 0).unwrap();

        for path in [
            "/v1/../x",
            "/v1/%2e%2e/x",
            "/v1/a/../../x",
            "/v1/.%2e/x",
        ] {
            let app = router_with(store.clone(), format!("http://{upstream_addr}"));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(header::AUTHORIZATION, format!("Bearer {id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "path: {path}");
        }

        assert!(
            paths.lock().expect("paths mutex").is_empty(),
            "dot-segment requests must never reach the upstream"
        );
    }
}
