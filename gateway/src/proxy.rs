//! INFER WP-A — API-key wall over an OpenAI passthrough (local-proxy
//! mode). Closes the P0 open-GPU-endpoint risk: `infer.citrate.ai`
//! currently answers unauthenticated `POST /v1/chat/completions` with a
//! real completion. In `CITRATE_GATEWAY_MODE=local-proxy` this router
//! puts every `/v1/*` route behind a valid `cgk_` API key and forwards
//! authenticated requests verbatim to the resident `llama-server`
//! (default `http://127.0.0.1:8081`), **streaming the response body
//! end-to-end so SSE (`stream: true`) is preserved without buffering**.
//!
//! Layering vs. the marketplace router: the marketplace mode (default,
//! unchanged) settles payment on-chain via `X402Layer`. Local-proxy
//! mode has no chain in the hot path — the upstream is a local GPU — so
//! metering is a flat per-request debit against the persistent
//! [`ApiKeyStore`] (reuses the same atomic `debit`/`refund` path, so
//! WP-B durability + RM-B1 refund-on-error semantics carry over).
//!
//! Security invariants:
//!   * `/health` is OPEN; every `/v1/*` route requires a valid key.
//!   * Missing / unknown / revoked / exhausted key → `401` and **no
//!     upstream call is made** (no GPU is touched).
//!   * `Authorization` is marked sensitive (never logged) — the router
//!     installs the same `redact_authorization()` layer the other
//!     modes use.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode, Uri};
use axum::routing::get;
use axum::Router;
use ethereum_types::U256;
use futures_util::TryStreamExt;
use tower::{Layer, Service};
use tower_http::trace::TraceLayer;

use crate::auth::{extract_bearer, ApiKeyStore, DebitError};
use crate::redact_authorization;

/// Flat per-request debit (in the key's balance unit) applied in
/// local-proxy mode. The resident `llama-server` isn't priced by the
/// chain oracle, so we meter each authenticated request as a unit of
/// the key's prepaid balance. Refunded if the upstream errors.
pub const LOCAL_PROXY_PER_REQUEST_GRAINS: u64 = 1;

/// Build the local-proxy router (INFER WP-A).
///
/// `store` is the (optionally RocksDB-backed) key store; `upstream_url`
/// is the OpenAI-compatible base URL of the resident model server
/// (e.g. `http://127.0.0.1:8081`). `/v1/*` is walled behind a valid
/// `cgk_` key; `/health` stays open.
pub fn build_local_proxy_router(store: Arc<ApiKeyStore>, upstream_url: String) -> Router {
    crate::metrics::install_recorder();
    let upstream = Arc::new(upstream_url.trim_end_matches('/').to_string());
    // A streaming reqwest client: no response buffering, so SSE chunks
    // flow straight through.
    let client = reqwest::Client::new();

    let proxy_state = ProxyState {
        client,
        upstream: upstream.clone(),
    };

    // The walled subtree: every route here requires a valid key.
    let walled = Router::new()
        .fallback(proxy_handler)
        .layer(ApiKeyWallLayer { store })
        .with_state(proxy_state);

    Router::new()
        .route("/health", get(crate::health::health_handler))
        .nest("/v1", walled)
        .layer(redact_authorization())
        .layer(TraceLayer::new_for_http())
}

#[derive(Clone)]
struct ProxyState {
    client: reqwest::Client,
    upstream: Arc<String>,
}

// ── The wall: 401 unless a valid, funded key is present ──────────────

/// Tower layer that fronts the proxy with the API-key wall. Unlike
/// [`crate::auth::ApiKeyLayer`] (which passes unauthenticated requests
/// through to the x402 challenge), this layer **rejects** any request
/// without a valid, funded `cgk_` key with `401` and never calls the
/// inner service — so no GPU work happens for an unauthorized request.
#[derive(Clone)]
struct ApiKeyWallLayer {
    store: Arc<ApiKeyStore>,
}

impl<S> Layer<S> for ApiKeyWallLayer {
    type Service = ApiKeyWallService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ApiKeyWallService {
            inner,
            store: self.store.clone(),
        }
    }
}

#[derive(Clone)]
struct ApiKeyWallService<S> {
    inner: S,
    store: Arc<ApiKeyStore>,
}

impl<S> Service<Request<Body>> for ApiKeyWallService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let store = self.store.clone();
        let inner_ready = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, inner_ready);

        Box::pin(async move {
            // No Bearer key → 401, no upstream call.
            let Some(key_id) = extract_bearer(req.headers()) else {
                metrics::counter!("gateway_local_proxy_requests_total", 1, "outcome" => "missing");
                return Ok(build_401("missing api key"));
            };

            // Unknown / revoked → 401, no upstream call.
            let Some(record) = store.get(&key_id).await else {
                metrics::counter!("gateway_local_proxy_requests_total", 1, "outcome" => "unknown");
                return Ok(build_401("unknown api key"));
            };
            if record.revoked {
                metrics::counter!("gateway_local_proxy_requests_total", 1, "outcome" => "revoked");
                return Ok(build_401("api key revoked"));
            }

            // Flat per-request debit. Atomic + (when RocksDB-backed)
            // durable. Exhausted / insufficient → 401, no upstream call.
            let price = U256::from(LOCAL_PROXY_PER_REQUEST_GRAINS);
            match store.debit(&key_id, price).await {
                Ok(_) => {}
                Err(DebitError::Insufficient(_)) => {
                    metrics::counter!("gateway_local_proxy_requests_total", 1, "outcome" => "exhausted");
                    return Ok(build_401("api key balance exhausted"));
                }
                Err(_) => {
                    metrics::counter!("gateway_local_proxy_requests_total", 1, "outcome" => "denied");
                    return Ok(build_401("api key not usable"));
                }
            }

            metrics::counter!("gateway_local_proxy_requests_total", 1, "outcome" => "funded");
            let mut inner = inner;
            let resp = inner.call(req).await?;

            // RM-B1: refund the debit if the upstream failed, so a 5xx
            // from the GPU doesn't burn the buyer's balance.
            if !resp.status().is_success() {
                if let Err(err) = store.refund(&key_id, price).await {
                    tracing::warn!(error = ?err, "local-proxy refund after upstream error failed");
                }
            }
            Ok(resp)
        })
    }
}

// ── The passthrough: forward to upstream, stream the body ────────────

/// Forward the authenticated request to the upstream OpenAI-compatible
/// server and **stream** the response body back without buffering, so
/// SSE (`text/event-stream`) is preserved chunk-for-chunk.
async fn proxy_handler(
    axum::extract::State(state): axum::extract::State<ProxyState>,
    req: Request<Body>,
) -> Response<Body> {
    let (parts, body) = req.into_parts();

    // Rebuild the upstream path: this handler is the fallback under the
    // `/v1` nest, so `parts.uri` is the path *after* `/v1`. Re-prefix it.
    let suffix = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let upstream_uri = format!("{}/v1{}", state.upstream, suffix);

    // Stream the request body upstream (don't buffer large prompts).
    let body_stream = body.into_data_stream();
    let reqwest_body = reqwest::Body::wrap_stream(body_stream);

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);

    let mut outbound = state.client.request(method, &upstream_uri).body(reqwest_body);

    // Forward request headers faithfully (model, stream flag, etc. live
    // in the JSON body; content-type / accept must be carried). Drop
    // hop-by-hop + host headers.
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) || name == header::HOST {
            continue;
        }
        outbound = outbound.header(name.as_str(), value.as_bytes());
    }

    let upstream_resp = match outbound.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, uri = %redact_uri(&parts.uri), "upstream proxy call failed");
            return build_502("upstream unavailable");
        }
    };

    // Build the downstream response, streaming the upstream body.
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (name, value) in upstream_resp.headers().iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    // Stream the upstream bytes straight through — no `.bytes()` /
    // `.collect()`, so an SSE stream stays chunked end-to-end.
    let stream = upstream_resp
        .bytes_stream()
        .map_err(std::io::Error::other);
    let downstream_body = Body::from_stream(stream);

    builder
        .body(downstream_body)
        .unwrap_or_else(|_| build_502("malformed upstream response"))
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

/// Strip any query string before logging a URI (paths only).
fn redact_uri(uri: &Uri) -> String {
    uri.path().to_string()
}

fn build_401(msg: &str) -> Response<Body> {
    json_error(StatusCode::UNAUTHORIZED, msg)
}

fn build_502(msg: &str) -> Response<Body> {
    json_error(StatusCode::BAD_GATEWAY, msg)
}

fn json_error(status: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": { "message": msg } }).to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
