//! INFER WP-A — API-key wall (local-proxy mode) smoke test.
//!
//! Closes the P0 open-GPU-endpoint risk: `infer.citrate.ai` currently
//! answers unauthenticated `POST /v1/chat/completions` with a real
//! completion. These tests assert that in local-proxy mode:
//!
//!   * unauthenticated `/v1/chat/completions` → 401 AND the upstream is
//!     never called (no GPU touched),
//!   * unknown / revoked key → 401 (and no upstream call),
//!   * a valid funded key → 200 and the upstream SSE stream is passed
//!     through CHUNKED (streaming preserved, not buffered into one
//!     blob),
//!   * `/health` stays open.
//!
//! The upstream is a tiny axum server returning an SSE stream — no real
//! llama-server required. It increments a shared counter on every hit
//! so we can assert "no upstream call" for the rejected paths.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::post;
use ethereum_types::{H160, U256};
use futures_util::StreamExt;
use tokio::net::TcpListener;

use citrate_gateway::auth::{create_key, ApiKeyStore};
use citrate_gateway::build_local_proxy_router;

/// Mock upstream: an OpenAI-compatible `/v1/chat/completions` that
/// returns an SSE stream of three `data:` frames, each in its own
/// chunk, then `[DONE]`. Increments `hits` on every request so the
/// tests can assert the rejected paths never reach it.
async fn spawn_mock_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route("/v1/chat/completions", post(sse_handler))
        .with_state(hits.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream serve");
    });
    (addr, hits)
}

async fn sse_handler(State(hits): State<Arc<AtomicUsize>>) -> Response {
    hits.fetch_add(1, Ordering::SeqCst);
    // Emit each frame as a separate chunk with a small delay so a
    // buffering proxy would visibly collapse them; a streaming proxy
    // forwards them as they arrive.
    let frames = vec![
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"!\"}}]}\n\n",
        "data: [DONE]\n\n",
    ];
    let stream = futures_util::stream::iter(frames.into_iter().map(|f| {
        Ok::<_, std::io::Error>(axum::body::Bytes::from(f))
    }))
    .then(|item| async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        item
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("sse response")
}

async fn spawn_proxy(upstream: SocketAddr, keys: Arc<ApiKeyStore>) -> SocketAddr {
    let upstream_url = format!("http://{}", upstream);
    let app = build_local_proxy_router(keys, upstream_url);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("proxy serve");
    });
    addr
}

fn chat_body() -> serde_json::Value {
    serde_json::json!({
        "model": "llama-3.1-8b",
        "messages": [{"role": "user", "content": "ping"}],
        "stream": true
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn unauthenticated_chat_is_401_and_never_touches_upstream() {
    let (upstream, hits) = spawn_mock_upstream().await;
    let keys = Arc::new(ApiKeyStore::new());
    let proxy = spawn_proxy(upstream, keys).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{}/v1/chat/completions", proxy))
        .json(&chat_body())
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 401, "open endpoint must be closed");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no GPU/upstream call may happen for an unauthenticated request"
    );
}

#[tokio::test]
async fn unknown_key_is_401_and_never_touches_upstream() {
    let (upstream, hits) = spawn_mock_upstream().await;
    let keys = Arc::new(ApiKeyStore::new());
    let proxy = spawn_proxy(upstream, keys).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{}/v1/chat/completions", proxy))
        .header("Authorization", "Bearer cgk_not-a-real-key")
        .json(&chat_body())
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 401);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn revoked_key_is_401_and_never_touches_upstream() {
    let (upstream, hits) = spawn_mock_upstream().await;
    let keys = Arc::new(ApiKeyStore::new());
    let initial = U256::from(1000u64);
    let key_id = create_key(&keys, "pilot", initial, H160::zero()).await;
    keys.revoke(&key_id).await.expect("revoke");
    let proxy = spawn_proxy(upstream, keys).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{}/v1/chat/completions", proxy))
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&chat_body())
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 401);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn valid_key_streams_sse_passthrough_chunked() {
    let (upstream, hits) = spawn_mock_upstream().await;
    let keys = Arc::new(ApiKeyStore::new());
    let initial = U256::from(1000u64);
    let key_id = create_key(&keys, "pilot", initial, H160::zero()).await;
    let proxy = spawn_proxy(upstream, keys.clone()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{}/v1/chat/completions", proxy))
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&chat_body())
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 200, "valid key should reach upstream");
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        ctype.contains("text/event-stream"),
        "SSE content-type must be preserved, got: {ctype}"
    );

    // Drain the response as a STREAM. Assert we observe more than one
    // chunk arriving over time — proof the proxy didn't buffer the
    // whole body into a single blob.
    let mut stream = resp.bytes_stream();
    let mut chunk_count = 0usize;
    let mut assembled = Vec::new();
    while let Some(item) = stream.next().await {
        let bytes = item.expect("chunk");
        chunk_count += 1;
        assembled.extend_from_slice(&bytes);
    }

    let text = String::from_utf8_lossy(&assembled);
    assert!(text.contains("Hel"), "first frame present: {text}");
    assert!(text.contains("[DONE]"), "terminal frame present: {text}");
    assert!(
        chunk_count >= 2,
        "expected multiple streamed chunks (SSE preserved), got {chunk_count}"
    );

    assert_eq!(hits.load(Ordering::SeqCst), 1, "upstream hit exactly once");

    // Metering: the flat per-request grain was debited.
    let record = keys.get(&key_id).await.expect("key exists");
    assert_eq!(record.balance_grains, initial - U256::from(1u64));
}

#[tokio::test]
async fn health_is_open_without_a_key() {
    let (upstream, _hits) = spawn_mock_upstream().await;
    let keys = Arc::new(ApiKeyStore::new());
    let proxy = spawn_proxy(upstream, keys).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::get(format!("http://{}/health", proxy))
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["ok"].as_bool(), Some(true));
}

#[tokio::test]
async fn exhausted_key_is_401_and_never_touches_upstream() {
    let (upstream, hits) = spawn_mock_upstream().await;
    let keys = Arc::new(ApiKeyStore::new());
    // Zero balance — first request can't pay the flat per-request grain.
    let key_id = create_key(&keys, "broke", U256::zero(), H160::zero()).await;
    let proxy = spawn_proxy(upstream, keys).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{}/v1/chat/completions", proxy))
        .header("Authorization", format!("Bearer {}", key_id))
        .json(&chat_body())
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), 401);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
