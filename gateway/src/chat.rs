//! `/v1/chat/completions` handler.
//!
//! Flow (assuming x402 has already settled — the `X402Layer`
//! middleware takes care of payment before this runs):
//!
//! 1. Parse the OpenAI-shape request body.
//! 2. Resolve `request.model` → modelHash via `ChainQueries`.
//! 3. List providers for that model.
//! 4. Pick best via `provider::select_provider`. On failure, fall
//!    back to the next-best (filter the failed one out, re-select).
//!    Up to `MAX_PROVIDER_ATTEMPTS` total before surfacing 503.
//! 5. Build Provider Protocol payload.
//! 6. Dispatch to provider with timeout.
//! 7. Translate provider response → OpenAI shape, OR stream as SSE
//!    if `stream: true`.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use futures_util::stream::{self, Stream};
use uuid::Uuid;

use x402_axum::X402Paid;

use crate::error::GatewayError;
use crate::openai::{ChatCompletionRequest, ChatCompletionResponse, ChatMessage, Choice, Usage};
use crate::provider::{dispatch_to_provider, select_provider, ProviderProtocolRequest};
use crate::usage::ApiKeyContext;
use crate::SharedState;

/// Default per-request provider HTTPS timeout.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(60);

/// Default max output tokens when caller doesn't specify.
const DEFAULT_MAX_TOKENS: u32 = 512;

/// How many providers to try before giving up on a request. The
/// first attempt is the highest-scored provider; each subsequent
/// attempt picks the next-best from the remaining candidates.
const MAX_PROVIDER_ATTEMPTS: usize = 3;

/// Convert a `GatewayError` into an HTTP response with a JSON body.
impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = Json(serde_json::json!({
            "error": {
                "message": self.to_string(),
            }
        }));
        (status, body).into_response()
    }
}

/// `POST /v1/chat/completions` handler.
///
/// Returns either a JSON `ChatCompletionResponse` (default) or an
/// SSE stream (when `stream: true`). Both wrapped in
/// `axum::response::Response` to share one return type.
pub async fn chat_completions_handler(
    State(state): State<SharedState>,
    api_key: Option<Extension<ApiKeyContext>>,
    paid: Option<Extension<X402Paid>>,
    Json(req): Json<ChatCompletionRequest>,
) -> Result<Response, GatewayError> {
    if req.messages.is_empty() {
        return Err(GatewayError::BadRequest("messages must be non-empty".into()));
    }

    let dispatch = match run_dispatch(&state, &req).await {
        Ok(d) => {
            metrics::counter!("gateway_chat_requests_total", 1, "outcome" => "success");
            d
        }
        Err(e) => {
            metrics::counter!("gateway_chat_requests_total", 1, "outcome" => "error");
            return Err(e);
        }
    };

    // WP-03.5: successful, API-key-authenticated requests emit one
    // usage row. Anonymous x402 requests (no ApiKeyContext) are NOT
    // tracked — usage is a per-identity resource.
    if let (Some(Extension(ctx)), Some(Extension(pay))) = (&api_key, &paid) {
        state
            .usage
            .record(
                &ctx.key_id,
                dispatch.prompt_tokens,
                dispatch.completion_tokens,
                pay.amount_wei,
            )
            .await;
        metrics::counter!("gateway_usage_rows_emitted_total", 1);
    }

    if req.stream {
        Ok(stream_response(req, dispatch).into_response())
    } else {
        Ok(Json(json_response(req, dispatch)).into_response())
    }
}

/// Bundles together what the dispatch path produced — provider
/// output + token counts + the prompt we built (for empty-token
/// fallback in the SSE path).
pub(crate) struct DispatchOutcome {
    pub(crate) output: String,
    pub(crate) prompt: String,
    pub(crate) prompt_tokens: u32,
    pub(crate) completion_tokens: u32,
}

/// Resolve model + provider + dispatch with failover. Returns the
/// raw provider output + token counts.
pub(crate) async fn run_dispatch(
    state: &SharedState,
    req: &ChatCompletionRequest,
) -> Result<DispatchOutcome, GatewayError> {
    // Resolve model name via ModelRegistry.
    let model_hash = state
        .queries
        .resolve_model_name(&req.model)
        .await
        .map_err(|_| GatewayError::UnknownModel(req.model.clone()))?;

    // List providers.
    let mut providers = state
        .queries
        .list_providers(model_hash)
        .await
        .map_err(|e| GatewayError::ChainUnavailable(e.to_string()))?;

    if providers.is_empty() {
        return Err(GatewayError::NoProviders);
    }

    // Build the prompt once; reused across attempts.
    let prompt = req
        .messages
        .iter()
        .map(|m| format!("{}: {}", m.role, m.content))
        .collect::<Vec<_>>()
        .join("\n");
    let provider_req = ProviderProtocolRequest {
        model: req.model.clone(),
        prompt: prompt.clone(),
        max_tokens: req.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS),
    };

    // Failover loop: try up to MAX_PROVIDER_ATTEMPTS providers,
    // removing each failed one from the candidate pool so the
    // re-selection picks the next-best, never the same one twice.
    let mut last_err: Option<GatewayError> = None;
    for _ in 0..MAX_PROVIDER_ATTEMPTS {
        let chosen = match select_provider(&providers) {
            Some(p) => p,
            None => break, // pool exhausted (all at capacity)
        };
        let chosen_addr = chosen.address;

        match dispatch_to_provider(&state.http, chosen, &provider_req, PROVIDER_TIMEOUT).await {
            Ok(resp) => {
                let prompt_tokens = resp
                    .input_tokens
                    .unwrap_or_else(|| prompt.split_whitespace().count() as u32);
                let completion_tokens = resp
                    .output_tokens
                    .unwrap_or_else(|| resp.output.split_whitespace().count() as u32);
                return Ok(DispatchOutcome {
                    output: resp.output,
                    prompt,
                    prompt_tokens,
                    completion_tokens,
                });
            }
            Err(e) => {
                tracing::warn!(
                    provider = %hex::encode(chosen_addr.as_bytes()),
                    error = %e,
                    "provider dispatch failed, trying next"
                );
                metrics::counter!("gateway_provider_dispatch_failures_total", 1);
                last_err = Some(e);
                // Remove the failed provider from the pool; selector
                // picks the next-best on the next iteration.
                providers.retain(|p| p.address != chosen_addr);
            }
        }
    }

    // All attempts exhausted — surface the last error (always
    // ProviderUnavailable from dispatch_to_provider). If we burned
    // through MAX_PROVIDER_ATTEMPTS without a single success, the
    // caller sees 503 with the most recent provider's failure.
    Err(last_err.unwrap_or(GatewayError::NoProviders))
}

pub(crate) fn json_response(req: ChatCompletionRequest, d: DispatchOutcome) -> ChatCompletionResponse {
    let _ = d.prompt; // not needed in JSON path
    ChatCompletionResponse {
        id: format!("chatcmpl-{}", Uuid::new_v4()),
        object: "chat.completion",
        created: now_unix_secs(),
        model: req.model,
        choices: vec![Choice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: d.output,
            },
            finish_reason: "stop",
        }],
        usage: Usage::new(d.prompt_tokens, d.completion_tokens),
    }
}

/// Build the SSE stream response. We don't actually stream from
/// the provider yet (Provider Protocol v1 doesn't define a
/// streaming variant); the gateway emits the full output as a
/// single `data: {chunk}` event followed by `data: [DONE]`. Real
/// chunk-streaming lands once the Provider Protocol has a
/// /infer/stream endpoint, in CM-05 era.
fn stream_response(
    req: ChatCompletionRequest,
    d: DispatchOutcome,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let id = format!("chatcmpl-{}", Uuid::new_v4());
    let model = req.model.clone();
    let created = now_unix_secs();

    // Two events: one delta carrying the full output, then [DONE].
    let chunk = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": { "role": "assistant", "content": d.output },
            "finish_reason": "stop"
        }]
    });
    let chunk_str = chunk.to_string();
    let events = vec![
        Ok::<_, Infallible>(Event::default().data(chunk_str)),
        Ok::<_, Infallible>(Event::default().data("[DONE]")),
    ];
    let stream = stream::iter(events);
    Sse::new(stream).keep_alive(KeepAlive::default())
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
