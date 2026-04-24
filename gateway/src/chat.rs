//! `/v1/chat/completions` handler.
//!
//! Flow (assuming x402 has already settled — the `X402Layer`
//! middleware takes care of payment before this runs):
//!
//! 1. Parse the OpenAI-shape request body.
//! 2. Resolve `request.model` → modelHash via `ChainQueries`.
//! 3. List providers for that model.
//! 4. Pick best via `provider::select_provider`.
//! 5. Build Provider Protocol payload.
//! 6. Dispatch to provider with timeout.
//! 7. Translate provider response → OpenAI shape.
//!
//! Failure modes:
//! - `UnknownModel` → 400
//! - `NoProviders` → 503
//! - `ProviderUnavailable` → 503 (next WP adds failover-then-503)
//! - `ChainUnavailable` → 503

use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use uuid::Uuid;

use crate::error::GatewayError;
use crate::openai::{ChatCompletionRequest, ChatCompletionResponse, ChatMessage, Choice, Usage};
use crate::provider::{dispatch_to_provider, select_provider, ProviderProtocolRequest};
use crate::SharedState;

/// Default per-request provider HTTPS timeout.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(60);

/// Default max output tokens when caller doesn't specify.
const DEFAULT_MAX_TOKENS: u32 = 512;

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
pub async fn chat_completions_handler(
    State(state): State<SharedState>,
    Json(req): Json<ChatCompletionRequest>,
) -> Result<Json<ChatCompletionResponse>, GatewayError> {
    if req.messages.is_empty() {
        return Err(GatewayError::BadRequest("messages must be non-empty".into()));
    }
    if req.stream {
        // SSE streaming lands in a follow-up WP-03.2 commit.
        return Err(GatewayError::BadRequest(
            "stream=true not yet supported (WP-03.2 follow-up)".into(),
        ));
    }

    // Resolve model name via ModelRegistry.
    let model_hash = state
        .queries
        .resolve_model_name(&req.model)
        .await
        .map_err(|_| GatewayError::UnknownModel(req.model.clone()))?;

    // List providers; pick best.
    let providers = state
        .queries
        .list_providers(model_hash)
        .await
        .map_err(|e| GatewayError::ChainUnavailable(e.to_string()))?;
    let provider = select_provider(&providers).ok_or(GatewayError::NoProviders)?;

    // Build provider request — concatenate messages into a flat
    // prompt for v1 (provider-side templating is a future
    // enhancement coordinated via the Provider Protocol ADR).
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

    // Dispatch.
    let provider_resp =
        dispatch_to_provider(&state.http, provider, &provider_req, PROVIDER_TIMEOUT).await?;

    // Translate to OpenAI shape.
    let prompt_tokens = provider_resp
        .input_tokens
        .unwrap_or_else(|| prompt.split_whitespace().count() as u32);
    let completion_tokens = provider_resp
        .output_tokens
        .unwrap_or_else(|| provider_resp.output.split_whitespace().count() as u32);

    Ok(Json(ChatCompletionResponse {
        id: format!("chatcmpl-{}", Uuid::new_v4()),
        object: "chat.completion",
        created: now_unix_secs(),
        model: req.model,
        choices: vec![Choice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: provider_resp.output,
            },
            finish_reason: "stop",
        }],
        usage: Usage::new(prompt_tokens, completion_tokens),
    }))
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
