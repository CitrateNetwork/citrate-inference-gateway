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

    // RM-B1 / WP-D2.4 (audit F-2): recharge against the caller's
    // actual `max_tokens` request. The X402Layer priced this request
    // at the gateway's *assumed* default (512 output tokens). A
    // caller can request up to u32::MAX max_tokens for the same
    // amount. Pre-fix this was a free out-of-policy capacity grant.
    // Post-fix we recompute the real cost from req.max_tokens and
    // reject with 402 if the signed amount falls short.
    //
    // RM-I-3 / WP-I2.1 (re-audit Stream 3 finding F-2 partial): the
    // input-token side was still pinned to ASSUMED_INPUT_TOKENS=256
    // even when the actual prompt was orders of magnitude larger. A
    // caller could ship a 32 KiB prompt + max_tokens=512 and still be
    // priced as if the input were 256 tokens. Post-fix we estimate
    // the real input token count from the request messages and use
    // it (capped at the maximum the model can accept) in the
    // recharge calculation. The estimate is conservative — see
    // `estimate_input_tokens` — so the gate is at least as strict as
    // the truth.
    if let Some(Extension(pay)) = &paid {
        let requested_tokens = req.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS);
        let real_input_tokens = estimate_input_tokens(&req.messages);
        let model_hash = state
            .queries
            .resolve_model_name(&req.model)
            .await
            .map_err(|_| GatewayError::UnknownModel(req.model.clone()))?;
        let actual_cost = state
            .queries
            .estimate_cost(
                model_hash,
                real_input_tokens,
                requested_tokens,
                crate::pricing::DEFAULT_VERIFICATION_TIER,
            )
            .await
            .map_err(|e| GatewayError::PricingUnavailable(e.to_string()))?;

        if pay.amount_wei < actual_cost {
            return Err(GatewayError::Underfunded {
                paid_wei: pay.amount_wei.to_string(),
                required_wei: actual_cost.to_string(),
                max_tokens: requested_tokens,
            });
        }
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

/// RM-I-3 / WP-I2.1 (audit F-2 input pricing closure):
/// Conservative input-token estimator over a list of chat messages.
///
/// Tokenisation is model-specific (BPE for GPT, SentencePiece for
/// Llama, etc.) and the precise count is only available after the
/// provider runs the request. For pricing-gate purposes we want a
/// *conservative upper bound* — overestimating costs the user a
/// touch more wei but never lets a caller under-pay; under-
/// estimating opens a free-capacity grant.
///
/// The standard heuristic (used by OpenAI tokenizers in their
/// guidance) is ~4 bytes per token for English text. We use 3
/// bytes/token as the floor (more aggressive = larger token count
/// = higher charge), plus a fixed 4-token overhead per message for
/// the role + separator wrappers ChatML and similar formats add.
/// Saturates at u32::MAX so a 4 GiB prompt still produces a finite
/// price (though the dispatch path will reject it long before).
pub(crate) fn estimate_input_tokens(messages: &[crate::openai::ChatMessage]) -> u32 {
    /// Bytes per token (conservative — over-estimates the count).
    const BYTES_PER_TOKEN: u64 = 3;
    /// Per-message role + separator overhead.
    const PER_MESSAGE_OVERHEAD: u64 = 4;

    let mut total: u64 = 0;
    for m in messages {
        // role + content are both attacker-controlled; both count.
        let body_bytes = (m.role.len() as u64) + (m.content.len() as u64);
        let body_tokens = (body_bytes + BYTES_PER_TOKEN - 1) / BYTES_PER_TOKEN; // ceil_div
        total = total
            .saturating_add(body_tokens)
            .saturating_add(PER_MESSAGE_OVERHEAD);
    }
    // Floor at the prior-track ASSUMED constant so an empty-message
    // edge case still charges something (defence-in-depth; the
    // empty-messages branch above is the load-bearing reject).
    let floor = crate::pricing::ASSUMED_INPUT_TOKENS as u64;
    let estimate = total.max(floor);
    if estimate > u32::MAX as u64 {
        u32::MAX
    } else {
        estimate as u32
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

    // List both individual providers and pools, then let the
    // selection layer (CM-05 WP-05.4) score them on a comparable
    // axis. Pool wins when its min_member_reputation × stake
    // exceeds any individual's reputation × capacity.
    let mut providers = state
        .queries
        .list_providers(model_hash)
        .await
        .map_err(|e| GatewayError::ChainUnavailable(e.to_string()))?;
    let pools = state
        .queries
        .list_pools(model_hash)
        .await
        .unwrap_or_else(|_| Vec::new());

    if providers.is_empty() && pools.is_empty() {
        return Err(GatewayError::NoProviders);
    }

    // Cross-class dispatch decision. If a pool wins, slice 1
    // returns 503 with the slice-2 marker so callers don't have a
    // dangling success path. Slice 2 will route through the
    // gateway wallet via `requestPoolCompute` + `JobCompleted` poll.
    if let Some(crate::selection::DispatchTarget::Pool(pl)) =
        crate::selection::select_dispatch_target(&providers, &pools)
    {
        return Err(GatewayError::PoolDispatchUnimplemented(pl.name));
    }

    // Selection picked an individual provider OR there were no
    // pools at all. Fall through to the existing failover loop
    // below using the providers list. (Note: we don't NARROW the
    // list to just the winning provider; the failover loop will
    // re-pick from the full set on each attempt, which preserves
    // the existing behaviour.)
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

#[cfg(test)]
mod input_token_estimation_tests {
    use super::*;
    use crate::openai::ChatMessage;

    fn msg(role: &str, content: &str) -> ChatMessage {
        ChatMessage {
            role: role.into(),
            content: content.into(),
        }
    }

    /// RM-I-3 / WP-I2.1: empty messages list saturates to the
    /// `ASSUMED_INPUT_TOKENS` floor (defence-in-depth — the empty-
    /// messages reject in the handler is the load-bearing gate).
    #[test]
    fn test_f_2_empty_messages_uses_assumed_floor() {
        let count = estimate_input_tokens(&[]);
        assert_eq!(
            count,
            crate::pricing::ASSUMED_INPUT_TOKENS,
            "F-2: empty messages must price at ASSUMED_INPUT_TOKENS floor"
        );
    }

    /// A short message produces a count above the per-message
    /// overhead (4 tokens) and below the floor (which dominates here).
    #[test]
    fn test_f_2_short_message_uses_floor() {
        let count = estimate_input_tokens(&[msg("user", "hi")]);
        assert_eq!(
            count,
            crate::pricing::ASSUMED_INPUT_TOKENS,
            "F-2: a 2-byte message + role overhead is below the floor; floor wins"
        );
    }

    /// A LONG message bypasses the floor and produces a real estimate.
    /// 32 KiB body / 3 bytes-per-token ≈ 10923 tokens — well above the
    /// 256 floor that the pre-fix code pinned.
    #[test]
    fn test_f_2_long_message_returns_real_estimate() {
        let payload: String = "A".repeat(32 * 1024);
        let count = estimate_input_tokens(&[msg("user", &payload)]);
        // Should be roughly (32768 + 4 [role len]) / 3 + 4 [overhead] ≈ 10928
        // Allow a wide tolerance — the assertion is "much more than 256".
        assert!(
            count >= 10_000,
            "F-2: 32 KiB message must price at least 10K tokens, got {}",
            count
        );
        assert!(
            count > crate::pricing::ASSUMED_INPUT_TOKENS,
            "F-2: 32 KiB message must exceed the assumed floor"
        );
    }

    /// Many short messages summed — guards against per-message overhead
    /// being skipped in the loop.
    #[test]
    fn test_f_2_many_messages_summed() {
        // 1000 messages of role "user" and content "hi"
        let messages: Vec<ChatMessage> = (0..1000).map(|_| msg("user", "hi")).collect();
        let count = estimate_input_tokens(&messages);
        // (4 + 2) bytes / 3 = 2 body tokens + 4 overhead = 6 tokens per
        // message * 1000 = 6000 total. Well above the 256 floor.
        assert!(
            count >= 5_000,
            "F-2: 1000 short messages must price at least 5K tokens, got {}",
            count
        );
    }

    /// Saturation at u32::MAX guards against a 4-GiB-prompt attack
    /// causing arithmetic overflow.
    #[test]
    fn test_f_2_huge_estimate_saturates_at_u32_max() {
        // Construct messages totalling ~16 GiB nominal — would overflow
        // u32 if we summed naively. We use 1 KiB content and pretend
        // we have many such messages.
        let msgs: Vec<ChatMessage> = (0..(1u32 << 24))
            .map(|_| msg("u", &"x".repeat(1024)))
            .collect();
        let count = estimate_input_tokens(&msgs);
        // ((1024 + 1) / 3 + 4) * (1 << 24) ≈ 6.6e9 > u32::MAX (~4.3e9).
        assert_eq!(
            count,
            u32::MAX,
            "F-2: extremely large prompts must saturate at u32::MAX, not overflow"
        );
    }
}
