//! `/v1/batch` — async batch inference endpoint (WP-03.3).
//!
//! Slice 1 scope:
//!   - In-memory store (RocksDB persistence is slice 2).
//!   - Inline `{requests: [...]}` body (≤ MAX_BATCH_SIZE).
//!   - One x402 settlement covers the whole batch (the batch route
//!     sits behind the same `X402Layer` as `/v1/chat/completions`).
//!   - On-chain `postJob` per request is slice 3 — for now the
//!     dispatcher fans requests out directly to providers, same as
//!     the sync chat path.
//!
//! State machine mirrors `GatewayBatchLifecycle.tla`:
//!
//! ```text
//!   batch:   Submitted → Running → {Completed | PartialFailure | Failed}
//!   request: Pending   → Dispatched → {Done | Errored}
//! ```
//!
//! Invariants the runtime enforces:
//!   - `EscrowBalances`: paid_escrow ≥ released + refunded
//!   - `TerminalBatchEscrowSettled`: when terminal, paid = released + refunded
//!   - `TerminalImpliesAllRequestsTerminal`
//!
//! Specs: `.agentile/formal/specs/compute/GatewayBatchLifecycle.tla`,
//! `citrate_v0.01.1/specs/gherkin/gateway_batch.feature`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ethereum_types::U256;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use x402_axum::X402Paid;

use crate::auth::ApiKeyCharge;
use crate::chat::{json_response, quote_chat_request_cost, run_dispatch, DEFAULT_MAX_TOKENS};
use crate::error::GatewayError;
use crate::openai::{ChatCompletionRequest, ChatCompletionResponse};
use crate::usage::ApiKeyContext;
use crate::SharedState;

/// Max requests per batch. Mirrors WP-03.3 spec.
pub const MAX_BATCH_SIZE: usize = 1000;

// ── State machine types ─────────────────────────────────────────

/// Per-batch lifecycle state. Mirrors `BatchStates` in the TLA+ spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// Just created; processor task hasn't picked it up yet.
    Submitted,
    /// At least one request has been dispatched; not yet terminal.
    Running,
    /// All requests Done.
    Completed,
    /// Mix of Done and Errored.
    PartialFailure,
    /// All requests Errored.
    Failed,
}

impl BatchStatus {
    /// True once the batch is in a final state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::PartialFailure | Self::Failed)
    }
}

/// Per-request state inside a batch. Mirrors `RequestStates`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    /// Not yet picked up by the processor.
    Pending,
    /// In flight to a provider.
    Dispatched,
    /// Provider returned a successful response.
    Done,
    /// Provider failed (after failover); request is errored.
    Errored,
}

/// One request slot inside a batch.
#[derive(Debug)]
struct RequestSlot {
    state: RequestStatus,
    request: ChatCompletionRequest,
    quoted_cost_grains: U256,
    response: Option<ChatCompletionResponse>,
    error: Option<String>,
}

/// Internal batch record. Lives behind `Arc<RwLock<...>>` so the
/// processor task can mutate it while polls read it.
#[derive(Debug)]
struct BatchRecord {
    id: String,
    status: BatchStatus,
    paid_escrow_grains: U256,
    released_grains: U256,
    refunded_grains: U256,
    payer_api_key_id: Option<String>,
    slots: Vec<RequestSlot>,
    created_at: u64,
}

impl BatchRecord {
    fn request_count(&self) -> usize {
        self.slots.len()
    }
    fn completed_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == RequestStatus::Done)
            .count()
    }
    fn errored_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state == RequestStatus::Errored)
            .count()
    }
    fn all_terminal(&self) -> bool {
        self.slots
            .iter()
            .all(|s| matches!(s.state, RequestStatus::Done | RequestStatus::Errored))
    }
}

// ── Store ───────────────────────────────────────────────────────

/// In-memory batch store. Each batch is wrapped in its own `RwLock`
/// so the processor task can hold a write lock without blocking
/// status polls on other batches.
#[derive(Default, Debug)]
pub struct BatchStore {
    batches: RwLock<HashMap<String, Arc<RwLock<BatchRecord>>>>,
}

impl BatchStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    async fn insert(&self, record: BatchRecord) -> Arc<RwLock<BatchRecord>> {
        let id = record.id.clone();
        let arc = Arc::new(RwLock::new(record));
        self.batches.write().await.insert(id, arc.clone());
        arc
    }

    async fn get(&self, id: &str) -> Option<Arc<RwLock<BatchRecord>>> {
        self.batches.read().await.get(id).cloned()
    }
}

// ── Wire shapes ─────────────────────────────────────────────────

/// `POST /v1/batch` body. Inline form — file uploads come later.
#[derive(Debug, Deserialize)]
pub struct BatchSubmitRequest {
    /// Inline list of chat-completion requests.
    pub requests: Vec<ChatCompletionRequest>,
}

/// Status response shape — returned by both POST /v1/batch (initial)
/// and GET /v1/batch/{id} (poll).
#[derive(Debug, Serialize)]
pub struct BatchStatusResponse {
    /// Constant `"batch"` per OpenAI shape.
    pub object: &'static str,
    /// Server-issued batch id.
    pub batch_id: String,
    /// Current lifecycle status.
    pub status: BatchStatus,
    /// Total requests in the batch.
    pub request_count: usize,
    /// Requests that finished `Done`.
    pub completed_count: usize,
    /// Requests that finished `Errored`.
    pub errored_count: usize,
    /// Unix seconds when the batch was created.
    pub created_at: u64,
    /// Total exact quote accepted for this batch, in grains (wei).
    /// Stringified to keep U256 lossless across JSON.
    pub paid_escrow_grains: String,
    /// Amount released to providers, in grains. On terminal, exact
    /// per-slot released quotes plus `refunded_grains` sum to
    /// `paid_escrow_grains`.
    pub released_grains: String,
    /// Amount refunded to client (one share per errored request).
    pub refunded_grains: String,
}

// ── Handlers ────────────────────────────────────────────────────

/// `POST /v1/batch` — submit a new batch.
///
/// Runs after the X402Layer settles payment, so `X402Paid` is
/// guaranteed in extensions.
pub async fn submit_batch_handler(
    State(state): State<SharedState>,
    Extension(paid): Extension<X402Paid>,
    api_key: Option<Extension<ApiKeyContext>>,
    Json(req): Json<BatchSubmitRequest>,
) -> Result<Response, GatewayError> {
    if req.requests.is_empty() {
        return Err(GatewayError::BadRequest(
            "requests must be non-empty".into(),
        ));
    }
    if req.requests.len() > MAX_BATCH_SIZE {
        return Err(GatewayError::BadRequest(format!(
            "max {} requests per batch (got {})",
            MAX_BATCH_SIZE,
            req.requests.len()
        )));
    }
    for (i, r) in req.requests.iter().enumerate() {
        if r.messages.is_empty() {
            return Err(GatewayError::BadRequest(format!(
                "requests[{}].messages must be non-empty",
                i
            )));
        }
    }

    let mut total_required = U256::zero();
    let mut largest_requested_tokens = DEFAULT_MAX_TOKENS;
    let mut slots = Vec::with_capacity(req.requests.len());
    for request in req.requests {
        let (quoted_cost_grains, requested_tokens) =
            quote_chat_request_cost(&state, &request).await?;
        let (next_total, overflow) = total_required.overflowing_add(quoted_cost_grains);
        if overflow {
            return Err(GatewayError::PricingUnavailable(
                "batch quote overflow".to_string(),
            ));
        }
        total_required = next_total;
        largest_requested_tokens = largest_requested_tokens.max(requested_tokens);
        slots.push(RequestSlot {
            state: RequestStatus::Pending,
            request,
            quoted_cost_grains,
            response: None,
            error: None,
        });
    }

    if paid.amount_wei < total_required {
        return Err(GatewayError::Underfunded {
            paid_wei: paid.amount_wei.to_string(),
            required_wei: total_required.to_string(),
            max_tokens: largest_requested_tokens,
        });
    }

    let id = format!("batch_{}", Uuid::new_v4());
    let payer_api_key_id = api_key.as_ref().map(|Extension(ctx)| ctx.key_id.clone());
    let record = BatchRecord {
        id: id.clone(),
        status: BatchStatus::Submitted,
        paid_escrow_grains: total_required,
        released_grains: U256::zero(),
        refunded_grains: U256::zero(),
        payer_api_key_id,
        slots,
        created_at: now_unix_secs(),
    };

    let arc = state.batches.insert(record).await;
    metrics::counter!("gateway_batch_submissions_total", 1);
    let initial = build_status(&*arc.read().await);

    // Spawn the processor task. It runs detached; status polls read
    // through the same Arc<RwLock<BatchRecord>>.
    let state_for_task = state.clone();
    let arc_for_task = arc.clone();
    tokio::spawn(async move {
        process_batch(state_for_task, arc_for_task).await;
    });

    let mut response = (StatusCode::OK, Json(initial)).into_response();
    if api_key.is_some() {
        response.extensions_mut().insert(ApiKeyCharge {
            amount_grains: total_required,
        });
    }
    Ok(response)
}

/// `GET /v1/batch/{id}` — poll batch status.
pub async fn get_batch_handler(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Response {
    match state.batches.get(&id).await {
        Some(arc) => {
            let body = build_status(&*arc.read().await);
            (StatusCode::OK, Json(body)).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": { "message": format!("unknown batch_id: {}", id) }
            })),
        )
            .into_response(),
    }
}

/// `GET /v1/batch/{id}/output` — JSONL of per-request outcomes.
///
/// Slice 1: returns whatever rows currently exist (terminal slots
/// fully populated; non-terminal ones still emit a row with their
/// current `status`). Once terminal, this is the authoritative
/// output stream consumers iterate.
pub async fn get_batch_output_handler(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Response {
    let Some(arc) = state.batches.get(&id).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": { "message": format!("unknown batch_id: {}", id) }
            })),
        )
            .into_response();
    };

    let record = arc.read().await;
    let mut body = String::with_capacity(256 * record.slots.len());
    for (i, slot) in record.slots.iter().enumerate() {
        let line = match slot.state {
            RequestStatus::Done => serde_json::json!({
                "request_index": i,
                "status": "completed",
                "response": slot.response,
            }),
            RequestStatus::Errored => serde_json::json!({
                "request_index": i,
                "status": "errored",
                "error": slot.error.clone().unwrap_or_default(),
            }),
            RequestStatus::Pending => serde_json::json!({
                "request_index": i,
                "status": "pending",
            }),
            RequestStatus::Dispatched => serde_json::json!({
                "request_index": i,
                "status": "dispatched",
            }),
        };
        body.push_str(&line.to_string());
        body.push('\n');
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        body,
    )
        .into_response()
}

// ── Processor ───────────────────────────────────────────────────

/// Background task: walks the batch through Submitted → Running →
/// terminal. Dispatches requests sequentially in slice 1 (parallel
/// dispatch is slice 2 — sequential keeps the escrow accounting
/// trivially correct without per-slot locks).
async fn process_batch(state: SharedState, arc: Arc<RwLock<BatchRecord>>) {
    {
        let mut record = arc.write().await;
        record.status = BatchStatus::Running;
    }

    let count = arc.read().await.slots.len();
    for i in 0..count {
        // Mark Dispatched.
        {
            let mut record = arc.write().await;
            record.slots[i].state = RequestStatus::Dispatched;
        }

        // Snapshot the request body so we don't hold the lock across
        // the await.
        let req_snapshot: ChatCompletionRequest = {
            let record = arc.read().await;
            ChatCompletionRequest {
                model: record.slots[i].request.model.clone(),
                messages: record.slots[i].request.messages.clone(),
                max_tokens: record.slots[i].request.max_tokens,
                stream: false,
            }
        };

        let result = run_dispatch(&state, &req_snapshot).await;

        // Record outcome + bump escrow.
        let mut record = arc.write().await;
        match result {
            Ok(outcome) => {
                let resp = json_response(req_snapshot, outcome);
                record.slots[i].state = RequestStatus::Done;
                record.slots[i].response = Some(resp);
            }
            Err(e) => {
                tracing::warn!(
                    batch_id = %record.id,
                    request_index = i,
                    error = %e,
                    "batch request errored"
                );
                record.slots[i].state = RequestStatus::Errored;
                record.slots[i].error = Some(e.to_string());
            }
        }
    }

    // Compute terminal state + escrow split.
    let mut record = arc.write().await;
    let total = record.request_count();
    let dones = record.completed_count();
    let errs = record.errored_count();
    debug_assert!(record.all_terminal(), "all slots must be terminal here");

    let (released, refunded) = split_quoted_escrow(&record.slots);
    record.released_grains = released;
    record.refunded_grains = refunded;
    record.status = if dones == total {
        BatchStatus::Completed
    } else if errs == total {
        BatchStatus::Failed
    } else {
        BatchStatus::PartialFailure
    };

    // Sanity check the EscrowBalances + TerminalBatchEscrowSettled
    // invariants from GatewayBatchLifecycle.tla. A violation here
    // indicates a code bug, not bad input — but we surface it loudly
    // so it shows in tests rather than silent misaccounting.
    debug_assert_eq!(
        record.released_grains + record.refunded_grains,
        record.paid_escrow_grains,
        "TerminalBatchEscrowSettled violated: paid={} released={} refunded={}",
        record.paid_escrow_grains,
        record.released_grains,
        record.refunded_grains
    );
    let api_refund = record
        .payer_api_key_id
        .clone()
        .map(|key_id| (key_id, record.refunded_grains))
        .filter(|(_, refund)| *refund > U256::zero());
    drop(record);

    if let Some((key_id, refund)) = api_refund {
        if let Err(err) = state.keys.refund(&key_id, refund).await {
            tracing::warn!(
                batch_refund = %refund,
                key_id = %key_id,
                error = ?err,
                "batch api key refund failed"
            );
        } else {
            metrics::counter!("gateway_batch_refunds_total", 1, "payer" => "api_key");
        }
    }
}

/// Split the quoted escrow into (released_to_providers, refunded).
///
/// Each successful request releases its exact quote. Each errored request
/// refunds its exact quote. That avoids the prior proportional split, which
/// lost per-request pricing information once mixed-cost batches were allowed.
fn split_quoted_escrow(slots: &[RequestSlot]) -> (U256, U256) {
    let mut released = U256::zero();
    let mut refunded = U256::zero();
    for slot in slots {
        match slot.state {
            RequestStatus::Done => {
                released = released.saturating_add(slot.quoted_cost_grains);
            }
            RequestStatus::Errored => {
                refunded = refunded.saturating_add(slot.quoted_cost_grains);
            }
            RequestStatus::Pending | RequestStatus::Dispatched => {}
        }
    }
    (released, refunded)
}

fn build_status(record: &BatchRecord) -> BatchStatusResponse {
    BatchStatusResponse {
        object: "batch",
        batch_id: record.id.clone(),
        status: record.status,
        request_count: record.request_count(),
        completed_count: record.completed_count(),
        errored_count: record.errored_count(),
        created_at: record.created_at,
        paid_escrow_grains: record.paid_escrow_grains.to_string(),
        released_grains: record.released_grains.to_string(),
        refunded_grains: record.refunded_grains.to_string(),
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(state: RequestStatus, quoted_cost_grains: u64) -> RequestSlot {
        RequestSlot {
            state,
            request: ChatCompletionRequest {
                model: "m".to_string(),
                messages: Vec::new(),
                max_tokens: None,
                stream: false,
            },
            quoted_cost_grains: U256::from(quoted_cost_grains),
            response: None,
            error: None,
        }
    }

    #[test]
    fn split_all_done_releases_all_quotes() {
        let slots = vec![
            slot(RequestStatus::Done, 10),
            slot(RequestStatus::Done, 20),
            slot(RequestStatus::Done, 70),
        ];
        let (rel, ref_) = split_quoted_escrow(&slots);
        assert_eq!(rel, U256::from(100u64));
        assert_eq!(ref_, U256::zero());
    }

    #[test]
    fn split_all_errored_refunds_all_quotes() {
        let slots = vec![
            slot(RequestStatus::Errored, 10),
            slot(RequestStatus::Errored, 20),
            slot(RequestStatus::Errored, 70),
        ];
        let (rel, ref_) = split_quoted_escrow(&slots);
        assert_eq!(rel, U256::zero());
        assert_eq!(ref_, U256::from(100u64));
    }

    #[test]
    fn split_partial_uses_exact_slot_quotes() {
        let slots = vec![
            slot(RequestStatus::Done, 10),
            slot(RequestStatus::Errored, 30),
            slot(RequestStatus::Done, 60),
        ];
        let (rel, ref_) = split_quoted_escrow(&slots);
        assert_eq!(rel + ref_, U256::from(100u64));
        assert_eq!(ref_, U256::from(30u64));
        assert_eq!(rel, U256::from(70u64));
    }

    #[test]
    fn batch_status_terminal() {
        assert!(BatchStatus::Completed.is_terminal());
        assert!(BatchStatus::PartialFailure.is_terminal());
        assert!(BatchStatus::Failed.is_terminal());
        assert!(!BatchStatus::Submitted.is_terminal());
        assert!(!BatchStatus::Running.is_terminal());
    }
}
