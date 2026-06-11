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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// 2026-05-31 audit -004 (SECREM-02 6.4a): SHA-256 (hex) of the
    /// submit-time read token issued to payers with no API key (x402 /
    /// open-chat). Reads must present the matching token; only the hash
    /// is kept at rest. `None` when an API key owns the batch (reads
    /// then require that key's bearer).
    read_token_hash: Option<String>,
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

// ── Durable form (WP-F slice F2) ────────────────────────────────

/// Slim, serializable projection of a batch for durable persistence. Omits the
/// response bodies (`ChatCompletionResponse` is `Serialize`-only — `&'static
/// str` fields can't deserialize), keeping exactly what's needed to settle
/// escrow and reconcile on recovery: per-slot state + quote + the request. U256
/// amounts are decimal strings (lossless, no serde-feature dependency).
#[derive(Debug, Serialize, Deserialize)]
struct PersistedSlot {
    state: RequestStatus,
    request: ChatCompletionRequest,
    quoted_cost_grains: String,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedBatch {
    id: String,
    status: BatchStatus,
    paid_escrow_grains: String,
    released_grains: String,
    refunded_grains: String,
    payer_api_key_id: Option<String>,
    /// Audit -004 — see [`BatchRecord::read_token_hash`]. `default` keeps
    /// pre-6.4a persisted batches decodable; they re-hydrate with `None`
    /// (and no API-key owner), so their reads FAIL CLOSED.
    #[serde(default)]
    read_token_hash: Option<String>,
    slots: Vec<PersistedSlot>,
    created_at: u64,
    refund_settled: bool,
}

impl PersistedBatch {
    fn from_record(r: &BatchRecord, refund_settled: bool) -> Self {
        Self {
            id: r.id.clone(),
            status: r.status,
            paid_escrow_grains: r.paid_escrow_grains.to_string(),
            released_grains: r.released_grains.to_string(),
            refunded_grains: r.refunded_grains.to_string(),
            payer_api_key_id: r.payer_api_key_id.clone(),
            read_token_hash: r.read_token_hash.clone(),
            slots: r
                .slots
                .iter()
                .map(|s| PersistedSlot {
                    state: s.state,
                    request: s.request.clone(),
                    quoted_cost_grains: s.quoted_cost_grains.to_string(),
                    error: s.error.clone(),
                })
                .collect(),
            created_at: r.created_at,
            refund_settled,
        }
    }

    fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Reconstruct a live `BatchRecord` (response bodies are not restored —
    /// recovered Done slots keep `response: None`; their output body is the
    /// documented limitation, the slot is not re-run).
    fn into_record(self) -> BatchRecord {
        let parse = |s: &str| U256::from_dec_str(s).unwrap_or_else(|_| U256::zero());
        BatchRecord {
            id: self.id,
            status: self.status,
            paid_escrow_grains: parse(&self.paid_escrow_grains),
            released_grains: parse(&self.released_grains),
            refunded_grains: parse(&self.refunded_grains),
            payer_api_key_id: self.payer_api_key_id,
            read_token_hash: self.read_token_hash,
            slots: self
                .slots
                .into_iter()
                .map(|s| RequestSlot {
                    state: s.state,
                    quoted_cost_grains: parse(&s.quoted_cost_grains),
                    request: s.request,
                    response: None,
                    error: s.error,
                })
                .collect(),
            created_at: self.created_at,
        }
    }
}

// ── Store ───────────────────────────────────────────────────────

/// Batch store. The live working set is always the in-memory map (the
/// processor mutates it while polls read it); when a durable `persist` handle
/// is present (production, WP-F), every transition is write-through to RocksDB
/// and the terminal refund settles **atomically + exactly-once**, so a crash
/// mid-batch never strands the buyer's escrow.
#[derive(Default)]
pub struct BatchStore {
    batches: RwLock<HashMap<String, Arc<RwLock<BatchRecord>>>>,
    persist: Option<Arc<crate::keystore::PersistentKeyStore>>,
}

impl std::fmt::Debug for BatchStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchStore")
            .field("durable", &self.persist.is_some())
            .finish()
    }
}

impl BatchStore {
    /// In-memory store (tests + the in-memory boot path).
    pub fn new() -> Self {
        Self::default()
    }

    /// Durable store sharing the one persistent key store (so batch settlement
    /// and the balance credit commit in a single atomic write).
    pub fn with_persistence(store: Arc<crate::keystore::PersistentKeyStore>) -> Self {
        Self {
            batches: RwLock::new(HashMap::new()),
            persist: Some(store),
        }
    }

    async fn insert(&self, record: BatchRecord) -> Arc<RwLock<BatchRecord>> {
        if let Some(p) = &self.persist {
            let _ = p.persist_batch(&record.id, &PersistedBatch::from_record(&record, false).to_json());
        }
        let id = record.id.clone();
        let arc = Arc::new(RwLock::new(record));
        self.batches.write().await.insert(id, arc.clone());
        arc
    }

    async fn get(&self, id: &str) -> Option<Arc<RwLock<BatchRecord>>> {
        self.batches.read().await.get(id).cloned()
    }

    /// Write-through the current batch state (best-effort progress durability).
    async fn checkpoint(&self, record: &BatchRecord) {
        if let Some(p) = &self.persist {
            let settled = p.batch_was_settled(&record.id).unwrap_or(false);
            let _ = p.persist_batch(&record.id, &PersistedBatch::from_record(record, settled).to_json());
        }
    }

    /// Boot recovery (WP-F): re-hydrate persisted batches into the live map and
    /// settle any a crash left unsettled. We do **not** re-run inference on
    /// recovery — every not-`Done` slot is **refunded** to the buyer (money-safe
    /// refund-on-recovery), and the credit + settled-marker commit atomically
    /// and exactly-once. A previously-settled batch is just re-hydrated for
    /// polls. Returns `(rehydrated, settled)`. (Resuming interrupted *inference*
    /// — re-dispatching Pending/Dispatched slots — is a documented follow-on;
    /// the resume-safe slot-skip in `process_batch` already supports it.)
    pub async fn recover(&self) -> (usize, usize) {
        let Some(store) = &self.persist else {
            return (0, 0);
        };
        let persisted = match store.load_batches() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = ?e, "batch recovery: load_batches failed");
                return (0, 0);
            }
        };

        let mut rehydrated = 0usize;
        let mut settled = 0usize;
        for (id, bytes) in persisted {
            let pb: PersistedBatch = match serde_json::from_slice(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(batch_id = %id, error = ?e, "batch recovery: skip undecodable record");
                    continue;
                }
            };
            let mut record = pb.into_record();

            if !store.batch_was_settled(&id).unwrap_or(false) {
                // Reconcile: Done slots release; everything else refunds.
                let total = record.request_count();
                let dones = record.completed_count();
                let mut released = U256::zero();
                let mut refunded = U256::zero();
                for slot in record.slots.iter_mut() {
                    if slot.state == RequestStatus::Done {
                        released = released.saturating_add(slot.quoted_cost_grains);
                    } else {
                        refunded = refunded.saturating_add(slot.quoted_cost_grains);
                        slot.state = RequestStatus::Errored;
                        if slot.error.is_none() {
                            slot.error = Some("interrupted by gateway restart".to_string());
                        }
                    }
                }
                record.released_grains = released;
                record.refunded_grains = refunded;
                record.status = if dones == total {
                    BatchStatus::Completed
                } else if dones == 0 {
                    BatchStatus::Failed
                } else {
                    BatchStatus::PartialFailure
                };

                let terminal_bytes = PersistedBatch::from_record(&record, true).to_json();
                match (record.payer_api_key_id.clone(), refunded > U256::zero()) {
                    (Some(key_id), true) => {
                        if let Err(e) = store.settle_batch_refund(&key_id, refunded, &id, &terminal_bytes) {
                            tracing::warn!(batch_id = %id, error = ?e, "batch recovery: settle failed");
                        }
                    }
                    _ => {
                        let _ = store.mark_batch_settled(&id, &terminal_bytes);
                    }
                }
                settled += 1;
                tracing::info!(batch_id = %id, refunded = %refunded, "batch recovery: reconciled + refunded on restart");
            }

            self.batches.write().await.insert(id, Arc::new(RwLock::new(record)));
            rehydrated += 1;
        }
        (rehydrated, settled)
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
    /// 2026-05-31 audit -004: one-time read credential, present ONLY in
    /// the initial submit response of a batch with no API-key owner
    /// (x402 / open-chat submits). The caller must present it as a
    /// Bearer token (or `x-batch-read-token` header) on `GET
    /// /v1/batch/{id}` and `/output`. Never echoed on polls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_token: Option<String>,
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
    // 2026-05-31 audit -004: bind reads to the submitter. API-key
    // submits are owned by that key (reads require the same bearer).
    // Key-less submits (x402-settled, and the open-chat dev profile —
    // where this token is the ONLY thing standing between a guessed
    // batch id and another tenant's prompts) get a one-time read token,
    // returned exactly once in the submit response; only its SHA-256
    // is stored.
    let (read_token, read_token_hash) = if payer_api_key_id.is_none() {
        let token = format!("brt_{}", Uuid::new_v4());
        let hash = crate::auth::hash_key_id(&token);
        (Some(token), Some(hash))
    } else {
        (None, None)
    };
    let record = BatchRecord {
        id: id.clone(),
        status: BatchStatus::Submitted,
        paid_escrow_grains: total_required,
        released_grains: U256::zero(),
        refunded_grains: U256::zero(),
        payer_api_key_id,
        read_token_hash,
        slots,
        created_at: now_unix_secs(),
    };

    let arc = state.batches.insert(record).await;
    metrics::counter!("gateway_batch_submissions_total", 1);
    let mut initial = build_status(&*arc.read().await);
    initial.read_token = read_token;

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

/// 404 body shared by "unknown id" and "not authorized" so a probing
/// caller cannot distinguish existing batches from non-existent ones
/// (audit -004: no existence oracle).
fn batch_not_found(id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": { "message": format!("unknown batch_id: {}", id) }
        })),
    )
        .into_response()
}

/// 2026-05-31 audit -004 (SECREM-02 6.4a): batch reads are bound to the
/// submitter. Pre-fix both read handlers took only `Path(id)` — any
/// caller who learned a batch id could read another tenant's prompts and
/// outputs. Authorization:
///
/// - API-key-owned batch → the caller must present the owning key as a
///   Bearer token (compared by SHA-256, never raw).
/// - Key-less batch (x402 / open-chat dev profile) → the caller must
///   present the submit-time `read_token` (Bearer or
///   `x-batch-read-token` header). Only the token's SHA-256 is at rest.
/// - Neither credential on the record (pre-6.4a persisted batches
///   re-hydrated after an upgrade) → fail closed.
fn batch_read_authorized(record: &BatchRecord, headers: &axum::http::HeaderMap) -> bool {
    let presented = crate::auth::extract_bearer(headers).or_else(|| {
        headers
            .get("x-batch-read-token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    });
    let Some(presented) = presented else {
        return false;
    };
    if let Some(owner_key) = &record.payer_api_key_id {
        // Hash both sides — avoids a variable-time compare on the raw
        // bearer secret and never materializes it beyond this scope.
        crate::auth::hash_key_id(&presented) == crate::auth::hash_key_id(owner_key)
    } else if let Some(token_hash) = &record.read_token_hash {
        &crate::auth::hash_key_id(&presented) == token_hash
    } else {
        false
    }
}

/// `GET /v1/batch/{id}` — poll batch status. Requires the submitter's
/// credential (audit -004; see [`batch_read_authorized`]).
pub async fn get_batch_handler(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    match state.batches.get(&id).await {
        Some(arc) => {
            let record = arc.read().await;
            if !batch_read_authorized(&record, &headers) {
                metrics::counter!("gateway_batch_read_denied_total", 1);
                return batch_not_found(&id);
            }
            let body = build_status(&record);
            (StatusCode::OK, Json(body)).into_response()
        }
        None => batch_not_found(&id),
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
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(arc) = state.batches.get(&id).await else {
        return batch_not_found(&id);
    };

    let record = arc.read().await;
    // Audit -004: outputs (prompts + completions) are the most
    // sensitive read — same submitter binding as the status poll.
    if !batch_read_authorized(&record, &headers) {
        metrics::counter!("gateway_batch_read_denied_total", 1);
        return batch_not_found(&id);
    }
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
        // Resume-safe: a slot already Done/Errored (e.g. recovered from a
        // persisted snapshot) is never re-run.
        let already_terminal = {
            let record = arc.read().await;
            matches!(
                record.slots[i].state,
                RequestStatus::Done | RequestStatus::Errored
            )
        };
        if already_terminal {
            continue;
        }

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
        {
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
        // Checkpoint the money-relevant state (which slots completed). Best-
        // effort, non-synced — a hard crash may lose the last few Done writes,
        // in which case recovery refunds those slots to the BUYER's benefit
        // (never the buyer's loss). The exactly-once settlement is synced.
        state.batches.checkpoint(&*arc.read().await).await;
    }

    // Compute terminal state + escrow split.
    let (batch_id, payer, refund_owed, terminal_bytes) = {
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
        // invariants from GatewayBatchLifecycle.tla.
        debug_assert_eq!(
            record.released_grains + record.refunded_grains,
            record.paid_escrow_grains,
            "TerminalBatchEscrowSettled violated: paid={} released={} refunded={}",
            record.paid_escrow_grains,
            record.released_grains,
            record.refunded_grains
        );

        let terminal_bytes = PersistedBatch::from_record(&record, true).to_json();
        (
            record.id.clone(),
            record.payer_api_key_id.clone(),
            record.refunded_grains,
            terminal_bytes,
        )
    };

    settle_batch(&state, &batch_id, payer, refund_owed, &terminal_bytes).await;
}

/// Final, crash-safe escrow settlement for a terminal batch.
///
/// Durable path: the buyer's refund credit + the "settled" marker + the
/// terminal snapshot commit in **one atomic synced write** (exactly-once even
/// if the process dies mid-settle — recovery replays it as a no-op). In-memory
/// path (tests): refund the in-memory key store.
async fn settle_batch(
    state: &SharedState,
    batch_id: &str,
    payer: Option<String>,
    refund: U256,
    terminal_bytes: &[u8],
) {
    match &state.batches.persist {
        Some(store) => match (payer, refund > U256::zero()) {
            (Some(key_id), true) => {
                if let Err(err) = store.settle_batch_refund(&key_id, refund, batch_id, terminal_bytes) {
                    tracing::warn!(batch_refund = %refund, key_id = %key_id, error = ?err, "batch api key refund failed");
                } else {
                    metrics::counter!("gateway_batch_refunds_total", 1, "payer" => "api_key");
                }
            }
            _ => {
                // No api-key refund owed — persist terminal + mark settled so
                // recovery skips this batch.
                let _ = store.mark_batch_settled(batch_id, terminal_bytes);
            }
        },
        None => {
            if refund > U256::zero() {
                if let Some(key_id) = payer {
                    if let Err(err) = state.keys.refund(&key_id, refund).await {
                        tracing::warn!(batch_refund = %refund, key_id = %key_id, error = ?err, "batch api key refund failed");
                    } else {
                        metrics::counter!("gateway_batch_refunds_total", 1, "payer" => "api_key");
                    }
                }
            }
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
        // Only the submit handler ever sets this (audit -004); polls
        // never re-issue the read credential.
        read_token: None,
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
