//! API key auth (WP-03.4).
//!
//! Repeat buyers with predictable spend prefer a classic
//! `Authorization: Bearer <key>` header over managing wSALT for
//! every request. This module provides:
//!
//! - [`ApiKeyStore`] — in-memory (slice 1) key→balance record store
//! - [`ApiKeyLayer`] — tower middleware that sits in front of
//!   `X402Layer`:
//!     * No `Authorization` header → pass through untouched
//!     * Unknown / revoked key → 401
//!     * Valid + funded → price via the same pricing strategy, deduct
//!       from balance, attach synthetic `X402Paid` to the request
//!       extensions so `X402Layer` bypasses its challenge flow
//!     * Exhausted → pass through to `X402Layer`; when it returns
//!       402, we patch the body to include a `deposit_instructions`
//!       pointer to the key's pre-allocated deposit address
//!
//! Out of scope for slice 1 (tracked in CM-03 WP-03.4 sprint file):
//!   - RocksDB persistence
//!   - SALT → wSALT auto-wrap watcher
//!   - Admin CLI binary (`citrate-gateway-admin`); for now the
//!     library-level [`create_key`] is the public admin surface
//!
//! Specs: `citrate_v0.01.1/specs/gherkin/gateway_api_key.feature`.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, Response, StatusCode};
use ethereum_types::{H160, U256};
use http_body_util::BodyExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tower::{Layer, Service};
use uuid::Uuid;

use x402_axum::{PricingStrategy, X402Paid};

/// RM-G2.3 / WP-G2.5 (audit F-3): hash the bearer key before
/// storing or looking up. Pre-fix we keyed `ApiKeyStore` by the
/// plaintext UUID, so a memory dump or RocksDB-snapshot leak
/// surfaced live keys an attacker could replay verbatim.
/// Post-fix the store only holds `sha256(key_id)`; the live key
/// material exists only on the holder's side.
fn hash_key_id(key_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(key_id.as_bytes());
    let out = h.finalize();
    hex::encode(out)
}

// ── Store ───────────────────────────────────────────────────────

/// What the key's `balance_grains` field is denominated in
/// (CM-06 WP-06.5).
///
///   Salt    : grains of SALT (default; existing CM-03 WP-03.4
///             behavior). Per-request debit equals the SALT price the
///             pricing strategy returns.
///   Credits : PFLOP-hour credits (18 decimals) backed by an
///             institution's BulkComputeGateway balance. Per-request
///             debit is the credit-equivalent of the SALT price; the
///             slice-1 layer treats the conversion 1:1 (debits the
///             same number of "units"), which is fine for tests but
///             not production-correct. Slice 2 wires an OracleAdapter
///             that converts via `saltPerPflopHour`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyBacking {
    /// Default — wSALT-equivalent grains.
    #[default]
    Salt,
    /// PFLOP-hour credits via BulkComputeGateway.
    Credits,
}

impl KeyBacking {
    /// Persisted discriminant for the durable [`crate::keystore::BalanceRecord`].
    fn as_u8(self) -> u8 {
        match self {
            KeyBacking::Salt => 0,
            KeyBacking::Credits => 1,
        }
    }

    /// Inverse of [`KeyBacking::as_u8`]; unknown values default to `Salt`.
    fn from_u8(v: u8) -> Self {
        match v {
            1 => KeyBacking::Credits,
            _ => KeyBacking::Salt,
        }
    }
}

/// One API key's mutable state.
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    /// Stable, opaque, operator-assigned label (`"pilot"`, `"ci"`).
    pub label: String,
    /// Current balance. Unit is grains of SALT when
    /// `backing == KeyBacking::Salt` (default); PFLOP-hour credits
    /// when `backing == KeyBacking::Credits`.
    pub balance_grains: U256,
    /// EOA address the operator allocated for this key's top-ups.
    /// Slice 2 will watch chain transfers to this address and credit
    /// the key automatically. For Credits-backed keys this is the
    /// institution's address whose BulkComputeGateway balance the
    /// key represents.
    pub deposit_address: H160,
    /// `true` once the admin revokes the key. Requests with a revoked
    /// key get 401 regardless of balance.
    pub revoked: bool,
    /// CM-06 WP-06.5 — what the balance is denominated in.
    pub backing: KeyBacking,
    /// Unix seconds when the key was minted.
    pub created_at: u64,
    /// INFER-S3 / WP-E — per-model remaining budgets (the in-memory backend's
    /// store; the persistent backend keeps these in its own `mbudget:`
    /// namespace and leaves this empty). A model absent from the map is
    /// uncapped. `BTreeMap` for deterministic enumeration.
    pub model_budgets: std::collections::BTreeMap<String, U256>,
}

/// Downstream handlers attach this to successful responses when the exact
/// accepted charge differs from the API-key layer's conservative pre-debit.
#[derive(Debug, Clone, Copy)]
pub struct ApiKeyCharge {
    /// Final charge in the key's balance unit.
    pub amount_grains: U256,
}

/// Store of API keys. Wrapped in `Arc`.
///
/// `Memory` is the in-process map (unit/integration tests + the test/injection
/// boot paths). `Persistent` is the RocksDB-backed, crash-atomic store used in
/// production marketplace mode (INFER-S4 / WP-F, TD-22): balances survive a
/// restart and debit/refund apply exactly once. The async API is identical
/// across both backends, so the audited x402 / `ApiKeyLayer` path never has to
/// know which one it's talking to.
pub struct ApiKeyStore {
    backend: Backend,
}

enum Backend {
    Memory(RwLock<HashMap<String, ApiKeyRecord>>),
    Persistent(Arc<crate::keystore::PersistentKeyStore>),
}

impl std::fmt::Debug for ApiKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.backend {
            Backend::Memory(_) => "memory",
            Backend::Persistent(_) => "persistent",
        };
        f.debug_struct("ApiKeyStore").field("backend", &kind).finish()
    }
}

impl Default for ApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiKeyStore {
    /// In-memory store (tests + the test/injection boot path).
    pub fn new() -> Self {
        Self {
            backend: Backend::Memory(RwLock::new(HashMap::new())),
        }
    }

    /// Durable, RocksDB-backed store at `path` (production marketplace boot).
    /// Balances and revocations survive a restart; debit/refund are
    /// crash-atomic (WP-F).
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, crate::keystore::StoreError> {
        Ok(Self::with_persistent(crate::keystore::PersistentKeyStore::open(path)?))
    }

    /// Build over an already-open persistent store, so the API-key balances and
    /// the durable batch store (WP-F F2) can **share one RocksDB** — the
    /// prerequisite for committing a batch refund + its balance credit in a
    /// single atomic write.
    pub fn with_persistent(store: Arc<crate::keystore::PersistentKeyStore>) -> Self {
        Self {
            backend: Backend::Persistent(store),
        }
    }

    /// Read a key's current record. The argument is the bearer
    /// token the caller supplied; the store hashes it before
    /// looking up (audit F-3).
    pub async fn get(&self, key_id: &str) -> Option<ApiKeyRecord> {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                m.read().await.get(&h).cloned()
            }
            Backend::Persistent(p) => {
                p.get_balance_record(key_id).ok().flatten().map(record_from_balance)
            }
        }
    }

    /// Try to debit `amount` from `key_id`. Returns the new balance
    /// on success. Atomic w.r.t. concurrent callers — holds the
    /// write lock (Memory) or per-key lock + synced commit (Persistent)
    /// through the check-and-deduct.
    pub async fn debit(&self, key_id: &str, amount: U256) -> Result<U256, DebitError> {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                let mut guard = m.write().await;
                let record = guard.get_mut(&h).ok_or(DebitError::Unknown)?;
                if record.revoked {
                    return Err(DebitError::Revoked);
                }
                if record.balance_grains < amount {
                    return Err(DebitError::Insufficient(record.balance_grains));
                }
                record.balance_grains -= amount;
                Ok(record.balance_grains)
            }
            Backend::Persistent(p) => p.debit_balance(key_id, amount).map_err(DebitError::from_balance),
        }
    }

    /// Credit a key after a downstream rejection, over-estimate adjustment, or
    /// batch slot failure. Refunds intentionally bypass `revoked`; revocation
    /// stops future spending but must not trap already-debited buyer funds.
    pub async fn refund(&self, key_id: &str, amount: U256) -> Result<U256, DebitError> {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                let mut guard = m.write().await;
                let record = guard.get_mut(&h).ok_or(DebitError::Unknown)?;
                record.balance_grains = record.balance_grains.saturating_add(amount);
                Ok(record.balance_grains)
            }
            Backend::Persistent(p) => p.refund_balance(key_id, amount).map_err(DebitError::from_balance),
        }
    }

    /// Revoke a key. Returns `Err(Unknown)` if no such key.
    pub async fn revoke(&self, key_id: &str) -> Result<(), DebitError> {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                let mut guard = m.write().await;
                let record = guard.get_mut(&h).ok_or(DebitError::Unknown)?;
                record.revoked = true;
                Ok(())
            }
            Backend::Persistent(p) => p.revoke(key_id).map_err(|_| DebitError::Unknown),
        }
    }

    // ── Per-model budgets (INFER-S3 / WP-E) ─────────────────────────

    /// Set (or replace) a key's remaining budget for `model`.
    pub async fn set_model_budget(&self, key_id: &str, model: &str, amount: U256) -> Result<(), DebitError> {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                let mut guard = m.write().await;
                let record = guard.get_mut(&h).ok_or(DebitError::Unknown)?;
                record.model_budgets.insert(model.to_owned(), amount);
                Ok(())
            }
            Backend::Persistent(p) => p.set_model_budget(key_id, model, amount).map_err(|_| DebitError::Unknown),
        }
    }

    /// All `(model, remaining)` budgets set for a key.
    pub async fn get_model_budgets(&self, key_id: &str) -> Vec<(String, U256)> {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                m.read()
                    .await
                    .get(&h)
                    .map(|r| r.model_budgets.iter().map(|(k, v)| (k.clone(), *v)).collect())
                    .unwrap_or_default()
            }
            Backend::Persistent(p) => p.get_model_budgets(key_id).unwrap_or_default(),
        }
    }

    /// Debit a model's budget. **No-op `Ok` if the model is uncapped.** Atomic
    /// check-and-deduct; `Err(Exceeded(remaining))` if the budget is insufficient.
    pub async fn debit_model_budget(
        &self,
        key_id: &str,
        model: &str,
        amount: U256,
    ) -> Result<(), crate::keystore::ModelBudgetError> {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                let mut guard = m.write().await;
                let Some(record) = guard.get_mut(&h) else {
                    return Ok(()); // unknown key here behaves as uncapped; overall debit already gated it
                };
                match record.model_budgets.get_mut(model) {
                    Some(remaining) => {
                        if *remaining < amount {
                            Err(crate::keystore::ModelBudgetError::Exceeded(*remaining))
                        } else {
                            *remaining -= amount;
                            Ok(())
                        }
                    }
                    None => Ok(()), // uncapped
                }
            }
            Backend::Persistent(p) => p.debit_model_budget(key_id, model, amount),
        }
    }

    /// Credit a model's budget back. **No-op if uncapped.** Never creates a budget.
    pub async fn refund_model_budget(&self, key_id: &str, model: &str, amount: U256) {
        match &self.backend {
            Backend::Memory(m) => {
                let h = hash_key_id(key_id);
                let mut guard = m.write().await;
                if let Some(record) = guard.get_mut(&h) {
                    if let Some(remaining) = record.model_budgets.get_mut(model) {
                        *remaining = remaining.saturating_add(amount);
                    }
                }
            }
            Backend::Persistent(p) => {
                let _ = p.refund_model_budget(key_id, model, amount);
            }
        }
    }

    /// Mint and insert a fresh record, returning the plaintext `cgk_` token.
    /// Backend-agnostic home for [`create_key_with_backing`].
    async fn insert(&self, label: String, balance: U256, deposit: H160, backing: KeyBacking) -> String {
        match &self.backend {
            Backend::Memory(m) => {
                let key_id = format!("cgk_{}", Uuid::new_v4().simple());
                let record = ApiKeyRecord {
                    label,
                    balance_grains: balance,
                    deposit_address: deposit,
                    revoked: false,
                    backing,
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    model_budgets: std::collections::BTreeMap::new(),
                };
                m.write().await.insert(hash_key_id(&key_id), record);
                key_id
            }
            Backend::Persistent(p) => p
                .create_balance_key(label, balance, deposit, backing.as_u8())
                .expect("persistent keystore create_balance_key"),
        }
    }

    /// Test-only: does the in-memory backend hold this map key?
    #[cfg(test)]
    async fn memory_contains_key(&self, map_key: &str) -> bool {
        match &self.backend {
            Backend::Memory(m) => m.read().await.contains_key(map_key),
            Backend::Persistent(_) => false,
        }
    }
}

/// Build an [`ApiKeyRecord`] view from a persisted [`crate::keystore::BalanceRecord`].
fn record_from_balance(br: crate::keystore::BalanceRecord) -> ApiKeyRecord {
    ApiKeyRecord {
        label: br.label,
        balance_grains: U256::from_big_endian(&br.balance_be),
        deposit_address: H160(br.deposit_address),
        revoked: br.revoked,
        backing: KeyBacking::from_u8(br.backing),
        created_at: br.created_at,
        model_budgets: std::collections::BTreeMap::new(),
    }
}

/// Why a debit attempt failed.
#[derive(Debug)]
pub enum DebitError {
    /// No such key.
    Unknown,
    /// Key is revoked.
    Revoked,
    /// Current balance in grains was less than the requested amount.
    Insufficient(U256),
}

impl DebitError {
    /// Map a durable-store [`crate::keystore::BalanceError`] onto the layer's
    /// `DebitError`. A transient store/encode error maps to `Unknown` — the
    /// `ApiKeyLayer` treats that as "couldn't debit" and falls through to the
    /// x402 challenge, so no buyer is charged on a backend hiccup.
    fn from_balance(e: crate::keystore::BalanceError) -> Self {
        use crate::keystore::BalanceError;
        match e {
            BalanceError::Unknown => DebitError::Unknown,
            BalanceError::Revoked => DebitError::Revoked,
            BalanceError::Insufficient(bal) => DebitError::Insufficient(bal),
            BalanceError::Store(_) | BalanceError::Encode(_) => DebitError::Unknown,
        }
    }
}

/// Admin: mint a new SALT-backed API key.
///
/// Returns the opaque key_id string the holder should send in
/// `Authorization: Bearer <id>`. Slice-1 ids are UUIDs; slice 2 may
/// swap in a stronger HMAC-derived format.
///
/// Equivalent to `create_key_with_backing(..., KeyBacking::Salt)` —
/// kept as a separate function so existing callers (and the
/// integration test suite from CM-03 WP-03.4) don't have to change
/// their signatures.
pub async fn create_key(
    store: &ApiKeyStore,
    label: impl Into<String>,
    initial_balance_grains: U256,
    deposit_address: H160,
) -> String {
    create_key_with_backing(
        store,
        label,
        initial_balance_grains,
        deposit_address,
        KeyBacking::Salt,
    )
    .await
}

/// Admin: mint a new API key with an explicit backing choice
/// (CM-06 WP-06.5).
///
/// Use `KeyBacking::Credits` for an institution that pre-purchased
/// compute credits via BulkComputeGateway. The key's balance is
/// then in PFLOP-hours (18 decimals); the per-request debit logic
/// in `ApiKeyLayer` is unit-agnostic — slice 2 will wire an
/// OracleAdapter to convert SALT-priced requests into credit cost.
pub async fn create_key_with_backing(
    store: &ApiKeyStore,
    label: impl Into<String>,
    initial_balance: U256,
    deposit_address: H160,
    backing: KeyBacking,
) -> String {
    // RM-G2.3 / audit F-3: the holder receives `key_id` (plaintext
    // UUID prefixed with `cgk_`); the store keys by `sha256(key_id)`
    // so the underlying map never holds material an attacker could
    // replay.
    store
        .insert(label.into(), initial_balance, deposit_address, backing)
        .await
}

// ── Layer ───────────────────────────────────────────────────────

/// Tower layer. Wrap an already-x402-protected router with this to
/// add the Bearer-key bypass.
#[derive(Clone)]
pub struct ApiKeyLayer {
    store: Arc<ApiKeyStore>,
    pricing: Arc<dyn PricingStrategy>,
}

impl std::fmt::Debug for ApiKeyLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyLayer").finish_non_exhaustive()
    }
}

impl ApiKeyLayer {
    /// Construct. `pricing` must be the same strategy the inner
    /// `X402Layer` uses so the amount deducted from the key's
    /// balance matches what the x402 challenge would have charged.
    pub fn new(store: Arc<ApiKeyStore>, pricing: Arc<dyn PricingStrategy>) -> Self {
        Self { store, pricing }
    }
}

impl<S> Layer<S> for ApiKeyLayer {
    type Service = ApiKeyService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ApiKeyService {
            inner,
            store: self.store.clone(),
            pricing: self.pricing.clone(),
        }
    }
}

/// Tower service producted by [`ApiKeyLayer`].
#[derive(Clone)]
pub struct ApiKeyService<S> {
    inner: S,
    store: Arc<ApiKeyStore>,
    pricing: Arc<dyn PricingStrategy>,
}

impl<S> Service<Request<Body>> for ApiKeyService<S>
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
        let pricing = self.pricing.clone();
        // Clone-before-replace pattern (same as X402Layer).
        let inner_ready = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, inner_ready);

        Box::pin(async move {
            let bearer = extract_bearer(req.headers());

            let key_id = match bearer {
                None => {
                    // No Authorization → plain x402 flow unchanged.
                    let mut inner = inner;
                    return inner.call(req).await;
                }
                Some(k) => k,
            };

            // Look up the key up-front so we can route cleanly.
            let record = store.get(&key_id).await;
            let Some(record) = record else {
                metrics::counter!("gateway_api_key_requests_total", 1, "outcome" => "unknown");
                return Ok(build_401("unknown api key"));
            };
            if record.revoked {
                metrics::counter!("gateway_api_key_requests_total", 1, "outcome" => "revoked");
                return Ok(build_401("api key revoked"));
            }

            // Price the request — same strategy x402 would use.
            let price = match pricing.price_for(&req).await {
                Ok(p) => p,
                Err(e) => return Ok(build_400(&e.to_string())),
            };

            if record.balance_grains < price {
                // Exhausted (or too-small balance). Fall through to
                // X402Layer so the challenge body is authentically
                // built, then post-process to attach a deposit hint.
                metrics::counter!("gateway_api_key_requests_total", 1, "outcome" => "exhausted");
                let deposit = record.deposit_address;
                let mut inner = inner;
                let resp = inner.call(req).await?;
                return Ok(attach_deposit_hint(resp, deposit).await);
            }

            // Valid + funded. Debit now (atomic). If someone else
            // drained the balance between the read and this debit,
            // fall through to the same exhausted path.
            match store.debit(&key_id, price).await {
                Ok(_new_balance) => {
                    metrics::counter!("gateway_api_key_requests_total", 1, "outcome" => "funded");
                    // Attach synthetic X402Paid so X402Layer's bypass
                    // short-circuits its challenge flow, plus an
                    // `ApiKeyContext` so downstream handlers (chat,
                    // batch) can emit per-key usage rows.
                    let mut req = req;
                    req.extensions_mut().insert(X402Paid {
                        payer: record.deposit_address,
                        amount_wei: price,
                        nonce: ethereum_types::H256::zero(),
                        settle_tx_hash: ethereum_types::H256::zero(),
                    });
                    req.extensions_mut().insert(crate::usage::ApiKeyContext {
                        key_id: key_id.clone(),
                        backing: record.backing,
                    });
                    let mut inner = inner;
                    let resp = inner.call(req).await?;
                    Ok(settle_api_key_response(store, key_id, price, resp).await)
                }
                Err(_) => {
                    // Race with concurrent drain — same fallthrough.
                    let deposit = record.deposit_address;
                    let mut inner = inner;
                    let resp = inner.call(req).await?;
                    Ok(attach_deposit_hint(resp, deposit).await)
                }
            }
        })
    }
}

// ── Helpers ─────────────────────────────────────────────────────

async fn settle_api_key_response(
    store: Arc<ApiKeyStore>,
    key_id: String,
    debited: U256,
    resp: Response<Body>,
) -> Response<Body> {
    if resp.status().is_success() {
        if let Some(charge) = resp.extensions().get::<ApiKeyCharge>() {
            if charge.amount_grains < debited {
                let refund = debited - charge.amount_grains;
                if let Err(err) = store.refund(&key_id, refund).await {
                    tracing::warn!(
                        key_id = %key_id,
                        refund = %refund,
                        error = ?err,
                        "api key over-estimate refund failed"
                    );
                } else {
                    metrics::counter!("gateway_api_key_refunds_total", 1, "reason" => "overestimate");
                }
            } else if charge.amount_grains > debited {
                tracing::error!(
                    key_id = %key_id,
                    debited = %debited,
                    charged = %charge.amount_grains,
                    "api key handler accepted a charge larger than the pre-debit"
                );
            }
        }
        return resp;
    }

    if let Err(err) = store.refund(&key_id, debited).await {
        tracing::warn!(
            key_id = %key_id,
            refund = %debited,
            status = %resp.status(),
            error = ?err,
            "api key rejection refund failed"
        );
    } else {
        metrics::counter!("gateway_api_key_refunds_total", 1, "reason" => "downstream_error");
    }
    resp
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn build_401(msg: &str) -> Response<Body> {
    let body = serde_json::json!({
        "error": { "message": msg }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn build_400(msg: &str) -> Response<Body> {
    let body = serde_json::json!({
        "error": { "message": msg }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[derive(Serialize)]
struct DepositHint {
    address: String,
    message: &'static str,
}

/// If `resp` is a 402 JSON body, parse it, add a `deposit_instructions`
/// object, re-serialize. Otherwise return unchanged.
async fn attach_deposit_hint(resp: Response<Body>, deposit: H160) -> Response<Body> {
    if resp.status() != StatusCode::PAYMENT_REQUIRED {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            // Can't inspect body — return original shape.
            return Response::from_parts(parts, Body::empty());
        }
    };
    let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            // Not JSON — pass through byte-identical.
            return Response::from_parts(parts, Body::from(bytes));
        }
    };
    if let Some(obj) = value.as_object_mut() {
        let hint = DepositHint {
            address: format!("0x{}", hex::encode(deposit.as_bytes())),
            message: "Send SALT to this address to top up the key",
        };
        obj.insert(
            "deposit_instructions".to_string(),
            serde_json::to_value(hint).unwrap_or(serde_json::Value::Null),
        );
    }
    let new_body = value.to_string();
    let mut new_resp = Response::from_parts(parts, Body::from(new_body.clone()));
    // Strip any stale content-length so axum recomputes.
    new_resp.headers_mut().remove(header::CONTENT_LENGTH);
    new_resp
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CM-06 WP-06.5 — KeyBacking ─────────────────────────────

    #[tokio::test]
    async fn create_key_defaults_to_salt_backing() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "default", U256::from(100u64), H160::zero()).await;
        let r = store.get(&id).await.expect("exists");
        assert_eq!(r.backing, KeyBacking::Salt);
    }

    #[tokio::test]
    async fn create_key_with_credits_backing_records_it() {
        let store = ApiKeyStore::new();
        let id = create_key_with_backing(
            &store,
            "credits-key",
            U256::from(10u64) * U256::from(1_000_000_000_000_000_000u128),
            H160::from([0xcc; 20]),
            KeyBacking::Credits,
        )
        .await;
        let r = store.get(&id).await.expect("exists");
        assert_eq!(r.backing, KeyBacking::Credits);
    }

    #[tokio::test]
    async fn debit_works_for_credits_backed_key() {
        // Slice 1 — debit logic is unit-agnostic; same code path as
        // SALT-backed. Slice 2 will introduce a unit conversion via
        // an OracleAdapter.
        let store = ApiKeyStore::new();
        let id = create_key_with_backing(
            &store,
            "credits-key",
            U256::from(100u64),
            H160::zero(),
            KeyBacking::Credits,
        )
        .await;
        let new_bal = store.debit(&id, U256::from(30u64)).await.expect("debit");
        assert_eq!(new_bal, U256::from(70u64));
        let r = store.get(&id).await.expect("exists");
        assert_eq!(r.backing, KeyBacking::Credits); // unchanged
    }

    #[tokio::test]
    async fn key_backing_default_impl() {
        // Documented default-trait behaviour for downstream consumers.
        let kb: KeyBacking = Default::default();
        assert_eq!(kb, KeyBacking::Salt);
    }

    // ── Existing tests (unchanged) ─────────────────────────────

    #[tokio::test]
    async fn create_then_get_roundtrip() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "test", U256::from(100u64), H160::from([0xab; 20])).await;
        let r = store.get(&id).await.expect("exists");
        assert_eq!(r.label, "test");
        assert_eq!(r.balance_grains, U256::from(100u64));
        assert!(!r.revoked);
    }

    /// RM-G2.3 / audit F-3: storage holds sha256(key_id), not the
    /// plaintext token. Even if the inner map is dumped, the
    /// attacker can't replay the keys without preimage.
    #[tokio::test]
    async fn store_holds_hashed_key_not_plaintext() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "f3", U256::from(1u64), H160::zero()).await;
        // The map MUST NOT contain the plaintext id.
        assert!(
            !store.memory_contains_key(&id).await,
            "storage must not key by plaintext id (audit F-3)"
        );
        // The map MUST contain the sha256 hash.
        let h = hash_key_id(&id);
        assert!(
            store.memory_contains_key(&h).await,
            "storage must key by sha256(id) (audit F-3)"
        );
        // sha256 hex is 64 chars.
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn hash_key_id_is_deterministic_and_collision_resistant() {
        let h1 = hash_key_id("cgk_abc");
        let h2 = hash_key_id("cgk_abc");
        let h3 = hash_key_id("cgk_xyz");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[tokio::test]
    async fn debit_reduces_balance() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "", U256::from(100u64), H160::zero()).await;
        let new_bal = store.debit(&id, U256::from(30u64)).await.expect("debit");
        assert_eq!(new_bal, U256::from(70u64));
    }

    #[tokio::test]
    async fn refund_restores_balance_even_when_key_revoked() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "", U256::from(100u64), H160::zero()).await;
        let new_bal = store.debit(&id, U256::from(30u64)).await.expect("debit");
        assert_eq!(new_bal, U256::from(70u64));

        store.revoke(&id).await.expect("revoke");
        let refunded = store.refund(&id, U256::from(30u64)).await.expect("refund");
        assert_eq!(refunded, U256::from(100u64));
    }

    #[tokio::test]
    async fn debit_insufficient_surfaces_balance() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "", U256::from(10u64), H160::zero()).await;
        let err = store
            .debit(&id, U256::from(999u64))
            .await
            .expect_err("fail");
        assert!(matches!(err, DebitError::Insufficient(b) if b == U256::from(10u64)));
    }

    #[tokio::test]
    async fn revoked_key_cannot_debit() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "", U256::from(100u64), H160::zero()).await;
        store.revoke(&id).await.expect("revoke");
        let err = store.debit(&id, U256::from(1u64)).await.expect_err("fail");
        assert!(matches!(err, DebitError::Revoked));
    }

    #[tokio::test]
    async fn unknown_key_debit_fails() {
        let store = ApiKeyStore::new();
        let err = store
            .debit("nope", U256::from(1u64))
            .await
            .expect_err("fail");
        assert!(matches!(err, DebitError::Unknown));
    }

    /// WP-E: the in-memory backend (the one the auth test harness uses) enforces
    /// per-model budgets — capped model exhausts independently, uncapped passes,
    /// refund restores the right bucket.
    #[tokio::test]
    async fn memory_model_budget_exhausts_refunds_and_passes_uncapped() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "k", U256::from(1000u64), H160::zero()).await;
        store.set_model_budget(&id, "llama", U256::from(5u64)).await.expect("set");

        store.debit_model_budget(&id, "llama", U256::from(5u64)).await.expect("debit");
        // llama exhausted
        assert!(matches!(
            store.debit_model_budget(&id, "llama", U256::from(1u64)).await,
            Err(crate::keystore::ModelBudgetError::Exceeded(_))
        ));
        // an uncapped model is a no-op pass
        store.debit_model_budget(&id, "mistral", U256::from(999u64)).await.expect("uncapped");
        // refund restores the llama bucket
        store.refund_model_budget(&id, "llama", U256::from(5u64)).await;
        store.debit_model_budget(&id, "llama", U256::from(5u64)).await.expect("debit after refund");

        let budgets = store.get_model_budgets(&id).await;
        assert_eq!(budgets, vec![("llama".to_string(), U256::zero())]);
    }

    #[test]
    fn extract_bearer_trims_whitespace() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer  cgk_abc  ".parse().expect("parse"),
        );
        assert_eq!(extract_bearer(&h).as_deref(), Some("cgk_abc"));
    }

    #[test]
    fn extract_bearer_missing() {
        let h = HeaderMap::new();
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_wrong_scheme() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Basic abc".parse().expect("parse"));
        assert!(extract_bearer(&h).is_none());
    }
}
