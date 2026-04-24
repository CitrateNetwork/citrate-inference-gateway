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
use tokio::sync::RwLock;
use tower::{Layer, Service};
use uuid::Uuid;

use x402_axum::{PricingStrategy, X402Paid};

// ── Store ───────────────────────────────────────────────────────

/// One API key's mutable state.
#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    /// Stable, opaque, operator-assigned label (`"pilot"`, `"ci"`).
    pub label: String,
    /// Current balance in grains (wei).
    pub balance_grains: U256,
    /// EOA address the operator allocated for this key's top-ups.
    /// Slice 2 will watch chain transfers to this address and credit
    /// the key automatically.
    pub deposit_address: H160,
    /// `true` once the admin revokes the key. Requests with a revoked
    /// key get 401 regardless of balance.
    pub revoked: bool,
    /// Unix seconds when the key was minted.
    pub created_at: u64,
}

/// In-memory store of API keys. Wrapped in `Arc`.
#[derive(Default, Debug)]
pub struct ApiKeyStore {
    inner: RwLock<HashMap<String, ApiKeyRecord>>,
}

impl ApiKeyStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a key's current record.
    pub async fn get(&self, key_id: &str) -> Option<ApiKeyRecord> {
        self.inner.read().await.get(key_id).cloned()
    }

    /// Try to debit `amount` from `key_id`. Returns the new balance
    /// on success, or `None` if the key is missing / revoked /
    /// insufficient. Atomic w.r.t. concurrent callers — holds the
    /// write lock through the check-and-deduct.
    pub async fn debit(
        &self,
        key_id: &str,
        amount: U256,
    ) -> Result<U256, DebitError> {
        let mut guard = self.inner.write().await;
        let record = guard.get_mut(key_id).ok_or(DebitError::Unknown)?;
        if record.revoked {
            return Err(DebitError::Revoked);
        }
        if record.balance_grains < amount {
            return Err(DebitError::Insufficient(record.balance_grains));
        }
        record.balance_grains -= amount;
        Ok(record.balance_grains)
    }

    /// Revoke a key. Returns `Err(Unknown)` if no such key.
    pub async fn revoke(&self, key_id: &str) -> Result<(), DebitError> {
        let mut guard = self.inner.write().await;
        let record = guard.get_mut(key_id).ok_or(DebitError::Unknown)?;
        record.revoked = true;
        Ok(())
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

/// Admin: mint a new API key.
///
/// Returns the opaque key_id string the holder should send in
/// `Authorization: Bearer <id>`. Slice-1 ids are UUIDs; slice 2 may
/// swap in a stronger HMAC-derived format.
pub async fn create_key(
    store: &ApiKeyStore,
    label: impl Into<String>,
    initial_balance_grains: U256,
    deposit_address: H160,
) -> String {
    let key_id = format!("cgk_{}", Uuid::new_v4().simple());
    let record = ApiKeyRecord {
        label: label.into(),
        balance_grains: initial_balance_grains,
        deposit_address,
        revoked: false,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    store.inner.write().await.insert(key_id.clone(), record);
    key_id
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
                return Ok(build_401("unknown api key"));
            };
            if record.revoked {
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
                    });
                    let mut inner = inner;
                    inner.call(req).await
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

    #[tokio::test]
    async fn create_then_get_roundtrip() {
        let store = ApiKeyStore::new();
        let id = create_key(
            &store,
            "test",
            U256::from(100u64),
            H160::from([0xab; 20]),
        )
        .await;
        let r = store.get(&id).await.expect("exists");
        assert_eq!(r.label, "test");
        assert_eq!(r.balance_grains, U256::from(100u64));
        assert!(!r.revoked);
    }

    #[tokio::test]
    async fn debit_reduces_balance() {
        let store = ApiKeyStore::new();
        let id = create_key(&store, "", U256::from(100u64), H160::zero()).await;
        let new_bal = store
            .debit(&id, U256::from(30u64))
            .await
            .expect("debit");
        assert_eq!(new_bal, U256::from(70u64));
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
        let err = store.debit("nope", U256::from(1u64)).await.expect_err("fail");
        assert!(matches!(err, DebitError::Unknown));
    }

    #[test]
    fn extract_bearer_trims_whitespace() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer  cgk_abc  ".parse().expect("parse"));
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
