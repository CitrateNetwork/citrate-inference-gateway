//! The `X402Layer` tower middleware.
//!
//! WP-02.2 wired the unpaid path (challenge generation → 402).
//! WP-02.3 wires the paid path: parse X-PAYMENT, verify via precompile
//! `0x0201`, build + submit settlement tx, poll receipt, extract
//! `PaymentSettled`, attach [`X402Paid`] to the request, forward to
//! the inner service.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use tower::{Layer, Service};

use ethereum_types::{H160, U256};

use crate::calldata::encode_settle_payment;
use crate::chain::{ChainClient, HttpChainClient};
use crate::challenge::{build_challenge, now_unix_secs, ChallengeInputs};
use crate::digest::wsalt_domain_separator;
use crate::error::X402Error;
use crate::header::{decode as decode_payment_header, X_PAYMENT_HEADER};
use crate::ledger::NonceLedger;
use crate::nonce::NonceSource;
use crate::observability::{NoopObservability, ObservabilityHook, RejectedEvent, SettledEvent};
use crate::pricing::PricingStrategy;
use crate::receipt::find_payment_settled;
use crate::types::X402Paid;

/// Fully-configured x402 middleware. Apply to any axum router via
/// `router.layer(layer)`. See crate-level docs for the integration
/// example.
#[derive(Clone)]
pub struct X402Layer {
    pub(crate) config: Arc<X402Config>,
    pub(crate) nonces: Arc<NonceSource>,
}

/// Internal configuration shared across the tower service.
pub(crate) struct X402Config {
    /// Chain ID — `40204` for Citrate testnet.
    pub chain_id: u64,
    /// `X402Facilitator` contract address on this chain.
    pub facilitator_address: H160,
    /// `WrappedSALT` contract address on this chain.
    pub wsalt_address: H160,
    /// Where the facilitator routes net payment after fees.
    pub treasury: H160,
    /// Pricing strategy — pluggable per deployment.
    pub pricing: Arc<dyn PricingStrategy>,
    /// Chain client (precompile verify + nonce + raw tx + receipt).
    pub chain: Arc<dyn ChainClient>,
    /// Observability hook — called on settlement success and rejection.
    /// Defaults to `NoopObservability` if unset.
    pub observability: Arc<dyn ObservabilityHook>,
    /// Operator wallet that signs the settlement tx. Secp256k1 key —
    /// stored as raw bytes so we can produce a fresh `SigningKey`
    /// per request (k256's `SigningKey` is not `Sync`).
    pub operator_secret: [u8; 32],
    /// Operator address derived from `operator_secret` at build time.
    pub operator_address: H160,
    /// Gas price for the settlement tx (wei).
    pub gas_price_wei: u64,
    /// Gas limit for the settlement tx.
    pub gas_limit: u64,
    /// How long challenges remain valid. Default 300 seconds.
    pub challenge_ttl_secs: u64,
    /// Receipt polling ceiling — after this, settle is reported as
    /// pending (scenario 9 in x402_payment.feature).
    pub receipt_timeout_secs: u64,
    /// Ledger of server-issued challenge nonces. The paid path only
    /// accepts a payment whose nonce was minted by this gateway, is
    /// unexpired, and has not been used before (2026-05-31 audit 001).
    pub nonce_ledger: Arc<NonceLedger>,
}

impl std::fmt::Debug for X402Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402Config")
            .field("chain_id", &self.chain_id)
            .field("facilitator_address", &self.facilitator_address)
            .field("wsalt_address", &self.wsalt_address)
            .field("treasury", &self.treasury)
            .field("operator_address", &self.operator_address)
            .field("gas_price_wei", &self.gas_price_wei)
            .field("gas_limit", &self.gas_limit)
            .field("challenge_ttl_secs", &self.challenge_ttl_secs)
            .field("receipt_timeout_secs", &self.receipt_timeout_secs)
            // Don't print operator_secret or chain/pricing for
            // obvious reasons.
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for X402Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X402Layer").field(&self.config).finish()
    }
}

impl X402Layer {
    /// Start building a new layer. See [`X402LayerBuilder`] for the
    /// required fields.
    pub fn builder() -> X402LayerBuilder {
        X402LayerBuilder::default()
    }
}

/// Builder for [`X402Layer`]. Required fields return
/// [`X402Error::Internal`] if omitted from `build()`.
#[derive(Default)]
pub struct X402LayerBuilder {
    chain_id: Option<u64>,
    facilitator_address: Option<H160>,
    wsalt_address: Option<H160>,
    treasury: Option<H160>,
    rpc_url: Option<String>,
    pricing: Option<Arc<dyn PricingStrategy>>,
    chain: Option<Arc<dyn ChainClient>>,
    observability: Option<Arc<dyn ObservabilityHook>>,
    operator_secret: Option<[u8; 32]>,
    gas_price_wei: Option<u64>,
    gas_limit: Option<u64>,
    challenge_ttl_secs: Option<u64>,
    receipt_timeout_secs: Option<u64>,
}

impl X402LayerBuilder {
    /// Required: chain ID (e.g. `40204`).
    pub fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = Some(id);
        self
    }

    /// Required: `X402Facilitator` address as a `0x`-prefixed hex string.
    pub fn facilitator_address(mut self, addr: &str) -> Self {
        self.facilitator_address = parse_addr(addr);
        self
    }

    /// Required: `WrappedSALT` address.
    pub fn wsalt_address(mut self, addr: &str) -> Self {
        self.wsalt_address = parse_addr(addr);
        self
    }

    /// Required: treasury address (fee + net value destination).
    pub fn treasury(mut self, addr: &str) -> Self {
        self.treasury = parse_addr(addr);
        self
    }

    /// Required: JSON-RPC URL.
    pub fn rpc_url(mut self, url: impl Into<String>) -> Self {
        self.rpc_url = Some(url.into());
        self
    }

    /// Required: pricing strategy.
    pub fn pricing<P: PricingStrategy + 'static>(mut self, pricing: P) -> Self {
        self.pricing = Some(Arc::new(pricing));
        self
    }

    /// Optional: override the default 300-second challenge validity.
    pub fn challenge_ttl_secs(mut self, secs: u64) -> Self {
        self.challenge_ttl_secs = Some(secs);
        self
    }

    /// Optional: override the default 10-second receipt poll timeout.
    pub fn receipt_timeout_secs(mut self, secs: u64) -> Self {
        self.receipt_timeout_secs = Some(secs);
        self
    }

    /// Required: operator secp256k1 private key, 32 bytes. The
    /// matching address is derived at build time and must hold SALT
    /// to fund the settlement tx's gas.
    pub fn operator_secret_hex(mut self, hex_or_prefixed: &str) -> Self {
        let s = hex_or_prefixed
            .strip_prefix("0x")
            .unwrap_or(hex_or_prefixed);
        if let Ok(bytes) = hex::decode(s) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                self.operator_secret = Some(arr);
            }
        }
        self
    }

    /// Required: operator secp256k1 private key as raw bytes.
    pub fn operator_secret_bytes(mut self, secret: [u8; 32]) -> Self {
        self.operator_secret = Some(secret);
        self
    }

    /// Optional: inject a custom [`ChainClient`]. If omitted, the
    /// builder constructs an [`HttpChainClient`] pointing at the
    /// configured `rpc_url`.
    pub fn chain_client<C: ChainClient + 'static>(mut self, chain: C) -> Self {
        self.chain = Some(Arc::new(chain));
        self
    }

    /// Optional: inject an [`ObservabilityHook`]. Defaults to
    /// [`NoopObservability`] if unset. Use
    /// [`crate::CountersObservability`] for simple in-memory metrics
    /// or implement the trait for a custom Prometheus/trail wiring.
    pub fn observability<H: ObservabilityHook + 'static>(mut self, hook: H) -> Self {
        self.observability = Some(Arc::new(hook));
        self
    }

    /// Optional: gas price in wei for the settle tx. Default: 1 gwei.
    pub fn gas_price_wei(mut self, price: u64) -> Self {
        self.gas_price_wei = Some(price);
        self
    }

    /// Optional: gas limit for the settle tx. Default: 200_000.
    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = Some(limit);
        self
    }

    /// Finalize into an [`X402Layer`], or return a configuration error.
    pub fn build(self) -> Result<X402Layer, X402Error> {
        let chain_id = self
            .chain_id
            .ok_or_else(|| X402Error::Internal("chain_id not set".into()))?;
        let facilitator_address = self
            .facilitator_address
            .ok_or_else(|| X402Error::Internal("facilitator_address not set".into()))?;
        let wsalt_address = self
            .wsalt_address
            .ok_or_else(|| X402Error::Internal("wsalt_address not set".into()))?;
        let treasury = self
            .treasury
            .ok_or_else(|| X402Error::Internal("treasury not set".into()))?;
        let rpc_url = self
            .rpc_url
            .ok_or_else(|| X402Error::Internal("rpc_url not set".into()))?;
        let pricing = self
            .pricing
            .ok_or_else(|| X402Error::Internal("pricing not set".into()))?;
        let operator_secret = self
            .operator_secret
            .ok_or_else(|| X402Error::Internal("operator_secret not set".into()))?;

        // Derive operator address from the secp256k1 key.
        let operator_address = crate::keys::derive_secp256k1_address(&operator_secret)
            .ok_or_else(|| X402Error::Internal("invalid operator_secret: not a valid scalar".into()))?;

        // If no chain client was injected, instantiate the default
        // reqwest-backed one pointing at `rpc_url`.
        let chain = self
            .chain
            .unwrap_or_else(|| Arc::new(HttpChainClient::new(&rpc_url)));

        let observability = self
            .observability
            .unwrap_or_else(|| Arc::new(NoopObservability));

        Ok(X402Layer {
            config: Arc::new(X402Config {
                chain_id,
                facilitator_address,
                wsalt_address,
                treasury,
                pricing,
                chain,
                observability,
                operator_secret,
                operator_address,
                gas_price_wei: self.gas_price_wei.unwrap_or(1_000_000_000), // 1 gwei
                gas_limit: self.gas_limit.unwrap_or(200_000),
                challenge_ttl_secs: self.challenge_ttl_secs.unwrap_or(300),
                receipt_timeout_secs: self.receipt_timeout_secs.unwrap_or(10),
                nonce_ledger: Arc::new(NonceLedger::new(
                    crate::ledger::DEFAULT_MAX_OUTSTANDING,
                )),
            }),
            nonces: Arc::new(NonceSource::new()),
        })
    }
}

// derive_secp256k1_address moved to crate::keys in WP-02.4 so it's
// shared with the X402Client payer-address derivation.

// ── Tower middleware glue ──────────────────────────────────────────

impl<S> Layer<S> for X402Layer {
    type Service = X402Service<S>;

    fn layer(&self, inner: S) -> Self::Service {
        X402Service {
            inner,
            config: self.config.clone(),
            nonces: self.nonces.clone(),
        }
    }
}

/// Tower service produced by [`X402Layer::layer`]. Clones cheaply
/// (everything behind it is `Arc`-shared or thin); axum clones the
/// service once per request, as expected.
#[derive(Clone)]
pub struct X402Service<S> {
    inner: S,
    config: Arc<X402Config>,
    nonces: Arc<NonceSource>,
}

impl<S> Service<Request<Body>> for X402Service<S>
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
        let config = self.config.clone();
        let nonces = self.nonces.clone();
        // Prepare a ready-to-go inner service (tower's
        // buffering pattern — swapping inner keeps the service
        // correct-by-construction w.r.t. ownership).
        let inner_ready = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, inner_ready);

        Box::pin(async move {
            // Bypass: if an upstream layer has already attached
            // `X402Paid` (e.g. the gateway's API-key middleware
            // deducted from a pre-funded key), skip the whole
            // challenge/settle flow and forward directly.
            if req.extensions().get::<X402Paid>().is_some() {
                let mut inner = inner;
                let fut = inner.call(req);
                return fut.await;
            }

            // Price first — 400 on unpriceable.
            let price = match config.pricing.price_for(&req).await {
                Ok(p) => p,
                Err(e) => return Ok(build_400_response(&e.to_string())),
            };

            // Peel out the X-PAYMENT header value early (ownership).
            let payment_header: Option<String> = req
                .headers()
                .get(X_PAYMENT_HEADER)
                .and_then(|v| v.to_str().ok().map(|s| s.to_string()));

            if payment_header.is_none() {
                // Unpaid → 402 with challenge. (WP-02.2 path.)
                drop(inner);
                let challenge = match make_challenge(&config, &nonces, price) {
                    Ok(c) => c,
                    Err(e) => return Ok(build_500_response(&e.to_string())),
                };
                return Ok(build_402_response(&challenge, None));
            }

            // WP-02.3 paid path.
            let header_value = payment_header.expect("checked above");
            match run_paid_path(&config, &header_value, price, req).await {
                PaidOutcome::Forward(req_with_paid, settled) => {
                    // Emit success observability BEFORE invoking the
                    // inner service — keeps the metric count aligned
                    // with "we charged and released" even if the
                    // inner handler panics or returns 5xx.
                    config.observability.on_settled(&settled).await;

                    // Forward to inner service. Only now do we need `inner`.
                    let mut inner = inner;
                    let fut = inner.call(*req_with_paid);
                    fut.await
                }
                PaidOutcome::Reject(err) => {
                    drop(inner);
                    let reason = err.reason();
                    let status = err.http_status();
                    config
                        .observability
                        .on_rejected(&RejectedEvent {
                            reason,
                            http_status: status,
                            payer: None,
                        })
                        .await;
                    let challenge = match make_challenge(&config, &nonces, price) {
                        Ok(c) => c,
                        Err(e) => return Ok(build_500_response(&e.to_string())),
                    };
                    Ok(build_402_response(&challenge, Some(reason)))
                }
                PaidOutcome::ServerError(err) => {
                    drop(inner);
                    let reason = err.reason();
                    let status = err.http_status();
                    config
                        .observability
                        .on_rejected(&RejectedEvent {
                            reason,
                            http_status: status,
                            payer: None,
                        })
                        .await;
                    Ok(build_error_response(err))
                }
            }
        })
    }
}

/// Intermediate outcome of the paid path — lets us unify the
/// reject-vs-server-error vs. forward-to-inner branches.
///
/// `Forward` is boxed because `Request<Body>` is a multi-hundred-byte
/// struct and clippy's `large_enum_variant` rightly flags it —
/// boxing keeps the common `Reject(X402Error)` path's enum size
/// small.
enum PaidOutcome {
    /// Forward the (possibly augmented) request to the inner service.
    /// Carries the settlement event so the outer `call()` can fire
    /// the observability hook before invoking the inner.
    Forward(Box<Request<Body>>, SettledEvent),
    /// Reject with a 402 response. Server has a fresh challenge ready.
    Reject(X402Error),
    /// Server-side failure — 500 with a reason.
    ServerError(X402Error),
}

async fn run_paid_path(
    config: &X402Config,
    header_value: &str,
    price: U256,
    mut req: Request<Body>,
) -> PaidOutcome {
    // 1. Parse header → PaymentPayload.
    let payload = match decode_payment_header(header_value) {
        Ok(p) => p,
        Err(e) => return PaidOutcome::Reject(e),
    };

    // 2. Window check (expired / not yet valid).
    let now = U256::from(now_unix_secs());
    if payload.valid_before <= now || payload.valid_after > now {
        return PaidOutcome::Reject(X402Error::Expired);
    }

    // 2b. Challenge-nonce ledger (2026-05-31 audit 001): the nonce must
    // be one THIS gateway minted, unexpired, and never used before.
    // Consumed (removed) on first use, so a concurrent second payment
    // with the same nonce is rejected before any chain work — the
    // on-chain `_authorizationStates` map remains the settlement-level
    // backstop. A failed settle burns the challenge; clients simply
    // re-challenge (the 402 response carries a fresh one).
    if config
        .nonce_ledger
        .consume(&payload.nonce, now_unix_secs())
        .is_err()
    {
        return PaidOutcome::Reject(X402Error::ChallengeNotIssued);
    }

    // 3. Price check — caller must have authorized at least what
    // this request costs.
    if payload.value < price {
        return PaidOutcome::Reject(X402Error::Internal(format!(
            "authorized amount {} wei below price {} wei",
            payload.value, price
        )));
    }

    // 4. Verify signature via precompile 0x0201. Input = domain(32)
    // || payload_bytes(233) = 265 bytes.
    let domain = wsalt_domain_separator(config.chain_id, config.wsalt_address);
    let mut precompile_input = Vec::with_capacity(32 + crate::types::PAYLOAD_BYTES);
    precompile_input.extend_from_slice(domain.as_bytes());
    precompile_input.extend_from_slice(&payload.to_bytes());
    let signer = match config.chain.verify_offline(&precompile_input).await {
        Ok(Some(addr)) => addr,
        Ok(None) => return PaidOutcome::Reject(X402Error::InvalidSignature),
        Err(e) => return PaidOutcome::ServerError(e),
    };
    if signer != payload.from {
        return PaidOutcome::Reject(X402Error::InvalidSignature);
    }

    // RM-B1 / WP-D2.3 (audit F-1): treasury bind. Pre-fix the
    // gateway accepted any well-signed payload, regardless of who
    // the payer authorized as the recipient. An attacker could
    // re-broadcast a valid signature originally addressed to a
    // different gateway's treasury — the operator would settle it
    // on-chain under THIS gateway's facilitator, the funds would
    // land at the attacker-chosen recipient, and the gateway would
    // unlock paid service for the attacker free of charge.
    // Post-fix the recipient is bound to this gateway's configured
    // treasury; cross-gateway replay returns 402.
    if payload.to != config.treasury {
        return PaidOutcome::Reject(X402Error::RecipientNotTreasury);
    }

    // 5. Build settlement calldata + get operator nonce.
    let calldata = encode_settle_payment(&payload);
    let op_nonce = match config.chain.get_nonce(config.operator_address).await {
        Ok(n) => n,
        Err(e) => return PaidOutcome::ServerError(e),
    };

    // 6. Sign + submit.
    let tx = crate::sign_tx::SettlementTx {
        chain_id: config.chain_id,
        nonce: op_nonce,
        gas_price_wei: config.gas_price_wei,
        gas_limit: config.gas_limit,
        to: config.facilitator_address,
        value: ethereum_types::U256::zero(),
        data: &calldata,
    };
    let signed = match crate::sign_tx::sign_settlement_tx(tx, &config.operator_secret) {
        Ok(s) => s,
        Err(e) => return PaidOutcome::ServerError(e),
    };
    let tx_hash = match config.chain.send_raw_tx(&signed.raw).await {
        Ok(h) => h,
        Err(e) => return PaidOutcome::ServerError(e),
    };

    // 7. Wait for receipt.
    let receipt = match config
        .chain
        .wait_for_receipt(tx_hash, Duration::from_secs(config.receipt_timeout_secs))
        .await
    {
        Ok(r) => r,
        Err(e) => return PaidOutcome::ServerError(e),
    };

    if !receipt.status {
        // Most common revert: wSALT sees the nonce already used.
        // We can't easily distinguish replay from other reverts at
        // this layer without fetching the revert reason, so surface
        // "nonce replayed" as the most likely cause. A future
        // enhancement can decode the revert data.
        return PaidOutcome::Reject(X402Error::NonceReplayed);
    }

    // 8. Extract the PaymentSettled event.
    let settled = match find_payment_settled(&receipt, config.facilitator_address) {
        Some(ev) => ev,
        None => {
            return PaidOutcome::ServerError(X402Error::FacilitatorReverted(
                "no PaymentSettled event in receipt".into(),
            ))
        }
    };

    // 9. Attach X402Paid to request extensions.
    //
    // RM-B1 / WP-D2.4 (audit F-2): `amount_wei` carries the GROSS
    // amount the payer authorized (`net + fee`), not the recipient's
    // net share. Inner handlers comparing against pricing oracles
    // need the user-signed total — the fee is internal accounting.
    let gross = settled.value.saturating_add(settled.fee);
    req.extensions_mut().insert(X402Paid {
        payer: settled.from,
        amount_wei: gross,
        nonce: settled.nonce,
        settle_tx_hash: tx_hash,
    });

    let event = SettledEvent {
        payer: settled.from,
        amount_wei: settled.value,
        fee_wei: settled.fee,
        nonce: settled.nonce,
        tx_hash,
        block_number: receipt.block_number,
    };

    PaidOutcome::Forward(Box::new(req), event)
}

fn make_challenge(
    config: &X402Config,
    nonces: &NonceSource,
    amount_wei: U256,
) -> Result<crate::types::PaymentChallenge, X402Error> {
    let nonce = nonces.next_nonce();
    let now_unix = now_unix_secs();
    let built = build_challenge(ChallengeInputs {
        chain_id: config.chain_id,
        facilitator: config.facilitator_address,
        wsalt: config.wsalt_address,
        recipient: config.treasury,
        amount_wei,
        payer: H160::zero(),
        nonce,
        now_unix,
        ttl_secs: config.challenge_ttl_secs,
    })?;
    // Record in the issued-nonce ledger so the paid path can later
    // verify this challenge is ours, unexpired, and single-use.
    config
        .nonce_ledger
        .record(nonce, now_unix + config.challenge_ttl_secs, now_unix);
    Ok(built.challenge)
}

fn build_error_response(err: X402Error) -> Response<Body> {
    let body = serde_json::json!({
        "error": "internal",
        "reason": err.reason(),
        "detail": err.to_string(),
    })
    .to_string();
    Response::builder()
        .status(StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Build a 402 response with the challenge body. Per spec #1.
fn build_402_response(
    challenge: &crate::types::PaymentChallenge,
    reason: Option<&str>,
) -> Response<Body> {
    let mut body_map = serde_json::Map::new();
    body_map.insert(
        "x402".to_string(),
        serde_json::to_value(challenge).unwrap_or(serde_json::Value::Null),
    );
    if let Some(r) = reason {
        body_map.insert("reason".to_string(), serde_json::Value::String(r.to_string()));
    }
    let body = serde_json::Value::Object(body_map).to_string();

    Response::builder()
        .status(StatusCode::PAYMENT_REQUIRED)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn build_400_response(reason: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": "bad request", "reason": reason }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn build_500_response(reason: &str) -> Response<Body> {
    let body = serde_json::json!({ "error": "internal", "reason": reason }).to_string();
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// (build_501_response removed in WP-02.3 — paid path now fully
// wired via run_paid_path; header-present requests take the real
// verify+settle path rather than returning a placeholder.)

fn parse_addr(addr: &str) -> Option<H160> {
    let s = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Some(H160::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pricing::FixedPricing;

    fn any_addr() -> &'static str {
        "0x8951ae72e5479cae28ef7bb3caa4207d5719e24b"
    }

    /// Deterministic test secret. Known-valid scalar for secp256k1.
    /// Same value used in sign_tx::tests. NOT a real operator key.
    fn test_secret_hex() -> &'static str {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    }

    fn full_builder() -> X402LayerBuilder {
        X402Layer::builder()
            .chain_id(40204)
            .facilitator_address(any_addr())
            .wsalt_address(any_addr())
            .treasury(any_addr())
            .rpc_url("http://127.0.0.1:18545")
            .pricing(FixedPricing::new("1000000000000000000"))
            .operator_secret_hex(test_secret_hex())
    }

    #[test]
    fn builder_requires_all_fields() {
        let err = X402Layer::builder().build().expect_err("empty builder");
        assert!(matches!(err, X402Error::Internal(_)));
    }

    #[test]
    fn builder_succeeds_with_full_config() {
        let layer = full_builder().build().expect("build ok");
        assert_eq!(layer.config.chain_id, 40204);
        assert_eq!(layer.config.challenge_ttl_secs, 300);
        assert_eq!(layer.config.receipt_timeout_secs, 10);
        // Operator address derived from the test secret; non-zero.
        assert_ne!(layer.config.operator_address, H160::zero());
    }

    #[test]
    fn builder_applies_optional_overrides() {
        let layer = full_builder()
            .challenge_ttl_secs(60)
            .receipt_timeout_secs(30)
            .gas_price_wei(5_000_000_000)
            .gas_limit(500_000)
            .build()
            .expect("build ok");
        assert_eq!(layer.config.challenge_ttl_secs, 60);
        assert_eq!(layer.config.receipt_timeout_secs, 30);
        assert_eq!(layer.config.gas_price_wei, 5_000_000_000);
        assert_eq!(layer.config.gas_limit, 500_000);
    }

    #[test]
    fn builder_rejects_malformed_address() {
        let err = X402Layer::builder()
            .chain_id(40204)
            .facilitator_address("not-hex")
            .wsalt_address(any_addr())
            .treasury(any_addr())
            .rpc_url("http://127.0.0.1:18545")
            .pricing(FixedPricing::new("1"))
            .operator_secret_hex(test_secret_hex())
            .build()
            .expect_err("should fail");
        // parse_addr returned None; builder reports missing.
        assert!(matches!(err, X402Error::Internal(m) if m.contains("facilitator_address")));
    }

    #[test]
    fn builder_rejects_missing_operator_secret() {
        let err = X402Layer::builder()
            .chain_id(40204)
            .facilitator_address(any_addr())
            .wsalt_address(any_addr())
            .treasury(any_addr())
            .rpc_url("http://127.0.0.1:18545")
            .pricing(FixedPricing::new("1"))
            .build()
            .expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(m) if m.contains("operator_secret")));
    }

    #[test]
    fn builder_rejects_all_zeros_operator_secret() {
        let err = X402Layer::builder()
            .chain_id(40204)
            .facilitator_address(any_addr())
            .wsalt_address(any_addr())
            .treasury(any_addr())
            .rpc_url("http://127.0.0.1:18545")
            .pricing(FixedPricing::new("1"))
            .operator_secret_bytes([0u8; 32])
            .build()
            .expect_err("should fail");
        assert!(matches!(err, X402Error::Internal(m) if m.contains("operator_secret")));
    }
}
