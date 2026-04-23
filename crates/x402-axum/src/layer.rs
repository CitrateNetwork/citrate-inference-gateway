//! The `X402Layer` tower middleware.
//!
//! WP-02.2 wired the unpaid path — requests arriving without
//! `X-PAYMENT` return 402 with a fully-populated challenge body.
//! WP-02.3 will fill the paid path (verify + settle). Until then,
//! requests WITH a header get a 501 "payment verification pending
//! WP-02.3" response so the full wire shape is observable.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use tower::{Layer, Service};

use ethereum_types::H160;

use crate::challenge::{build_challenge, now_unix_secs, ChallengeInputs};
use crate::error::X402Error;
use crate::nonce::NonceSource;
use crate::pricing::PricingStrategy;

/// Fully-configured x402 middleware. Apply to any axum router via
/// `router.layer(layer)`. See crate-level docs for the integration
/// example.
#[derive(Clone)]
pub struct X402Layer {
    pub(crate) config: Arc<X402Config>,
    pub(crate) nonces: Arc<NonceSource>,
}

/// Internal configuration shared across the tower service.
///
/// `dead_code` allowed during WP-02 scaffolding — fields not yet
/// referenced become live at WP-02.3 (rpc_url, facilitator_address,
/// treasury, receipt_timeout_secs).
#[allow(dead_code)]
pub(crate) struct X402Config {
    /// Chain ID — `40204` for Citrate testnet.
    pub chain_id: u64,
    /// `X402Facilitator` contract address on this chain.
    pub facilitator_address: H160,
    /// `WrappedSALT` contract address on this chain.
    pub wsalt_address: H160,
    /// Where the facilitator routes net payment after fees.
    pub treasury: H160,
    /// JSON-RPC endpoint for on-chain settlement. Typically the
    /// service operator's own node.
    pub rpc_url: String,
    /// Pricing strategy — pluggable per deployment.
    pub pricing: Arc<dyn PricingStrategy>,
    /// How long challenges remain valid. Default 300 seconds.
    pub challenge_ttl_secs: u64,
    /// Receipt polling ceiling — after this, settle is reported as
    /// pending (scenario 9 in x402_payment.feature).
    pub receipt_timeout_secs: u64,
}

impl std::fmt::Debug for X402Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402Config")
            .field("chain_id", &self.chain_id)
            .field("facilitator_address", &self.facilitator_address)
            .field("wsalt_address", &self.wsalt_address)
            .field("treasury", &self.treasury)
            .field("rpc_url", &self.rpc_url)
            .field("challenge_ttl_secs", &self.challenge_ttl_secs)
            .field("receipt_timeout_secs", &self.receipt_timeout_secs)
            .finish()
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

/// Builder for [`X402Layer`]. All fields are required; calling
/// [`build`](X402LayerBuilder::build) without one returns
/// [`X402Error::Internal`].
#[derive(Default)]
pub struct X402LayerBuilder {
    chain_id: Option<u64>,
    facilitator_address: Option<H160>,
    wsalt_address: Option<H160>,
    treasury: Option<H160>,
    rpc_url: Option<String>,
    pricing: Option<Arc<dyn PricingStrategy>>,
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

        Ok(X402Layer {
            config: Arc::new(X402Config {
                chain_id,
                facilitator_address,
                wsalt_address,
                treasury,
                rpc_url,
                pricing,
                challenge_ttl_secs: self.challenge_ttl_secs.unwrap_or(300),
                receipt_timeout_secs: self.receipt_timeout_secs.unwrap_or(10),
            }),
            nonces: Arc::new(NonceSource::new()),
        })
    }
}

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
        // Prepare a ready-to-go inner service (see the tower docs'
        // buffering pattern — swapping inner keeps the service
        // correct-by-construction w.r.t. ownership).
        let inner_ready = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, inner_ready);

        Box::pin(async move {
            // WP-02.3: parse X-PAYMENT, verify, settle. For now, any
            // header at all gets 501 with a clear reason so integration
            // tests observe the shape.
            if req.headers().get("x-payment").is_some() {
                return Ok(build_501_response());
            }

            // Price the request first — 400 on unpriceable, 402 on
            // valid-but-expensive.
            let price = match config.pricing.price_for(&req).await {
                Ok(p) => p,
                Err(e) => return Ok(build_400_response(&e.to_string())),
            };

            // Choose a payer identity to embed in the challenge.
            // v1 convention: use the zero address as "unknown payer"
            // — the client fills in its real address when signing.
            // On-chain, WrappedSALT will recover the *actual* signer
            // from ECDSA recovery; the `from` field in the EIP-3009
            // payload MUST match that recovered address, so the
            // zero-address placeholder is simply overwritten during
            // sign. (If we ever want to bind a challenge to a
            // specific known payer — e.g. for API-key backed
            // accounts — the pricing strategy can return that
            // binding. Deferred.)
            let payer = H160::zero();

            let nonce = nonces.next_nonce();
            let built = match build_challenge(ChallengeInputs {
                chain_id: config.chain_id,
                facilitator: config.facilitator_address,
                wsalt: config.wsalt_address,
                recipient: config.treasury,
                amount_wei: price,
                payer,
                nonce,
                now_unix: now_unix_secs(),
                ttl_secs: config.challenge_ttl_secs,
            }) {
                Ok(b) => b,
                Err(e) => return Ok(build_500_response(&e.to_string())),
            };

            // `inner` is captured because the S: Clone bound requires
            // it for the eventual WP-02.3 paid path; on the 402 path
            // we drop it explicitly rather than forward.
            drop(inner);
            Ok(build_402_response(&built.challenge, None))
        })
    }
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

fn build_501_response() -> Response<Body> {
    // WP-02.3 fills this — returns a clear placeholder so integration
    // tests and curl users can observe the shape without silent
    // 500s.
    let body = serde_json::json!({
        "error": "not implemented",
        "reason": "payment verification pending WP-02.3",
    })
    .to_string();
    Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

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

    #[test]
    fn builder_requires_all_fields() {
        let err = X402Layer::builder().build().expect_err("empty builder");
        assert!(matches!(err, X402Error::Internal(_)));
    }

    #[test]
    fn builder_succeeds_with_full_config() {
        let layer = X402Layer::builder()
            .chain_id(40204)
            .facilitator_address(any_addr())
            .wsalt_address(any_addr())
            .treasury(any_addr())
            .rpc_url("http://127.0.0.1:18545")
            .pricing(FixedPricing::new("1000000000000000000"))
            .build()
            .expect("build ok");
        assert_eq!(layer.config.chain_id, 40204);
        assert_eq!(layer.config.challenge_ttl_secs, 300);
        assert_eq!(layer.config.receipt_timeout_secs, 10);
    }

    #[test]
    fn builder_applies_optional_overrides() {
        let layer = X402Layer::builder()
            .chain_id(40204)
            .facilitator_address(any_addr())
            .wsalt_address(any_addr())
            .treasury(any_addr())
            .rpc_url("http://127.0.0.1:18545")
            .pricing(FixedPricing::new("1"))
            .challenge_ttl_secs(60)
            .receipt_timeout_secs(30)
            .build()
            .expect("build ok");
        assert_eq!(layer.config.challenge_ttl_secs, 60);
        assert_eq!(layer.config.receipt_timeout_secs, 30);
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
            .build()
            .expect_err("should fail");
        // parse_addr returned None; builder reports missing
        assert!(matches!(err, X402Error::Internal(m) if m.contains("facilitator_address")));
    }
}
