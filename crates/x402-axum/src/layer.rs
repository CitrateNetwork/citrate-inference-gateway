//! The `X402Layer` tower middleware — scaffolding only (WP-02.1).
//!
//! WP-02.2 fills the challenge generator. WP-02.3 fills verify + settle.
//! WP-02.5 wires observability. Until those land, [`X402Layer::new`]
//! only validates the builder config; there is no request path yet.

use std::sync::Arc;

use ethereum_types::H160;

use crate::error::X402Error;
use crate::pricing::PricingStrategy;

/// Fully-configured x402 middleware. Apply to any axum router via
/// `router.layer(layer)`. See crate-level docs for the integration
/// example.
#[derive(Clone)]
pub struct X402Layer {
    pub(crate) config: Arc<X402Config>,
}

/// Internal configuration shared across the tower service.
///
/// `dead_code` allowed during WP-02.1 scaffolding — fields are
/// consumed by WP-02.2 (pricing, challenge_ttl_secs),
/// WP-02.3 (facilitator_address, wsalt_address, treasury, rpc_url,
/// receipt_timeout_secs, chain_id). Remove the attribute once the
/// service body is implemented.
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
        })
    }
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
