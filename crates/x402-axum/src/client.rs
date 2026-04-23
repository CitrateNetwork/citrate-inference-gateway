//! Client-side helper — scaffolding only (WP-02.1).
//!
//! The shape below is the public API WP-02.4 fills in. A caller wraps
//! a `reqwest::RequestBuilder` and the client auto-handles any 402
//! response by signing the authorization and retrying once.

use ethereum_types::{H160, U256};

use crate::error::X402Error;

/// Auto-paying HTTP client for x402-gated endpoints.
///
/// Composes with `reqwest` — pass a `RequestBuilder` to
/// [`send_paid`](X402Client::send_paid) and the client handles the
/// 402 challenge, signing, and retry. If the response is still 402
/// on the retry, the error bubbles to the caller.
///
/// Only supports secp256k1 signing keys. Ed25519 wallets surface as
/// [`X402Error::UnsupportedKeyType`] — EIP-3009 is ECDSA over
/// secp256k1 by definition.
pub struct X402Client {
    #[allow(dead_code)]
    pub(crate) config: ClientConfig,
}

#[allow(dead_code)]
pub(crate) struct ClientConfig {
    pub wsalt_address: H160,
    pub facilitator_address: H160,
    pub chain_id: u64,
    /// Hard cap on per-request amount the client will sign. Defaults
    /// to `10 SALT` (`10 * 10^18` wei). Prevents a bug in a server's
    /// pricing from draining the client's wallet.
    pub budget_cap_wei: U256,
    // WP-02.4: will carry a citrate_wallet_core::UnifiedKey handle
    // and a reqwest::Client here. Omitted in the scaffold to keep
    // this crate compilable without a live keystore fixture.
}

impl X402Client {
    /// Create a client. See WP-02.4 for the real constructor that
    /// takes a signing key + wallet handle.
    pub fn new(
        wsalt_address: H160,
        facilitator_address: H160,
        chain_id: u64,
    ) -> Self {
        Self {
            config: ClientConfig {
                wsalt_address,
                facilitator_address,
                chain_id,
                // 10 SALT default.
                budget_cap_wei: U256::from(10u128) * U256::from(10u128).pow(18.into()),
            },
        }
    }

    /// Set a per-request budget cap (wei). If a server challenges
    /// above this, the client returns [`X402Error::BudgetExceeded`]
    /// without producing a signature.
    pub fn with_budget_cap(mut self, cap_wei: U256) -> Self {
        self.config.budget_cap_wei = cap_wei;
        self
    }

    /// Send a request, auto-handling any 402 response. WP-02.4 fills
    /// the implementation.
    pub async fn send_paid(
        &self,
        _req: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, X402Error> {
        todo!("WP-02.4: challenge parse, sign via wallet, retry with X-PAYMENT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any_addr() -> H160 {
        let mut out = [0u8; 20];
        out[0] = 0x42;
        H160::from(out)
    }

    #[test]
    fn client_default_budget_cap_is_ten_salt() {
        let c = X402Client::new(any_addr(), any_addr(), 40204);
        assert_eq!(
            c.config.budget_cap_wei,
            U256::from(10u128) * U256::from(10u128).pow(18.into())
        );
    }

    #[test]
    fn with_budget_cap_overrides() {
        let c = X402Client::new(any_addr(), any_addr(), 40204)
            .with_budget_cap(U256::from(42u128));
        assert_eq!(c.config.budget_cap_wei, U256::from(42u128));
    }
}
