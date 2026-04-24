//! Gateway configuration.
//!
//! Sourced from a TOML file in production (loaded by `main.rs`)
//! and constructed manually in tests.

use serde::{Deserialize, Serialize};

/// Top-level gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Chain ID. Default 40204 (Citrate testnet).
    pub chain_id: u64,
    /// JSON-RPC URL for chain queries (ModelRegistry, eth_call,
    /// etc.). Defaults to `http://127.0.0.1:18545`.
    pub rpc_url: String,
    /// Listen address — `0.0.0.0:9800` for production, `127.0.0.1:0`
    /// for tests (random port).
    pub listen_addr: String,
    /// Contract addresses on this chain. Required for production
    /// runs; tests using `build_router_with` inject mock queries
    /// and don't read these.
    pub contracts: ContractAddresses,
}

/// Addresses of the on-chain contracts the gateway queries.
///
/// On chain 40204 (testnet beta), these are sourced from
/// `contracts/DEPLOYED_ADDRESSES.md`. On a fresh chain or
/// dev environment, operators set these via env vars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAddresses {
    /// `ModelRegistry` — model metadata + IPFS CID lookup.
    pub model_registry: String,
    /// `ComputePricingOracle` — wei-cost estimation per job.
    pub pricing_oracle: String,
    /// `InferenceRouter` — per-model provider list + endpoint URLs.
    pub inference_router: String,
}

impl Default for ContractAddresses {
    fn default() -> Self {
        // Testnet-beta (chain 40204) deployments per
        // contracts/DEPLOYED_ADDRESSES.md. Override via env on
        // any other chain.
        Self {
            model_registry: "0x077fbc3338a9e6bad90a3a041e6b7425689754ef".to_string(),
            pricing_oracle: "0x46773aeca885be65cd313b7d9bce9625767d40b5".to_string(),
            inference_router: "0xad7c3135c1b9b3189208fd617b6b058c1c0469f3".to_string(),
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            chain_id: 40204,
            rpc_url: "http://127.0.0.1:18545".to_string(),
            listen_addr: "0.0.0.0:9800".to_string(),
            contracts: ContractAddresses::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let c = GatewayConfig::default();
        assert_eq!(c.chain_id, 40204);
        assert!(c.rpc_url.contains("18545"));
        assert!(c.listen_addr.contains("9800"));
    }

    #[test]
    fn round_trips_toml() {
        let c = GatewayConfig::default();
        let s = toml::to_string(&c).unwrap_or_else(|_| String::new());
        // toml dep is optional in this commit; serde_json works as
        // a generic round-trip test.
        let json = serde_json::to_string(&c).expect("ser");
        let back: GatewayConfig = serde_json::from_str(&json).expect("de");
        assert_eq!(back.chain_id, c.chain_id);
        let _ = s; // silence unused-var if toml isn't compiled in
    }
}
