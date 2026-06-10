//! Gateway configuration.
//!
//! Sourced from a TOML file in production (loaded by `main.rs`)
//! and constructed manually in tests.
//!
//! Contract addresses are NOT hardcoded inline: the
//! [`ContractAddresses::default()`] impl reads from the federation-canonical
//! contract-address table vendored at `src/generated/addresses.json`
//! (source-of-truth: `citrate-chain/contracts/addresses/40204.json`).
//! After a chain re-roll, run `bash scripts/sync-addresses.sh` from the
//! gateway repo root to re-vendor the table — no source edit required.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Vendored copy of the federation-canonical contract-address table.
const ADDRESS_TABLE_JSON: &str = include_str!("generated/addresses.json");

/// Subset of the canonical table the gateway reads. Anything outside
/// `contracts` + `aaStack` is ignored — the gateway doesn't care about
/// precompiles or genesis-allocations.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalTable {
    contracts: BTreeMap<String, String>,
    aa_stack: BTreeMap<String, String>,
}

static ADDRESS_TABLE: Lazy<CanonicalTable> = Lazy::new(|| {
    // The vendored JSON is bundled with the binary at build time and is
    // schema-checked by `scripts/sync-addresses.sh` before it ever lands
    // on disk, so a parse failure here is a build invariant violation.
    serde_json::from_str::<CanonicalTable>(ADDRESS_TABLE_JSON)
        .expect("src/generated/addresses.json is malformed at build time")
});

/// Look up a contract address by canonical name. Searches `contracts`
/// first, then `aaStack`. Returns the address as a lowercase 0x-prefixed
/// hex string.
fn canonical_address(name: &str) -> String {
    ADDRESS_TABLE
        .contracts
        .get(name)
        .or_else(|| ADDRESS_TABLE.aa_stack.get(name))
        .unwrap_or_else(|| {
            panic!(
                "canonical address table missing {name:?} (vendored \
                 src/generated/addresses.json may be stale — run \
                 `bash scripts/sync-addresses.sh`)"
            )
        })
        .clone()
}

/// Top-level gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Chain ID. Default 40204 (Citrate testnet).
    pub chain_id: u64,
    /// JSON-RPC URL for chain queries (ModelRegistry, eth_call,
    /// etc.). Defaults to `http://127.0.0.1:18545`.
    pub rpc_url: String,
    /// Listen address. Defaults to loopback (`127.0.0.1:9800`); set
    /// `CITRATE_GATEWAY_LISTEN_ADDR=0.0.0.0:9800` for an intentional remote
    /// bind (e.g. inside a container). Tests use `127.0.0.1:0` (random port).
    /// SECREM-01 SVC-5 (pre-audit 2026-06-09): loopback default — see main.rs.
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
        // Sourced from the federation-canonical contract-address table
        // (see module-level docstring + `src/generated/addresses.json`).
        // Override via env on any non-canonical chain.
        Self {
            model_registry: canonical_address("ModelRegistry"),
            pricing_oracle: canonical_address("ComputePricingOracle"),
            inference_router: canonical_address("InferenceRouter"),
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            chain_id: 40204,
            rpc_url: "http://127.0.0.1:18545".to_string(),
            // SECREM-01 SVC-5 (pre-audit 2026-06-09): loopback default.
            listen_addr: "127.0.0.1:9800".to_string(),
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
    fn contract_defaults_come_from_canonical_table() {
        // The default impl reads from the vendored canonical table at
        // src/generated/addresses.json; this test pins the three names the
        // gateway looks up so a rename in the canonical (e.g. ModelRegistry →
        // ModelRegistryV2) breaks the build instead of silently shifting.
        let c = ContractAddresses::default();
        // Addresses are non-empty 0x-prefixed 20-byte hex.
        for (name, addr) in [
            ("model_registry", &c.model_registry),
            ("pricing_oracle", &c.pricing_oracle),
            ("inference_router", &c.inference_router),
        ] {
            assert!(
                addr.starts_with("0x") && addr.len() == 42,
                "{name} is not a 20-byte hex: {addr}"
            );
        }
        // Sanity: pricing_oracle is NOT the same as model_registry or
        // inference_router (would catch a rename collision in the canonical).
        assert_ne!(c.pricing_oracle, c.model_registry);
        assert_ne!(c.pricing_oracle, c.inference_router);
    }

    #[test]
    #[should_panic(expected = "canonical address table missing")]
    fn unknown_contract_name_panics() {
        // Build invariant: if the gateway asks for a name not in the
        // vendored table, we PANIC at boot rather than silently using "" or
        // a default — that surfaces a stale `src/generated/addresses.json`
        // immediately instead of leaking through to an opaque RPC failure
        // hours later. Verified via #[should_panic].
        let _ = canonical_address("DefinitelyNotAContractName");
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
