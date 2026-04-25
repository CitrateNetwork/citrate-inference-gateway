//! `/v1/models` endpoint.
//!
//! Queries `ModelRegistry.listModels()` via `eth_call` and returns
//! an OpenAI-compatible model list.
//!
//! # Resilience
//!
//! If the chain RPC is unreachable or the contract call returns
//! garbage, we degrade to an empty list rather than 500. Reasoning:
//! `/v1/models` is hit by SDK auto-discovery code (e.g.
//! `openai.models.list()`); a 500 there breaks SDK boot. An empty
//! list is honest ("no models available right now") and lets the
//! SDK fail later at the actual endpoint with a clearer error.
//!
//! # Data source
//!
//! `ModelRegistry.listModels()` — Solidity address per chain in
//! `gui/citrate_gui_native/src/marketplace_client.rs::known_contract`.
//! For the gateway we'll port that address-book lookup in a future
//! WP; for WP-03.1 we just stub the empty list and prove the shape.

use axum::extract::State;
use axum::Json;
use ethereum_types::H256;
use serde::Serialize;

use crate::SharedState;

/// One entry in the `/v1/models` response.
#[derive(Debug, Serialize)]
pub struct ModelEntry {
    /// Stable model identifier (e.g. "llama-3.1-8b").
    pub id: String,
    /// OpenAI shape required this — always "model".
    pub object: &'static str,
    /// Address that owns the model (creator).
    pub owned_by: String,
    /// Unix seconds when the model was registered on-chain.
    pub created: u64,
}

/// Top-level `/v1/models` response.
#[derive(Debug, Serialize)]
pub struct ModelsResponse {
    /// OpenAI shape — always "list".
    pub object: &'static str,
    /// Models known on this chain.
    pub data: Vec<ModelEntry>,
}

/// `GET /v1/models` handler.
///
/// Lists individual provider-backed models AND ComputePool entries.
/// Pool entries appear with `id` prefixed by `"pool-"` so SDK
/// callers can target them like any other model id (CM-05 WP-05.4).
/// Falls through to an empty list on any chain failure — see the
/// resilience note at the top of this module.
pub async fn models_handler(
    State(state): State<SharedState>,
) -> Json<ModelsResponse> {
    let _ = &state.config;
    let _ = &state.http;

    // The on-chain ModelRegistry doesn't expose a name→hash listing
    // yet, so individual-model discovery from this endpoint is
    // empty pending an off-chain index (or a slice-2 ABI extension).
    // Pools, however, we can list directly via list_pools — the
    // pool's name is its display id.
    let pools = state
        .queries
        .list_pools(H256::zero())
        .await
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pool_entries: Vec<ModelEntry> = pools
        .into_iter()
        .map(|p| ModelEntry {
            id: format!("pool-{}", strip_pool_prefix(&p.name)),
            object: "model",
            owned_by: format!("pool:{}", p.pool_id),
            created: now,
        })
        .collect();
    Json(ModelsResponse {
        object: "list",
        data: pool_entries,
    })
}

/// `pool-llama-70b` → `llama-70b` (avoid the double-prefix
/// `pool-pool-llama-70b`).
fn strip_pool_prefix(name: &str) -> &str {
    name.strip_prefix("pool-").unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_entry_serializes_with_openai_fields() {
        let e = ModelEntry {
            id: "llama-3.1-8b".into(),
            object: "model",
            owned_by: "0xabcd".into(),
            created: 1_714_000_000,
        };
        let s = serde_json::to_string(&e).expect("ser");
        // Required OpenAI fields present.
        assert!(s.contains(r#""id":"llama-3.1-8b""#));
        assert!(s.contains(r#""object":"model""#));
        assert!(s.contains(r#""owned_by":"0xabcd""#));
        assert!(s.contains(r#""created":1714000000"#));
    }

    #[test]
    fn empty_list_response_shape() {
        let r = ModelsResponse {
            object: "list",
            data: vec![],
        };
        let s = serde_json::to_string(&r).expect("ser");
        assert_eq!(s, r#"{"object":"list","data":[]}"#);
    }
}
