//! `/v1/models` endpoint.
//!
//! Returns an OpenAI-compatible list of every active model the
//! gateway knows about, populated from two on-chain sources:
//!
//! 1. `ModelRegistry` — every individual model registered via
//!    `registerModel` (e.g. `gemma-4-E4B-it-Q4_K_M`). One entry per
//!    active model, with the human-readable on-chain name as the
//!    OpenAI `id` and the registrar EOA as `owned_by`.
//! 2. `ComputePool` (CM-05 WP-05.4) — pool entries that aggregate
//!    multiple member providers. One entry per pool, with `id`
//!    prefixed `"pool-"` so SDK callers can target them like any
//!    other model id.
//!
//! # Resilience
//!
//! If either chain query fails (RPC unreachable, decode failure)
//! that source degrades to an empty list rather than failing the
//! whole endpoint. `/v1/models` is the first thing SDK auto-
//! discovery code (`openai.models.list()`) calls; a 500 here breaks
//! SDK boot. Falling through to an empty (or partial) list is
//! honest and lets the SDK fail later at the actual endpoint with a
//! clearer error.

use axum::extract::State;
use axum::Json;
use ethereum_types::H256;
use serde::Serialize;

use crate::SharedState;

/// One entry in the `/v1/models` response.
#[derive(Debug, Serialize)]
pub struct ModelEntry {
    /// Stable model identifier (e.g. "gemma-4-E4B-it-Q4_K_M" or
    /// "pool-llama-70b"). What the OpenAI SDK sends back as the
    /// `model` field on subsequent requests.
    pub id: String,
    /// OpenAI shape requires this — always "model".
    pub object: &'static str,
    /// Owner address as a 0x-prefixed hex string. For individual
    /// models, the registrar EOA; for pools, a synthetic
    /// `pool:<id>` so the SDK has something to display.
    pub owned_by: String,
    /// Unix seconds. ModelRegistry doesn't expose `createdAt` via a
    /// view function today, so we fall back to "now" — informational
    /// only. Tracked as a follow-up to surface the real timestamp.
    pub created: u64,
}

/// Top-level `/v1/models` response.
#[derive(Debug, Serialize)]
pub struct ModelsResponse {
    /// OpenAI shape — always "list".
    pub object: &'static str,
    /// Active models known on this chain, individual + pools.
    pub data: Vec<ModelEntry>,
}

/// `GET /v1/models` handler.
///
/// Concatenates individual models (from `ModelRegistry`) with
/// `ComputePool` entries. Inactive models are filtered out; failed
/// chain queries degrade to an empty list per the resilience
/// contract at the top of this module.
pub async fn models_handler(State(state): State<SharedState>) -> Json<ModelsResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Source 1: individual models from ModelRegistry. Filter to
    // `isActive == true` so callers don't try to dispatch to a
    // deactivated model.
    let models = state.queries.list_models().await.unwrap_or_default();
    let mut data: Vec<ModelEntry> = models
        .into_iter()
        .filter(|m| m.is_active)
        .map(|m| ModelEntry {
            id: m.name,
            object: "model",
            owned_by: format!("0x{}", hex::encode(m.owner.as_bytes())),
            created: now,
        })
        .collect();

    // Source 2: ComputePool entries. `H256::zero()` asks for every
    // pool regardless of which model — the gateway's pool listing is
    // currently a catalogue, not a per-model filter.
    let pools = state
        .queries
        .list_pools(H256::zero())
        .await
        .unwrap_or_default();
    data.extend(pools.into_iter().map(|p| ModelEntry {
        id: format!("pool-{}", strip_pool_prefix(&p.name)),
        object: "model",
        owned_by: format!("pool:{}", p.pool_id),
        created: now,
    }));

    Json(ModelsResponse {
        object: "list",
        data,
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
            id: "gemma-4-E4B-it-Q4_K_M".into(),
            object: "model",
            owned_by: "0xabcd".into(),
            created: 1_714_000_000,
        };
        let s = serde_json::to_string(&e).expect("ser");
        assert!(s.contains(r#""id":"gemma-4-E4B-it-Q4_K_M""#));
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
