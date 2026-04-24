//! Provider selection + dispatch.
//!
//! Two halves:
//!
//! 1. **Selection** — given a list of `ProviderInfo`s for a model,
//!    pick the best one. Scoring: reputation_bps × capacity_remaining
//!    / 10000. Ties broken by lowest current_load. Providers at
//!    capacity (capacity_remaining == 0) are filtered out.
//!
//! 2. **Dispatch** — POST to `provider.endpoint/infer` with the
//!    Provider Protocol v1 payload. Times out at the configured
//!    deadline (default 60s). Returns the parsed response or a
//!    `GatewayError::ProviderUnavailable`.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::GatewayError;
use crate::queries::ProviderInfo;

/// Outbound payload to a provider's `/infer` endpoint.
/// The Provider Protocol v1 ADR (deferred to ADR-006 in CM-05)
/// will formalize this; the shape is locked here pending that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProtocolRequest {
    /// Model identifier (name or pinned hash).
    pub model: String,
    /// Plain-text prompt (concatenated chat messages for v1).
    pub prompt: String,
    /// Hard cap on output tokens.
    pub max_tokens: u32,
}

/// Inbound response shape from a provider's `/infer` endpoint.
#[derive(Debug, Deserialize)]
pub struct ProviderProtocolResponse {
    /// Generated text.
    pub output: String,
    /// Optional input-token count from the provider. Gateway falls
    /// back to whitespace-split if absent.
    #[serde(default)]
    pub input_tokens: Option<u32>,
    /// Optional output-token count from the provider. Gateway falls
    /// back to whitespace-split if absent.
    #[serde(default)]
    pub output_tokens: Option<u32>,
}

/// Pick the best provider from a candidate list, or `None` if no
/// provider has remaining capacity.
pub fn select_provider(candidates: &[ProviderInfo]) -> Option<&ProviderInfo> {
    candidates
        .iter()
        .filter(|p| p.capacity_remaining() > 0)
        .max_by_key(|p| {
            // score: reputation × capacity / 10000. Higher better.
            // Tie-break: lower current_load wins.
            let score = (p.reputation_bps as u64) * (p.capacity_remaining() as u64) / 10_000;
            (score, u32::MAX - p.current_load)
        })
}

/// Dispatch a chat request to a provider via HTTPS.
pub async fn dispatch_to_provider(
    http: &reqwest::Client,
    provider: &ProviderInfo,
    req: &ProviderProtocolRequest,
    timeout: Duration,
) -> Result<ProviderProtocolResponse, GatewayError> {
    let resp = http
        .post(&provider.endpoint)
        .json(req)
        .timeout(timeout)
        .send()
        .await
        .map_err(|e| GatewayError::ProviderUnavailable(format!("{}: {}", provider.endpoint, e)))?;
    if !resp.status().is_success() {
        return Err(GatewayError::ProviderUnavailable(format!(
            "{}: HTTP {}",
            provider.endpoint,
            resp.status()
        )));
    }
    resp.json::<ProviderProtocolResponse>()
        .await
        .map_err(|e| {
            GatewayError::ProviderUnavailable(format!(
                "{}: malformed response: {}",
                provider.endpoint, e
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::H160;

    fn p(rep: u32, load: u32, max: u32) -> ProviderInfo {
        ProviderInfo {
            address: H160::zero(),
            endpoint: format!("http://x-{}", rep),
            reputation_bps: rep,
            current_load: load,
            max_concurrent: max,
        }
    }

    #[test]
    fn picks_highest_reputation_when_capacities_equal() {
        let pool = vec![p(8000, 0, 10), p(9500, 0, 10), p(5000, 0, 10)];
        let chosen = select_provider(&pool).expect("some");
        assert_eq!(chosen.reputation_bps, 9500);
    }

    #[test]
    fn excludes_at_capacity_providers() {
        let pool = vec![p(9500, 10, 10), p(8000, 0, 10)];
        let chosen = select_provider(&pool).expect("some");
        // 9500 is at capacity; must pick 8000.
        assert_eq!(chosen.reputation_bps, 8000);
    }

    #[test]
    fn returns_none_when_all_at_capacity() {
        let pool = vec![p(9500, 10, 10), p(8000, 5, 5)];
        assert!(select_provider(&pool).is_none());
    }

    #[test]
    fn returns_none_for_empty_pool() {
        assert!(select_provider(&[]).is_none());
    }

    #[test]
    fn tie_breaks_on_lower_load() {
        // Same rep and capacity remaining: prefer lower load.
        let pool = vec![p(9000, 5, 10), p(9000, 1, 6)];
        let chosen = select_provider(&pool).expect("some");
        // capacity_remaining: both = 5; reputation × cap = 4500; tie.
        // Lower load = 1.
        assert_eq!(chosen.current_load, 1);
    }
}
