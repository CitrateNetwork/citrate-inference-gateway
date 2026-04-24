//! Per-API-key usage accounting (WP-03.5).
//!
//! Slice 1: in-memory aggregation by `(key_id, date_yyyy_mm_dd)`.
//! Emitted on every successful chat completion that traveled through
//! the API-key auth path — i.e. the caller presented a funded Bearer
//! key. Anonymous x402 requests are not tracked here (no key = no
//! row).
//!
//! `GET /v1/usage` requires `Authorization: Bearer <key>` and reports
//! ONLY the caller's own aggregate + daily breakdown. SALT spend is
//! surfaced in both raw grains (U256 string) and human-readable form
//! (`"X.Y SALT"` via [`citrate_wallet_core::format::grains_str_to_salt_display`]).
//!
//! RocksDB persistence is slice 2.
//!
//! Specs: `citrate_v0.01.1/specs/gherkin/gateway_usage.feature`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ethereum_types::U256;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::SharedState;

/// Marker attached to request extensions by `ApiKeyLayer` so
/// downstream handlers can emit usage bound to the right key.
#[derive(Debug, Clone)]
pub struct ApiKeyContext {
    /// Opaque key id (the part after `Bearer `).
    pub key_id: String,
    /// CM-06 WP-06.5 — the unit of `paid.amount_wei` for usage
    /// accounting. `Salt` means grains-of-SALT; `Credits` means
    /// PFLOP-hour credits debited from BulkComputeGateway. Usage
    /// rows record the value as-is; the display layer formats based
    /// on this hint.
    pub backing: crate::auth::KeyBacking,
}

/// One row's worth of per-day aggregate.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UsageRow {
    /// YYYY-MM-DD UTC.
    pub date: String,
    /// Successful requests counted on this day.
    pub requests: u64,
    /// Sum of provider-reported input tokens.
    pub input_tokens: u64,
    /// Sum of provider-reported output tokens.
    pub output_tokens: u64,
    /// Raw grains spent (stringified U256 for JSON fidelity).
    pub salt_spent_grains: String,
}

/// In-memory usage store keyed by `(key_id, date)`.
///
/// Daily rows are kept indefinitely in slice 1; the `/v1/usage`
/// handler returns all rows for the caller's key. A TTL / 30-day
/// pruning policy lands with the slice-2 RocksDB migration.
#[derive(Default, Debug)]
pub struct UsageStore {
    // The inner value tracks everything as native types so we don't
    // re-parse on every mutation; serialization happens on read.
    rows: RwLock<HashMap<(String, String), RawRow>>,
}

#[derive(Debug, Default, Clone)]
struct RawRow {
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    salt_spent_grains: U256,
}

impl UsageStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful request. Atomic: one write lock covers
    /// the read-modify-write so concurrent emitters don't clobber.
    pub async fn record(
        &self,
        key_id: &str,
        input_tokens: u32,
        output_tokens: u32,
        grains: U256,
    ) {
        let date = today_utc_yyyy_mm_dd();
        let mut guard = self.rows.write().await;
        let row = guard
            .entry((key_id.to_string(), date))
            .or_insert_with(RawRow::default);
        row.requests += 1;
        row.input_tokens += u64::from(input_tokens);
        row.output_tokens += u64::from(output_tokens);
        row.salt_spent_grains += grains;
    }

    /// Gather all rows for a key, newest first.
    pub async fn rows_for(&self, key_id: &str) -> Vec<UsageRow> {
        let guard = self.rows.read().await;
        let mut rows: Vec<UsageRow> = guard
            .iter()
            .filter(|((k, _), _)| k == key_id)
            .map(|((_, date), row)| UsageRow {
                date: date.clone(),
                requests: row.requests,
                input_tokens: row.input_tokens,
                output_tokens: row.output_tokens,
                salt_spent_grains: row.salt_spent_grains.to_string(),
            })
            .collect();
        // Sort newest → oldest for a stable presentation.
        rows.sort_by(|a, b| b.date.cmp(&a.date));
        rows
    }
}

/// Response shape for `GET /v1/usage`.
#[derive(Debug, Serialize)]
pub struct UsageResponse {
    /// Sum across all daily rows.
    pub total_requests: u64,
    /// Aggregate input token count.
    pub total_input_tokens: u64,
    /// Aggregate output token count.
    pub total_output_tokens: u64,
    /// Total SALT spent, in raw grains (stringified U256).
    pub salt_spent_grains: String,
    /// Human-readable SALT amount, e.g. `"3.0 SALT"`.
    pub salt_spent_display: String,
    /// Per-day breakdown, newest first.
    pub daily: Vec<UsageRow>,
}

/// `GET /v1/usage` — returns the caller's aggregate + daily breakdown.
///
/// Requires `Authorization: Bearer <key>`. Unknown / revoked keys get
/// 401. Unlike the x402-protected endpoints, this one does NOT fall
/// through to an x402 challenge on missing auth — usage data is a
/// per-identity resource and identity is proven only by the key.
pub async fn usage_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Response {
    let Some(key_id) = extract_bearer(&headers) else {
        return error(
            StatusCode::UNAUTHORIZED,
            "Authorization: Bearer <key> required",
        );
    };

    // Validate the key exists + isn't revoked. We could in principle
    // return usage for a revoked key (historical data), but gating on
    // revocation makes the contract simple: once revoked, no access.
    match state.keys.get(&key_id).await {
        None => return error(StatusCode::UNAUTHORIZED, "unknown api key"),
        Some(r) if r.revoked => {
            return error(StatusCode::UNAUTHORIZED, "api key revoked")
        }
        Some(_) => {}
    }

    let daily = state.usage.rows_for(&key_id).await;
    let total_requests: u64 = daily.iter().map(|r| r.requests).sum();
    let total_input: u64 = daily.iter().map(|r| r.input_tokens).sum();
    let total_output: u64 = daily.iter().map(|r| r.output_tokens).sum();
    // Re-sum grains as U256 to avoid u128 overflow risk at scale.
    let salt_total: U256 = daily.iter().fold(U256::zero(), |acc, r| {
        acc + U256::from_dec_str(&r.salt_spent_grains).unwrap_or(U256::zero())
    });
    let grains_str = salt_total.to_string();
    let display = citrate_wallet_core::format::grains_str_to_salt_display(&grains_str);

    Json(UsageResponse {
        total_requests,
        total_input_tokens: total_input,
        total_output_tokens: total_output,
        salt_spent_grains: grains_str,
        salt_spent_display: display,
        daily,
    })
    .into_response()
}

fn error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "error": { "message": msg } }).to_string(),
    )
        .into_response()
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// UTC date as `YYYY-MM-DD`. Local time zones create cross-day
/// accounting drift — usage is always UTC-bucketed.
fn today_utc_yyyy_mm_dd() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil date arithmetic without chrono — the gateway already
    // avoids a chrono dep. Good enough for a YYYY-MM-DD bucket.
    civil_date(secs)
}

/// Convert Unix epoch seconds → "YYYY-MM-DD" (UTC). Handles leap
/// years. Based on Howard Hinnant's `civil_from_days` algorithm.
fn civil_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    // Days since 1970-01-01 → (year, month, day) in proleptic
    // Gregorian. Algorithm valid for any year ≥ -32767.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", year, m, d)
}

/// Convenience alias consumed by handlers + lib wiring.
pub type SharedUsage = Arc<UsageStore>;


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_then_read_back() {
        let store = UsageStore::new();
        store
            .record("k1", 7, 13, U256::from(1_000_000_000_000_000_000u128))
            .await;
        store
            .record("k1", 7, 13, U256::from(1_000_000_000_000_000_000u128))
            .await;
        let rows = store.rows_for("k1").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requests, 2);
        assert_eq!(rows[0].input_tokens, 14);
        assert_eq!(rows[0].output_tokens, 26);
        assert_eq!(
            U256::from_dec_str(&rows[0].salt_spent_grains).expect("u256"),
            U256::from(2_000_000_000_000_000_000u128)
        );
    }

    #[tokio::test]
    async fn rows_are_isolated_per_key() {
        let store = UsageStore::new();
        store.record("a", 1, 1, U256::from(1u64)).await;
        store.record("b", 2, 2, U256::from(2u64)).await;
        assert_eq!(store.rows_for("a").await[0].requests, 1);
        assert_eq!(store.rows_for("b").await[0].requests, 1);
    }

    #[test]
    fn civil_date_epoch_is_1970_01_01() {
        assert_eq!(civil_date(0), "1970-01-01");
    }

    #[test]
    fn civil_date_handles_leap_day() {
        // 2024-02-29 00:00 UTC → 1709164800 seconds
        assert_eq!(civil_date(1_709_164_800), "2024-02-29");
    }

    #[test]
    fn civil_date_handles_y2k() {
        // 2000-01-01 00:00 UTC → 946684800
        assert_eq!(civil_date(946_684_800), "2000-01-01");
    }
}
