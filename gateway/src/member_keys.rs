//! Self-serve member keys (GW-AUTOKEY / WP-1).
//!
//! Lets any account signed in at `auth.citrate.ai` obtain a rate-limited
//! `cgk_` key for the local proxy without an operator running
//! `citrate-gateway-admin`. Mounted by
//! [`crate::local_proxy::build_local_proxy_router`] as
//! `POST /auth/member-key`; **off unless** [`MemberKeyConfig`] is supplied
//! via [`crate::local_proxy::LocalProxyState::with_member_keys`] (404
//! otherwise), so existing deployments are unchanged until ops enables it.
//!
//! # Flow
//!
//! 1. `Authorization: Bearer <IdP access token>` — the IdP's token, NOT a
//!    `cgk_` key. Missing → **401**.
//! 2. Shed per-IP floods before touching the IdP (**429**).
//! 3. Verify the token by calling the IdP userinfo endpoint. The gateway
//!    holds no IdP signing keys and no session state, so asking the IdP is
//!    the only verification that also honours IdP-side revocation.
//!    401/403 → **401**; anything else that isn't a 200 carrying a
//!    non-empty `sub` (5xx, timeout, garbage) → **503**. Never mint on IdP
//!    failure: an IdP outage must not turn into an open mint.
//! 4. Account = `hex(sha256(sub))[..16]`. The raw `sub` is never stored or
//!    logged; the label `member:<subhash>` is pseudonymous.
//! 5. Issuance limits, in memory (restart resets them — the persisted
//!    per-key daily quota and member pool are what bound real usage):
//!    ≤ 1 issuance / 60 s and ≤ 20 / UTC day per account; ≤ 30 / hour per
//!    client IP. Exceeded → **429** + `Retry-After`.
//! 6. Mint via [`PersistentKeyStore::rotate_member_key`], which revokes the
//!    account's previous key: one live key per account, so re-issuing is
//!    also how a member rotates a leaked key.
//! 7. **200** `{key, base_url, model, quota_rps, daily_requests}` with
//!    `Cache-Control: no-store`. The plaintext key appears only in this body.
//!
//! # Client IP
//!
//! The proxy is not served with `ConnectInfo` and in production only ever
//! sees Caddy on loopback, so the socket peer is useless. With
//! `trust_forwarded_for` the first `X-Forwarded-For` hop is used — correct
//! behind Caddy, which (without `trusted_proxies`) discards any client-sent
//! XFF and writes the real peer. Without it (or with an unparseable value)
//! every caller shares one `unknown` bucket: strict, but never spoofable.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use sha2::{Digest, Sha256};

use crate::local_proxy::LocalProxyState;

/// Default IdP userinfo endpoint.
pub const DEFAULT_USERINFO_URL: &str = "https://auth.citrate.ai/me";
/// Default `base_url` handed to members (what they point an OpenAI SDK at).
pub const DEFAULT_BASE_URL: &str = "https://infer.citrate.ai/v1";
/// Default `model` handed to members.
pub const DEFAULT_MODEL: &str = "citrate-gemma";
/// Default per-key requests/second for a member key.
pub const DEFAULT_MEMBER_RPS: u32 = 1;
/// Default per-key requests per UTC day for a member key.
pub const DEFAULT_MEMBER_DAILY: u64 = 300;
/// Default cap on requests per UTC day across ALL member keys (0 = off).
pub const DEFAULT_MEMBER_POOL_DAILY: u64 = 50_000;
/// Default in-flight requests per member key. Lower than the proxy-wide
/// [`crate::local_proxy::DEFAULT_MAX_CONCURRENT_PER_KEY`] because member keys
/// are free and numerous; a member needs a stream plus a follow-up, not 4.
pub const DEFAULT_MEMBER_MAX_CONCURRENT: usize = 2;

/// Cap on the userinfo response we will buffer. A userinfo document is a few
/// hundred bytes; anything bigger is not the IdP we expect.
const MAX_USERINFO_BODY: usize = 64 * 1024;
/// Shared bucket for callers whose IP we can't (or won't) trust.
const UNKNOWN_IP: &str = "unknown";
/// Prune limiter maps past this many entries (bounds memory under a flood
/// of distinct accounts / IPs; only stale windows are dropped).
const LIMITER_PRUNE_AT: usize = 10_000;

/// Operator configuration for member-key issuance. `Default` is the
/// production policy; `main.rs` overrides fields from env.
#[derive(Clone, Debug)]
pub struct MemberKeyConfig {
    /// IdP userinfo endpoint called with the member's bearer.
    pub userinfo_url: String,
    /// Timeout for the userinfo call.
    pub idp_timeout: Duration,
    /// Per-key requests/second for minted keys.
    pub quota_rps: u32,
    /// Per-key requests per UTC day for minted keys.
    pub daily_quota: u64,
    /// Requests per UTC day across all member keys; `0` disables the pool.
    pub pool_daily: u64,
    /// In-flight requests per member key (applied only to `member:` keys).
    pub max_concurrent: usize,
    /// `base_url` returned to the member.
    pub base_url: String,
    /// `model` returned to the member.
    pub model: String,
    /// Use the first `X-Forwarded-For` hop as the client IP (set only
    /// behind a proxy that overwrites XFF — see module docs).
    pub trust_forwarded_for: bool,
    /// Minimum spacing between issuances for one account.
    pub account_min_interval: Duration,
    /// Issuances per account per UTC day.
    pub account_daily_max: u32,
    /// Issuances per client IP per hour.
    pub ip_hourly_max: u32,
}

impl Default for MemberKeyConfig {
    fn default() -> Self {
        Self {
            userinfo_url: DEFAULT_USERINFO_URL.to_string(),
            idp_timeout: Duration::from_secs(5),
            quota_rps: DEFAULT_MEMBER_RPS,
            daily_quota: DEFAULT_MEMBER_DAILY,
            pool_daily: DEFAULT_MEMBER_POOL_DAILY,
            max_concurrent: DEFAULT_MEMBER_MAX_CONCURRENT,
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            trust_forwarded_for: false,
            account_min_interval: Duration::from_secs(60),
            account_daily_max: 20,
            ip_hourly_max: 30,
        }
    }
}

/// Unix-seconds clock. Injectable so tests can step past the 60 s window.
pub(crate) type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Runtime half of the feature: config + limiter + clock. Held in
/// [`LocalProxyState`] as `Option<Arc<_>>` — `None` is "feature off".
pub(crate) struct MemberKeys {
    pub(crate) cfg: MemberKeyConfig,
    limiter: parking_lot::Mutex<IssuanceLimiter>,
    pub(crate) clock: Clock,
}

impl MemberKeys {
    pub(crate) fn new(cfg: MemberKeyConfig) -> Self {
        Self {
            cfg,
            limiter: parking_lot::Mutex::new(IssuanceLimiter::default()),
            clock: Arc::new(system_clock),
        }
    }
}

#[derive(Clone, Copy)]
struct AccountWindow {
    last: u64,
    day: u64,
    count_today: u32,
}

#[derive(Clone, Copy)]
struct IpWindow {
    hour: u64,
    count: u32,
}

/// In-memory issuance windows (see module docs for why memory is enough).
#[derive(Default)]
struct IssuanceLimiter {
    accounts: HashMap<String, AccountWindow>,
    ips: HashMap<String, IpWindow>,
}

impl IssuanceLimiter {
    /// Seconds to wait if `ip` has used its hourly budget, else `None`.
    /// Read-only: used to shed floods before the IdP is called.
    fn ip_blocked(&self, ip: &str, now: u64, cfg: &MemberKeyConfig) -> Option<u64> {
        let hour = now / 3600;
        match self.ips.get(ip) {
            Some(w) if w.hour == hour && w.count >= cfg.ip_hourly_max => Some(3600 - now % 3600),
            _ => None,
        }
    }

    /// Check every issuance limit for (`account`, `ip`) and, if all pass,
    /// charge them — atomically, under the caller's lock, so concurrent
    /// issuances can't both slip under a limit. `Err(retry_after_secs)`.
    fn reserve(
        &mut self,
        account: &str,
        ip: &str,
        now: u64,
        cfg: &MemberKeyConfig,
    ) -> Result<(), u64> {
        let day = now / 86_400;
        let hour = now / 3600;
        if let Some(retry) = self.ip_blocked(ip, now, cfg) {
            return Err(retry);
        }
        if let Some(w) = self.accounts.get(account) {
            let min = cfg.account_min_interval.as_secs();
            let since = now.saturating_sub(w.last);
            if since < min {
                return Err(min - since);
            }
            if w.day == day && w.count_today >= cfg.account_daily_max {
                return Err(86_400 - now % 86_400);
            }
        }

        let acct = self
            .accounts
            .entry(account.to_string())
            .or_insert(AccountWindow {
                last: now,
                day,
                count_today: 0,
            });
        if acct.day != day {
            acct.day = day;
            acct.count_today = 0;
        }
        acct.last = now;
        acct.count_today = acct.count_today.saturating_add(1);

        let ipw = self
            .ips
            .entry(ip.to_string())
            .or_insert(IpWindow { hour, count: 0 });
        if ipw.hour != hour {
            ipw.hour = hour;
            ipw.count = 0;
        }
        ipw.count = ipw.count.saturating_add(1);

        self.prune(now, cfg);
        Ok(())
    }

    /// Drop windows that can no longer refuse anything.
    fn prune(&mut self, now: u64, cfg: &MemberKeyConfig) {
        let day = now / 86_400;
        let hour = now / 3600;
        let min = cfg.account_min_interval.as_secs();
        if self.accounts.len() > LIMITER_PRUNE_AT {
            self.accounts
                .retain(|_, w| w.day == day || now.saturating_sub(w.last) < min);
        }
        if self.ips.len() > LIMITER_PRUNE_AT {
            self.ips.retain(|_, w| w.hour == hour);
        }
    }
}

/// `hex(sha256(sub))[..16]` — the pseudonymous account id.
pub fn subject_hash(sub: &str) -> String {
    let digest = hex::encode(Sha256::digest(sub.as_bytes()));
    digest.chars().take(16).collect()
}

/// Client IP bucket for the issuance limiter (see module docs).
fn client_ip(headers: &HeaderMap, trust_forwarded_for: bool) -> String {
    if !trust_forwarded_for {
        return UNKNOWN_IP.to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|first| first.trim().parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| UNKNOWN_IP.to_string())
}

/// Why the IdP did not vouch for a token.
enum IdpVerdict {
    /// 200 with a non-empty `sub`.
    Subject(String),
    /// 401/403 — the token is bad; the member should sign in again.
    Rejected,
    /// Anything else — transport error, timeout, 5xx, malformed body.
    Unavailable,
}

/// Ask the IdP who this bearer belongs to. The token is sent only to the
/// configured userinfo URL and is never logged (errors are logged without
/// the request, and reqwest's error text never includes headers).
async fn verify_with_idp(http: &reqwest::Client, cfg: &MemberKeyConfig, token: &str) -> IdpVerdict {
    let resp = match http
        .get(&cfg.userinfo_url)
        .bearer_auth(token)
        .header(header::ACCEPT, "application/json")
        .timeout(cfg.idp_timeout)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e.without_url(), "member-key: IdP userinfo unreachable");
            return IdpVerdict::Unavailable;
        }
    };
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return IdpVerdict::Rejected;
    }
    if !status.is_success() {
        tracing::warn!(%status, "member-key: IdP userinfo error");
        return IdpVerdict::Unavailable;
    }
    let Some(body) = read_capped(resp, MAX_USERINFO_BODY).await else {
        tracing::warn!("member-key: IdP userinfo body unreadable or oversized");
        return IdpVerdict::Unavailable;
    };
    match serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("sub").and_then(|s| s.as_str()).map(str::to_owned))
    {
        Some(sub) if !sub.trim().is_empty() => IdpVerdict::Subject(sub),
        _ => {
            tracing::warn!("member-key: IdP userinfo carried no `sub`");
            IdpVerdict::Unavailable
        }
    }
}

/// Buffer at most `cap` bytes of a response body; `None` past the cap or on
/// a read error.
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if out.len() + chunk.len() > cap {
                    return None;
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => return Some(out),
            Err(_) => return None,
        }
    }
}

/// `POST /auth/member-key`. See the module docs for the full contract.
/// Never consumes any `cgk_` key's quota — it is not under `/v1/`.
pub(crate) async fn member_key_handler(
    State(state): State<LocalProxyState>,
    headers: HeaderMap,
) -> Response<Body> {
    let Some(mk) = state.member_keys.clone() else {
        return json_response(StatusCode::NOT_FOUND, error_body("unknown route"));
    };
    let Some(token) = bearer(&headers) else {
        return json_response(StatusCode::UNAUTHORIZED, error_body("missing bearer token"));
    };

    let ip = client_ip(&headers, mk.cfg.trust_forwarded_for);
    // Cheap pre-check so a flood from one IP never reaches the IdP.
    let blocked = mk.limiter.lock().ip_blocked(&ip, (mk.clock)(), &mk.cfg);
    if let Some(retry) = blocked {
        return too_many(retry, "too many key requests from this address");
    }

    let sub = match verify_with_idp(&state.http, &mk.cfg, &token).await {
        IdpVerdict::Subject(s) => s,
        IdpVerdict::Rejected => {
            return json_response(StatusCode::UNAUTHORIZED, error_body("invalid token"))
        }
        IdpVerdict::Unavailable => {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                error_body("identity provider unavailable"),
            )
        }
    };
    let subhash = subject_hash(&sub);

    // Charge the limits only once the IdP has vouched, so a bad token can't
    // burn a real member's account budget.
    let reserved = mk
        .limiter
        .lock()
        .reserve(&subhash, &ip, (mk.clock)(), &mk.cfg);
    if let Err(retry) = reserved {
        return too_many(retry, "key issuance rate limit exceeded");
    }

    let key = match state
        .store
        .rotate_member_key(&subhash, mk.cfg.quota_rps, mk.cfg.daily_quota)
    {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, member = %subhash, "member-key: mint failed");
            return json_response(StatusCode::INTERNAL_SERVER_ERROR, error_body("internal"));
        }
    };
    tracing::info!(member = %subhash, "member-key: issued");

    let body = serde_json::json!({
        "key": key,
        "base_url": mk.cfg.base_url,
        "model": mk.cfg.model,
        "quota_rps": mk.cfg.quota_rps,
        "daily_requests": mk.cfg.daily_quota,
    });
    json_response(StatusCode::OK, body)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": { "message": msg } })
}

/// Every response from this route is `no-store`: the success body carries a
/// live credential, and errors must not be cached in front of a retry.
fn json_response(code: StatusCode, body: serde_json::Value) -> Response<Body> {
    let mut r = Response::new(Body::from(body.to_string()));
    *r.status_mut() = code;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn too_many(retry_after_secs: u64, msg: &str) -> Response<Body> {
    let mut r = json_response(StatusCode::TOO_MANY_REQUESTS, error_body(msg));
    r.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from(retry_after_secs.max(1)),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_hash_is_16_hex_of_sha256() {
        let h = subject_hash("alice");
        assert_eq!(h.len(), 16);
        assert_eq!(h, hex::encode(Sha256::digest(b"alice"))[..16]);
        assert_ne!(subject_hash("alice"), subject_hash("bob"));
    }

    #[test]
    fn client_ip_trusts_xff_only_when_told_to() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&h, false), UNKNOWN_IP);
        assert_eq!(client_ip(&h, true), "203.0.113.7");
        h.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(&h, true), UNKNOWN_IP);
        assert_eq!(client_ip(&HeaderMap::new(), true), UNKNOWN_IP);
    }

    #[test]
    fn limiter_enforces_spacing_daily_and_ip_caps() {
        let cfg = MemberKeyConfig {
            account_daily_max: 2,
            ip_hourly_max: 3,
            ..MemberKeyConfig::default()
        };
        let mut l = IssuanceLimiter::default();
        let t0 = 86_400 * 1000; // start of a UTC day and an hour
        assert!(l.reserve("a", "ip", t0, &cfg).is_ok());
        // Within 60 s: refused with the remaining wait.
        assert_eq!(l.reserve("a", "ip", t0 + 10, &cfg), Err(50));
        assert!(l.reserve("a", "ip", t0 + 60, &cfg).is_ok());
        // Daily cap (2) reached: wait until UTC midnight.
        assert_eq!(l.reserve("a", "ip", t0 + 200, &cfg), Err(86_400 - 200));
        // Next UTC day resets the account.
        assert!(l.reserve("a", "ip2", t0 + 86_400, &cfg).is_ok());
        // IP cap (3/hour): third issuance from "ip" this hour is the last.
        assert!(l.reserve("b", "ip", t0 + 300, &cfg).is_ok());
        assert_eq!(l.reserve("c", "ip", t0 + 301, &cfg), Err(3600 - 301));
        assert_eq!(l.ip_blocked("ip", t0 + 301, &cfg), Some(3600 - 301));
        assert!(l.reserve("c", "ip", t0 + 3600, &cfg).is_ok());
    }

    #[test]
    fn refused_reservation_charges_nothing() {
        let cfg = MemberKeyConfig {
            ip_hourly_max: 2,
            ..MemberKeyConfig::default()
        };
        let mut l = IssuanceLimiter::default();
        assert!(l.reserve("a", "ip", 0, &cfg).is_ok());
        // Refused on account spacing; must not consume the IP budget.
        assert!(l.reserve("a", "ip", 1, &cfg).is_err());
        assert!(l.reserve("b", "ip", 2, &cfg).is_ok());
    }
}
