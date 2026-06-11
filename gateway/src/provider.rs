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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::GatewayError;
use crate::queries::ProviderInfo;

const ALLOW_PRIVATE_PROVIDER_ENDPOINTS_ENV: &str =
    "CITRATE_GATEWAY_ALLOW_PRIVATE_PROVIDER_ENDPOINTS";
const MAX_PROVIDER_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

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
    /// Optional result-binding signature (FUA-GATEWAY-02): 65-byte
    /// `r||s||v` hex (0x-prefixed or bare) by the provider's registered
    /// key over [`result_binding_digest`]. When present it MUST verify;
    /// when `CITRATE_GATEWAY_REQUIRE_SIGNED_RESULTS=1` it MUST be present.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Domain tag for signed provider results (FUA-GATEWAY-02). Versioned so
/// a future scheme change can't be replayed against the old one.
pub const RESULT_SIG_DOMAIN: &[u8] = b"CITRATE-RESULT-V1";

/// FUA-GATEWAY-02: the digest a provider signs to bind its output to the
/// job: `keccak(domain || model_hash || keccak(prompt) || keccak(output))`.
/// Hashing prompt/output first keeps the preimage fixed-size.
pub fn result_binding_digest(
    model_hash: ethereum_types::H256,
    prompt: &str,
    output: &str,
) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let prompt_hash = Keccak256::digest(prompt.as_bytes());
    let output_hash = Keccak256::digest(output.as_bytes());
    let mut h = Keccak256::new();
    h.update(RESULT_SIG_DOMAIN);
    h.update(model_hash.as_bytes());
    h.update(&prompt_hash);
    h.update(&output_hash);
    h.finalize().into()
}

/// FUA-GATEWAY-02: verify a provider's result-binding signature against
/// its on-chain registered address. Any malformed input → `false`
/// (fail closed).
pub fn verify_result_binding(
    provider: ethereum_types::H160,
    model_hash: ethereum_types::H256,
    prompt: &str,
    output: &str,
    signature_hex: &str,
) -> bool {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    let sig_bytes = match hex::decode(signature_hex.trim_start_matches("0x")) {
        Ok(b) if b.len() == 65 => b,
        _ => return false,
    };
    let sig = match Signature::from_slice(&sig_bytes[..64]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let v = sig_bytes[64];
    let rec = match RecoveryId::from_byte(if v >= 27 { v - 27 } else { v }) {
        Some(r) => r,
        None => return false,
    };
    let digest = result_binding_digest(model_hash, prompt, output);
    let vk = match VerifyingKey::recover_from_prehash(&digest, &sig, rec) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let point = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    ethereum_types::H160::from_slice(&hash[12..]) == provider
}

/// FUA-GATEWAY-02 policy: when set, every provider result must carry a
/// valid binding signature or it is treated as a dispatch failure.
pub fn require_signed_results() -> bool {
    std::env::var("CITRATE_GATEWAY_REQUIRE_SIGNED_RESULTS")
        .ok()
        .as_deref()
        == Some("1")
}

/// FUA-GATEWAY-02 acceptance: a present signature must verify; an absent
/// one is acceptable only while signed results are not required (the
/// documented pilot trust assumption).
pub fn result_acceptable(signature_valid: Option<bool>, required: bool) -> bool {
    match signature_valid {
        Some(valid) => valid,
        None => !required,
    }
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
    _http: &reqwest::Client,
    provider: &ProviderInfo,
    req: &ProviderProtocolRequest,
    timeout: Duration,
) -> Result<ProviderProtocolResponse, GatewayError> {
    let guarded = validate_provider_endpoint(
        &provider.endpoint,
        allow_private_provider_endpoints(),
    )
    .await?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .resolve(&guarded.host, guarded.pinned_addr)
        .build()
        .map_err(|e| GatewayError::ProviderUnavailable(format!("provider http client: {e}")))?;
    let resp = http
        .post(guarded.url.clone())
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
    let bytes = resp.bytes().await.map_err(|e| {
        GatewayError::ProviderUnavailable(format!("{}: response read failed: {e}", provider.endpoint))
    })?;
    if bytes.len() > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(GatewayError::ProviderUnavailable(format!(
            "{}: response too large ({} bytes > {} bytes)",
            provider.endpoint,
            bytes.len(),
            MAX_PROVIDER_RESPONSE_BYTES
        )));
    }
    serde_json::from_slice::<ProviderProtocolResponse>(&bytes).map_err(|e| {
        GatewayError::ProviderUnavailable(format!(
            "{}: malformed response: {}",
            provider.endpoint, e
        ))
    })
}

#[derive(Debug)]
struct GuardedProviderEndpoint {
    url: reqwest::Url,
    host: String,
    pinned_addr: SocketAddr,
}

async fn validate_provider_endpoint(
    endpoint: &str,
    allow_private: bool,
) -> Result<GuardedProviderEndpoint, GatewayError> {
    let url = reqwest::Url::parse(endpoint).map_err(|e| {
        GatewayError::ProviderUnavailable(format!("provider endpoint is not a valid URL: {e}"))
    })?;
    match url.scheme() {
        "https" => {}
        "http" if allow_private => {}
        scheme => {
            return Err(GatewayError::ProviderUnavailable(format!(
                "provider endpoint scheme {scheme:?} is not allowed"
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(GatewayError::ProviderUnavailable(
            "provider endpoint must not contain credentials".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| {
            GatewayError::ProviderUnavailable("provider endpoint host is missing".to_string())
        })?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port_or_known_default().ok_or_else(|| {
        GatewayError::ProviderUnavailable("provider endpoint port is missing".to_string())
    })?;
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| {
                GatewayError::ProviderUnavailable(format!(
                    "provider endpoint DNS lookup failed for {host}: {e}"
                ))
            })?
            .collect()
    };
    if addrs.is_empty() {
        return Err(GatewayError::ProviderUnavailable(format!(
            "provider endpoint DNS lookup returned no addresses for {host}"
        )));
    }
    for addr in &addrs {
        if !provider_ip_allowed(addr.ip(), allow_private) {
            return Err(GatewayError::ProviderUnavailable(format!(
                "provider endpoint resolved to forbidden address {}",
                addr.ip()
            )));
        }
    }
    Ok(GuardedProviderEndpoint {
        url,
        host,
        pinned_addr: addrs[0],
    })
}

fn allow_private_provider_endpoints() -> bool {
    std::env::var(ALLOW_PRIVATE_PROVIDER_ENDPOINTS_ENV)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn provider_ip_allowed(ip: IpAddr, allow_private: bool) -> bool {
    if is_cloud_metadata_ip(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => ipv4_provider_allowed(ip, allow_private),
        IpAddr::V6(ip) => ipv6_provider_allowed(ip, allow_private),
    }
}

fn ipv4_provider_allowed(ip: Ipv4Addr, allow_private: bool) -> bool {
    if allow_private && (ip.is_loopback() || ip.is_private()) {
        return true;
    }
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || is_shared_address_space(ip)
        || is_benchmarking_ip(ip))
}

fn ipv6_provider_allowed(ip: Ipv6Addr, allow_private: bool) -> bool {
    if allow_private && (ip.is_loopback() || ip.is_unique_local()) {
        return true;
    }
    !(ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_unspecified()
        || ip.is_multicast())
}

fn is_cloud_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip == Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(ip) => ip == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    }
}

fn is_shared_address_space(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_benchmarking_ip(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 198 && matches!(b, 18 | 19)
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

    #[tokio::test]
    async fn test_t0_06_rejects_http_without_dev_mode() {
        let err = validate_provider_endpoint("http://example.com/infer", false)
            .await
            .expect_err("http must be rejected without dev mode");
        assert!(err.to_string().contains("scheme"));
    }

    #[tokio::test]
    async fn test_t0_06_rejects_loopback_without_dev_mode() {
        let err = validate_provider_endpoint("https://127.0.0.1/infer", false)
            .await
            .expect_err("loopback must be rejected");
        assert!(err.to_string().contains("forbidden address"));
    }

    #[tokio::test]
    async fn test_t0_06_allows_loopback_only_in_dev_mode() {
        let guarded = validate_provider_endpoint("http://127.0.0.1:8080/infer", true)
            .await
            .expect("dev mode allows local provider endpoints");
        assert_eq!(guarded.pinned_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_t0_06_rejects_aws_metadata_ipv4_even_in_dev_mode() {
        let err = validate_provider_endpoint("http://169.254.169.254/latest/meta-data", true)
            .await
            .expect_err("metadata endpoint must be rejected");
        assert!(err.to_string().contains("forbidden address"));
    }

    #[tokio::test]
    async fn test_t0_06_rejects_aws_metadata_ipv6_even_in_dev_mode() {
        let err = validate_provider_endpoint("http://[fd00:ec2::254]/latest/meta-data", true)
            .await
            .expect_err("metadata endpoint must be rejected");
        assert!(err.to_string().contains("forbidden address"));
    }

    #[tokio::test]
    async fn test_t0_06_rejects_endpoint_credentials() {
        let err = validate_provider_endpoint("https://user:pass@example.com/infer", false)
            .await
            .expect_err("credentials must be rejected");
        assert!(err.to_string().contains("credentials"));
    }

    // ── FUA-GATEWAY-02: result-binding signature ────────────────────

    /// Sign the binding digest with a throwaway k256 key and return
    /// (eth_address, 65-byte r||s||v hex).
    fn sign_binding(
        model_hash: ethereum_types::H256,
        prompt: &str,
        output: &str,
    ) -> (H160, String) {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest, Keccak256};
        let sk = SigningKey::from_slice(&[0x42u8; 32]).expect("key");
        let digest = result_binding_digest(model_hash, prompt, output);
        let (sig, rec) = sk.sign_prehash_recoverable(&digest).expect("sign");
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let addr = H160::from_slice(&hash[12..]);
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(rec.to_byte() + 27);
        (addr, format!("0x{}", hex::encode(bytes)))
    }

    #[test]
    fn valid_binding_signature_verifies() {
        let mh = ethereum_types::H256::from([0x11; 32]);
        let (addr, sig) = sign_binding(mh, "prompt", "output");
        assert!(verify_result_binding(addr, mh, "prompt", "output", &sig));
    }

    #[test]
    fn tampered_output_fails_verification() {
        let mh = ethereum_types::H256::from([0x11; 32]);
        let (addr, sig) = sign_binding(mh, "prompt", "output");
        assert!(!verify_result_binding(addr, mh, "prompt", "FORGED", &sig));
    }

    #[test]
    fn wrong_provider_address_fails_verification() {
        let mh = ethereum_types::H256::from([0x11; 32]);
        let (_, sig) = sign_binding(mh, "prompt", "output");
        let other = H160::from([0x99; 20]);
        assert!(!verify_result_binding(other, mh, "prompt", "output", &sig));
    }

    #[test]
    fn wrong_model_hash_fails_verification() {
        let mh = ethereum_types::H256::from([0x11; 32]);
        let (addr, sig) = sign_binding(mh, "prompt", "output");
        let other_mh = ethereum_types::H256::from([0x22; 32]);
        assert!(!verify_result_binding(addr, other_mh, "prompt", "output", &sig));
    }

    #[test]
    fn malformed_signature_fails_closed() {
        let mh = ethereum_types::H256::from([0x11; 32]);
        let addr = H160::from([0x01; 20]);
        assert!(!verify_result_binding(addr, mh, "p", "o", "not-hex"));
        assert!(!verify_result_binding(addr, mh, "p", "o", "0xabcd"));
        assert!(!verify_result_binding(addr, mh, "p", "o", ""));
    }

    #[test]
    fn result_acceptance_policy_fails_closed() {
        // Present signature: verification result decides, required or not.
        assert!(result_acceptable(Some(true), false));
        assert!(result_acceptable(Some(true), true));
        assert!(!result_acceptable(Some(false), false));
        assert!(!result_acceptable(Some(false), true));
        // Absent signature: acceptable only while not required.
        assert!(result_acceptable(None, false));
        assert!(!result_acceptable(None, true));
    }
}
