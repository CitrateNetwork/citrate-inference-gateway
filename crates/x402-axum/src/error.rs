//! Error types for the x402-axum crate.
//!
//! Three tiers, matching the behavior contract in
//! `citrate_v0.01.1/specs/gherkin/x402_payment.feature`:
//!
//! - **Client errors** (HTTP 402): missing header, invalid signature,
//!   expired payload, replayed nonce, insufficient on-chain balance.
//!   Retriable — the client can fix and retry.
//! - **Server errors** (HTTP 500): RPC unreachable, receipt-poll
//!   timeout, facilitator revert due to our misconfiguration.
//!   Not the caller's fault.
//! - **Policy errors** (HTTP 403): payer on deny-list.
//!   Present but not used in v1 (deny-list is an empty config field).

use thiserror::Error;

/// Error surface for the whole crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum X402Error {
    // ── Client-facing (402) ─────────────────────────────────────────
    /// Request arrived with no `X-PAYMENT` header. Server responds 402
    /// with a fresh challenge.
    #[error("missing X-PAYMENT header")]
    MissingPaymentHeader,

    /// `X-PAYMENT` header was present but not valid base64 or had the
    /// wrong byte length (expected 265 per EIP-3009 payload shape).
    #[error("malformed X-PAYMENT header: {0}")]
    MalformedPaymentHeader(String),

    /// Precompile 0x0201 recovered a signer that doesn't match the
    /// claimed `from` address.
    #[error("signature invalid: recovered signer differs from claimed 'from'")]
    InvalidSignature,

    /// Nonce has already been settled. Replay attempt.
    #[error("nonce replayed: already settled on-chain")]
    NonceReplayed,

    /// `block.timestamp` exceeds `validBefore`, or is below `validAfter`.
    #[error("payload expired or not yet valid")]
    Expired,

    /// Payment payload's recipient (`to`) does not match this gateway's
    /// configured treasury. Closes the cross-gateway replay path:
    /// pre-fix a signature for one gateway's treasury could be reused
    /// against another gateway. RM-B1 / WP-D2.3 (audit F-1).
    #[error("recipient does not match gateway treasury")]
    RecipientNotTreasury,

    /// Payer has insufficient wSALT balance at settle time. Tx reverted.
    #[error("insufficient wSALT balance")]
    InsufficientBalance,

    /// Client's X402Client exceeded its configured budget cap for this
    /// session. No signature produced; caller should not retry.
    #[error("budget cap exceeded: {amount_requested_wei} wei > {cap_wei} wei")]
    BudgetExceeded {
        /// The amount the challenge demanded.
        amount_requested_wei: String,
        /// The client's configured cap.
        cap_wei: String,
    },

    /// Ed25519 keys cannot produce EIP-3009 signatures (EIP-3009 is
    /// ECDSA over secp256k1). Surfaces when the wallet is the native
    /// Citrate Ed25519 default rather than an imported secp256k1.
    #[error("unsupported key type: EIP-3009 requires secp256k1")]
    UnsupportedKeyType,

    // ── Server-facing (500) ────────────────────────────────────────
    /// JSON-RPC transport error.
    #[error("rpc transport: {0}")]
    RpcTransport(String),

    /// JSON-RPC returned an error object.
    #[error("rpc error: {0}")]
    RpcError(String),

    /// `settlePayment` submitted but no receipt inside the configured
    /// poll window. The tx MAY still land — callers should NOT mark
    /// the nonce settled locally (see
    /// `x402_payment.feature` scenario "Receipt-poll timeout degrades
    /// gracefully").
    #[error("settle pending (timeout)")]
    SettlePendingTimeout,

    /// Facilitator contract reverted. Usually misconfiguration on the
    /// server side (wrong chain_id, wrong treasury, wrong wSALT).
    #[error("facilitator reverted: {0}")]
    FacilitatorReverted(String),

    // ── Policy (403) ────────────────────────────────────────────────
    /// Payer address on the operator's deny-list. Not used in v1.
    #[error("payer denied by policy")]
    Denied,

    // ── Internal / bug ──────────────────────────────────────────────
    /// A pricing strategy returned an error.
    #[error("pricing error: {0}")]
    Pricing(String),

    /// Catch-all for "this shouldn't happen" conditions we'd rather
    /// not panic on.
    #[error("internal: {0}")]
    Internal(String),
}

impl X402Error {
    /// HTTP status this error maps to. See the three-tier policy in
    /// the module docs.
    pub fn http_status(&self) -> u16 {
        use X402Error::*;
        match self {
            MissingPaymentHeader
            | MalformedPaymentHeader(_)
            | InvalidSignature
            | NonceReplayed
            | Expired
            | RecipientNotTreasury
            | InsufficientBalance
            | BudgetExceeded { .. }
            | UnsupportedKeyType => 402,
            Denied => 403,
            RpcTransport(_)
            | RpcError(_)
            | SettlePendingTimeout
            | FacilitatorReverted(_)
            | Pricing(_)
            | Internal(_) => 500,
        }
    }

    /// Short reason string, suitable for the `reason` field in the
    /// `402` JSON body. Matches the Gherkin scenarios verbatim.
    pub fn reason(&self) -> &'static str {
        use X402Error::*;
        match self {
            MissingPaymentHeader => "payment required",
            MalformedPaymentHeader(_) => "malformed payment header",
            InvalidSignature => "signature invalid",
            NonceReplayed => "nonce replayed",
            Expired => "expired",
            RecipientNotTreasury => "recipient not treasury",
            InsufficientBalance => "insufficient balance",
            BudgetExceeded { .. } => "budget cap exceeded",
            UnsupportedKeyType => "unsupported key type",
            Denied => "denied",
            RpcTransport(_) => "rpc transport error",
            RpcError(_) => "rpc error",
            SettlePendingTimeout => "settle pending (timeout)",
            FacilitatorReverted(_) => "on-chain settle failed",
            Pricing(_) => "pricing error",
            Internal(_) => "internal error",
        }
    }
}
