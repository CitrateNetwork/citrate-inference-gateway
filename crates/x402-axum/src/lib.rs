//! HTTP 402 Payment Required middleware for axum.
//!
//! # What this crate does
//!
//! Gate any axum handler behind an on-chain payment. A request without
//! a valid `X-PAYMENT` header gets a `402` response with a challenge.
//! A request WITH a valid signed authorization gets verified via
//! Citrate precompile `0x0201` (off-chain, free), settled on-chain via
//! `X402Facilitator.settlePayment`, and only then forwarded to the
//! wrapped handler.
//!
//! # Formal basis
//!
//! - Server-side state machine:
//!   `.agentile/formal/specs/compute/X402FacilitatorSettle.tla` —
//!   six invariants including `NonceNeverReused` and
//!   `SettleImpliesChallenge`.
//! - Client-side complement:
//!   `.agentile/formal/specs/wallet/X402PaymentFlow.tla` —
//!   eight invariants governing the client's challenge→sign→retry flow.
//! - Behavior contract:
//!   `citrate_v0.01.1/specs/gherkin/x402_payment.feature` — ten
//!   scenarios the implementation must satisfy.
//! - Architecture decision:
//!   `docs/adr/ADR-005-x402-payment-protocol.md`.
//!
//! # Usage (server)
//!
//! ```ignore
//! use x402_axum::{X402Layer, FixedPricing};
//!
//! let layer = X402Layer::builder()
//!     .chain_id(40204)
//!     .facilitator_address("0x...")
//!     .wsalt_address("0x...")
//!     .treasury("0x...")
//!     .rpc_url("http://127.0.0.1:18545")
//!     .pricing(FixedPricing::new("1000000000000000000"))  // 1 SALT
//!     .build()?;
//!
//! let app = axum::Router::new()
//!     .route("/expensive", post(handler))
//!     .layer(layer);
//! ```
//!
//! # Usage (client)
//!
//! ```ignore
//! use x402_axum::X402Client;
//!
//! let client = X402Client::new(signer, wsalt_addr, facilitator_addr, 40204);
//! let response = client.send_paid(reqwest::Client::new().post(url)).await?;
//! ```
//!
//! # Status
//!
//! This is WP-02.1 of CM-02 — crate scaffolding only. Types are
//! declared but bodies are `todo!()`. WP-02.2 fills in the challenge
//! generator; WP-02.3 fills verify + settle; WP-02.4 implements the
//! client; WP-02.5 wires observability.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod challenge;
pub mod client;
pub mod digest;
pub mod error;
pub mod layer;
pub mod nonce;
pub mod pricing;
pub mod types;

// Convenience re-exports — the shape a user integrates with.
pub use challenge::{build_challenge, now_unix_secs, BuiltChallenge, ChallengeInputs};
pub use client::X402Client;
pub use digest::{eip712_digest, transfer_with_authorization_struct_hash, wsalt_domain_separator};
pub use error::X402Error;
pub use layer::{X402Layer, X402LayerBuilder, X402Service};
pub use nonce::NonceSource;
pub use pricing::{FixedPricing, PricingError, PricingStrategy};
pub use types::{PaymentChallenge, PaymentPayload, X402Paid};
