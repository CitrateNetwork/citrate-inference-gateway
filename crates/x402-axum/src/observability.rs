//! Observability hook for `X402Layer`.
//!
//! The layer calls into an [`ObservabilityHook`] on every settlement
//! decision — success or rejection. The default hook is a no-op, so
//! library consumers pay nothing for the hook surface if they don't
//! care about it. Operators who DO care (running a gateway, wiring
//! Prometheus, feeding a trail) implement the trait once and pass it
//! through the builder.
//!
//! Closes x402_payment.feature scenario #10:
//! > "Successful settlement emits a trail event and Prometheus
//! >  counter. The event fields include payer, amount_wei (grains),
//! >  tx_hash. The Prometheus counter increments by 1."
//!
//! The hook is fire-and-forget from the layer's perspective — any
//! `.await` happens inside the hook's own implementation. Failures in
//! the hook do NOT fail the request; they're logged via `tracing`
//! and otherwise swallowed. This keeps the hot path clean: a broken
//! metrics exporter must not break payment.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ethereum_types::{H160, H256, U256};

/// Event fired on a successful settlement. The layer attaches the
/// same data to the request via `X402Paid` — this is the trail /
/// metrics surface for callers who want to see every settlement as
/// it happens.
#[derive(Debug, Clone)]
pub struct SettledEvent {
    /// Payer (from `PaymentSettled` event's `from` topic).
    pub payer: H160,
    /// Net value received by the recipient, in wei (grains — NOT
    /// SALT). Converts via `citrate_wallet_core::format::grains_to_salt`
    /// for display.
    pub amount_wei: U256,
    /// Facilitator fee in wei.
    pub fee_wei: U256,
    /// The settled nonce. Useful for correlating across services
    /// (gateway <-> facilitator <-> trail).
    pub nonce: H256,
    /// The on-chain tx hash of the settlement.
    pub tx_hash: H256,
    /// Block the settlement landed in.
    pub block_number: u64,
}

/// Event fired when a request is rejected (402, 500, or 403).
#[derive(Debug, Clone)]
pub struct RejectedEvent {
    /// Short machine-readable reason from `X402Error::reason()`.
    pub reason: &'static str,
    /// HTTP status the layer will return.
    pub http_status: u16,
    /// Best-effort identification of the payer. `None` if the
    /// request had no parseable X-PAYMENT header.
    pub payer: Option<H160>,
}

/// Hook called on every payment decision. Implementations are
/// expected to be cheap — heavy I/O should go to background tasks.
#[async_trait]
pub trait ObservabilityHook: Send + Sync + std::fmt::Debug {
    /// Called after a settlement succeeds, before the inner service
    /// is invoked. Errors here do not fail the request.
    async fn on_settled(&self, event: &SettledEvent);

    /// Called when the layer rejects a request. Errors here do not
    /// change the response.
    async fn on_rejected(&self, event: &RejectedEvent);
}

/// Default no-op hook. Used when no hook is configured on the builder.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopObservability;

#[async_trait]
impl ObservabilityHook for NoopObservability {
    async fn on_settled(&self, _event: &SettledEvent) {}
    async fn on_rejected(&self, _event: &RejectedEvent) {}
}

/// Thread-safe in-memory counters, easy to wire into a Prometheus
/// exporter. Not a full metric-library dependency — the crate
/// stays dependency-light; exporters can sample these values on
/// their own cadence.
#[derive(Debug, Default)]
pub struct CountersObservability {
    settlements_total: AtomicU64,
    rejections_total: AtomicU64,
    // Reasons are static strings so counting per-reason needs a
    // small interning table. Kept simple: we count the common
    // reasons individually and sum the rest into "other."
    rejected_nonce_replayed: AtomicU64,
    rejected_invalid_sig: AtomicU64,
    rejected_expired: AtomicU64,
    rejected_budget: AtomicU64,
    rejected_malformed: AtomicU64,
    rejected_insufficient_balance: AtomicU64,
    rejected_other: AtomicU64,
}

impl CountersObservability {
    /// Create a new counter set. Wrap in `Arc` if you want to share
    /// with an exporter thread.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total successful settlements.
    pub fn settlements_total(&self) -> u64 {
        self.settlements_total.load(Ordering::Relaxed)
    }

    /// Total rejections across all reasons.
    pub fn rejections_total(&self) -> u64 {
        self.rejections_total.load(Ordering::Relaxed)
    }

    /// Rejections broken down by reason. Keys match the strings in
    /// `X402Error::reason()`.
    pub fn rejections_by_reason(&self) -> RejectionBreakdown {
        RejectionBreakdown {
            nonce_replayed: self.rejected_nonce_replayed.load(Ordering::Relaxed),
            invalid_signature: self.rejected_invalid_sig.load(Ordering::Relaxed),
            expired: self.rejected_expired.load(Ordering::Relaxed),
            budget_exceeded: self.rejected_budget.load(Ordering::Relaxed),
            malformed: self.rejected_malformed.load(Ordering::Relaxed),
            insufficient_balance: self.rejected_insufficient_balance.load(Ordering::Relaxed),
            other: self.rejected_other.load(Ordering::Relaxed),
        }
    }
}

/// Labeled snapshot of rejection counters for Prometheus export.
#[derive(Debug, Clone, Copy)]
pub struct RejectionBreakdown {
    /// `reason == "nonce replayed"`.
    pub nonce_replayed: u64,
    /// `reason == "signature invalid"`.
    pub invalid_signature: u64,
    /// `reason == "expired"`.
    pub expired: u64,
    /// `reason == "budget cap exceeded"`.
    pub budget_exceeded: u64,
    /// `reason ∈ {"malformed payment header", "payment required"}`.
    pub malformed: u64,
    /// `reason == "insufficient balance"`.
    pub insufficient_balance: u64,
    /// Everything else.
    pub other: u64,
}

#[async_trait]
impl ObservabilityHook for CountersObservability {
    async fn on_settled(&self, _event: &SettledEvent) {
        self.settlements_total.fetch_add(1, Ordering::Relaxed);
    }

    async fn on_rejected(&self, event: &RejectedEvent) {
        self.rejections_total.fetch_add(1, Ordering::Relaxed);
        let counter = match event.reason {
            "nonce replayed" => &self.rejected_nonce_replayed,
            "signature invalid" => &self.rejected_invalid_sig,
            "expired" => &self.rejected_expired,
            "budget cap exceeded" => &self.rejected_budget,
            "malformed payment header" | "payment required" => &self.rejected_malformed,
            "insufficient balance" => &self.rejected_insufficient_balance,
            _ => &self.rejected_other,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Blanket impl so `Arc<dyn ObservabilityHook>` works with any
/// `Arc<T: ObservabilityHook>`.
#[async_trait]
impl<T: ObservabilityHook + ?Sized> ObservabilityHook for Arc<T> {
    async fn on_settled(&self, event: &SettledEvent) {
        (**self).on_settled(event).await;
    }

    async fn on_rejected(&self, event: &RejectedEvent) {
        (**self).on_rejected(event).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_hook_does_nothing() {
        let h = NoopObservability;
        let ev = SettledEvent {
            payer: H160::zero(),
            amount_wei: U256::zero(),
            fee_wei: U256::zero(),
            nonce: H256::zero(),
            tx_hash: H256::zero(),
            block_number: 0,
        };
        h.on_settled(&ev).await; // doesn't panic; no observable effect
        h.on_rejected(&RejectedEvent {
            reason: "expired",
            http_status: 402,
            payer: None,
        })
        .await;
    }

    #[tokio::test]
    async fn counters_hook_increments_on_settle() {
        let c = CountersObservability::new();
        let ev = SettledEvent {
            payer: H160::zero(),
            amount_wei: U256::from(100u64),
            fee_wei: U256::from(1u64),
            nonce: H256::zero(),
            tx_hash: H256::zero(),
            block_number: 42,
        };
        assert_eq!(c.settlements_total(), 0);
        c.on_settled(&ev).await;
        c.on_settled(&ev).await;
        c.on_settled(&ev).await;
        assert_eq!(c.settlements_total(), 3);
        assert_eq!(c.rejections_total(), 0);
    }

    #[tokio::test]
    async fn counters_hook_breaks_down_rejections() {
        let c = CountersObservability::new();
        for reason in [
            "nonce replayed",
            "nonce replayed",
            "signature invalid",
            "expired",
            "budget cap exceeded",
            "budget cap exceeded",
            "budget cap exceeded",
            "malformed payment header",
            "something weird",
        ] {
            c.on_rejected(&RejectedEvent {
                reason,
                http_status: 402,
                payer: None,
            })
            .await;
        }

        let b = c.rejections_by_reason();
        assert_eq!(b.nonce_replayed, 2);
        assert_eq!(b.invalid_signature, 1);
        assert_eq!(b.expired, 1);
        assert_eq!(b.budget_exceeded, 3);
        assert_eq!(b.malformed, 1);
        assert_eq!(b.other, 1);
        assert_eq!(c.rejections_total(), 9);
    }

    #[tokio::test]
    async fn counters_are_thread_safe() {
        // Spawn N concurrent on_settled calls — every one must land.
        let c = Arc::new(CountersObservability::new());
        let mut handles = vec![];
        let event = SettledEvent {
            payer: H160::zero(),
            amount_wei: U256::zero(),
            fee_wei: U256::zero(),
            nonce: H256::zero(),
            tx_hash: H256::zero(),
            block_number: 0,
        };
        for _ in 0..100 {
            let c = c.clone();
            let ev = event.clone();
            handles.push(tokio::spawn(async move {
                c.on_settled(&ev).await;
            }));
        }
        for h in handles {
            h.await.expect("join");
        }
        assert_eq!(c.settlements_total(), 100);
    }

    #[tokio::test]
    async fn arc_dyn_forwards_to_inner() {
        let inner: Arc<dyn ObservabilityHook> = Arc::new(CountersObservability::new());
        let ev = SettledEvent {
            payer: H160::zero(),
            amount_wei: U256::zero(),
            fee_wei: U256::zero(),
            nonce: H256::zero(),
            tx_hash: H256::zero(),
            block_number: 0,
        };
        inner.on_settled(&ev).await; // exercises the blanket impl
    }
}
