//! Cross-class dispatch target selection (CM-05 WP-05.4).
//!
//! Compares individual providers and pools on a single comparable
//! score. The winner determines which path the chat handler takes:
//!
//! - `Individual` → existing CM-03 WP-03.2 dispatch (HTTPS to provider's
//!   /infer endpoint with x402-paid wallet behind the gateway)
//! - `Pool` → CM-05 dispatch via `requestPoolCompute` on-chain
//!   (slice 1 returns 503; slice 2 wires the gateway wallet)
//!
//! # Scoring
//!
//! Both classes produce a `u128` score; higher wins.
//!
//! - Individual: `reputation_bps × max_concurrent` (capacity-aware
//!   reputation; a 9000-bps provider with 100 concurrent slots
//!   beats a 9500-bps provider with 1 slot when contention matters)
//! - Pool: `min_member_reputation_bps × stake_in_salt` where
//!   `stake_in_salt = total_stake_grains / 1e18` (grains per SALT)
//!
//! The two scoring functions are NOT trying to be commensurate at
//! the unit level — they're calibrated empirically so a "good
//! pool" with 9500-bps members and 500 SALT stake (score 4_750_000)
//! beats a "good individual" with 9000 bps and 100 capacity (score
//! 900_000), but a "weak pool" with 5000-bps members and 10 SALT
//! stake (score 50_000) loses to the same individual.
//!
//! This calibration is configurable per-deployment in slice 2.

use ethereum_types::U256;

use crate::queries::{PoolEntry, ProviderInfo};

/// Dispatch target chosen by `select_dispatch_target`.
#[derive(Debug, Clone)]
pub enum DispatchTarget {
    /// Route via the individual-provider path (CM-03 WP-03.2).
    Individual(ProviderInfo),
    /// Route via the pool path (CM-05).
    Pool(PoolEntry),
}

/// Score an individual provider. Higher = better.
pub fn score_provider(p: &ProviderInfo) -> u128 {
    let cap = u128::from(p.capacity_remaining());
    let rep = u128::from(p.reputation_bps);
    rep.saturating_mul(cap)
}

/// Score a pool. Higher = better.
pub fn score_pool(p: &PoolEntry) -> u128 {
    let salt = (p.total_stake_grains
        / U256::from(1_000_000_000_000_000_000u128))
    .as_u128();
    let rep = u128::from(p.min_member_reputation_bps);
    rep.saturating_mul(salt)
}

/// Pick the best dispatch target across both classes.
///
/// Returns `None` when both lists are empty (the chat handler maps
/// this to `GatewayError::NoProviders` → 503).
///
/// Ties are broken in favour of the individual provider — pools
/// have higher coordination overhead (extra on-chain tx per job),
/// so when scores match the cheaper route wins.
pub fn select_dispatch_target(
    providers: &[ProviderInfo],
    pools: &[PoolEntry],
) -> Option<DispatchTarget> {
    let best_provider = providers.iter().max_by_key(|p| score_provider(p));
    let best_pool = pools.iter().max_by_key(|p| score_pool(p));
    match (best_provider, best_pool) {
        (None, None) => None,
        (Some(p), None) => Some(DispatchTarget::Individual(p.clone())),
        (None, Some(pl)) => Some(DispatchTarget::Pool(pl.clone())),
        (Some(p), Some(pl)) => {
            let ps = score_provider(p);
            let pls = score_pool(pl);
            if pls > ps {
                Some(DispatchTarget::Pool(pl.clone()))
            } else {
                Some(DispatchTarget::Individual(p.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::H160;

    fn provider(rep_bps: u32, cap: u32) -> ProviderInfo {
        ProviderInfo {
            address: H160::zero(),
            endpoint: "http://x".into(),
            reputation_bps: rep_bps,
            current_load: 0,
            max_concurrent: cap,
        }
    }

    fn pool(rep_bps: u32, salt: u64) -> PoolEntry {
        PoolEntry {
            pool_id: 1,
            name: "pool-x".into(),
            total_stake_grains: U256::from(salt) * U256::from(1_000_000_000_000_000_000u128),
            member_count: 1,
            min_member_reputation_bps: rep_bps,
        }
    }

    #[test]
    fn empty_both_returns_none() {
        assert!(select_dispatch_target(&[], &[]).is_none());
    }

    #[test]
    fn only_individual_wins() {
        let p = provider(9000, 10);
        let out = select_dispatch_target(std::slice::from_ref(&p), &[]).expect("some");
        assert!(matches!(out, DispatchTarget::Individual(_)));
    }

    #[test]
    fn only_pool_wins() {
        let pl = pool(9000, 100);
        let out = select_dispatch_target(&[], std::slice::from_ref(&pl)).expect("some");
        assert!(matches!(out, DispatchTarget::Pool(_)));
    }

    #[test]
    fn high_pool_beats_individual() {
        let p = provider(9000, 10);   // score = 90_000
        let pl = pool(9500, 100);     // score = 950_000
        let out = select_dispatch_target(&[p], &[pl]).expect("some");
        assert!(matches!(out, DispatchTarget::Pool(_)));
    }

    #[test]
    fn weak_pool_loses_to_individual() {
        let p = provider(9000, 100);  // score = 900_000
        let pl = pool(5000, 10);      // score = 50_000
        let out = select_dispatch_target(&[p], &[pl]).expect("some");
        assert!(matches!(out, DispatchTarget::Individual(_)));
    }

    #[test]
    fn tie_goes_to_individual() {
        // Provider score = 9000 × 10 = 90_000.
        // Pool score = 9000 × 10 = 90_000. Same.
        let p = provider(9000, 10);
        let pl = pool(9000, 10);
        let out = select_dispatch_target(&[p], &[pl]).expect("some");
        assert!(
            matches!(out, DispatchTarget::Individual(_)),
            "tie should favour the cheaper individual path"
        );
    }
}
