//! `citrate-gateway-admin` — local-only key admin CLI (WP-3 of
//! 2026-06-04 planset).
//!
//! Operates directly on the RocksDB keystore that the local-proxy gateway
//! reads. There is no admin HTTP surface — this binary is the entire
//! provisioning surface, and it's intended to be invoked over SSH on the
//! host that owns the keystore directory.
//!
//! # Subcommands
//!
//! - `create --label <l> [--quota-rps N] [--daily-requests N]` — mints a
//!   fresh `cgk_…` key, prints it on stdout exactly **once**. Operator
//!   captures it from stdout (e.g. into Vercel env). Defaults match the
//!   "conservative" tier in the planset's key-distribution model.
//! - `revoke <plaintext-id>` — marks the key revoked; effective on next
//!   request.
//! - `list` — prints active and revoked keys (hash prefix + label +
//!   quotas). The plaintext bearer is never recoverable.
//!
//! All operations require write access to the keystore dir, which is
//! `0600` and owned by the gateway service user on production hosts.

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use citrate_gateway::keystore::PersistentKeyStore;
use ethereum_types::U256;

#[derive(Parser)]
#[command(
    name = "citrate-gateway-admin",
    about = "Mint, revoke, and list cgk_ API keys for the local-proxy gateway.",
    long_about = None,
)]
struct Cli {
    /// Path to the keystore directory. Defaults to the same location the
    /// service unit reads (`CITRATE_GATEWAY_KEYSTORE_PATH`).
    #[arg(
        long,
        env = "CITRATE_GATEWAY_KEYSTORE_PATH",
        default_value = "/var/lib/citrate-gateway/keystore"
    )]
    keystore: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mint a fresh API key. Prints the plaintext token to stdout exactly
    /// once; capture it now or remint.
    Create {
        /// Human label, e.g. `chatbot-prod` or `explorer-prod`.
        #[arg(long)]
        label: String,
        /// Requests/second cap. `0` disables the rate limit.
        #[arg(long, default_value_t = 5)]
        quota_rps: u32,
        /// Daily request cap (UTC day). `0` disables the daily quota.
        #[arg(long, default_value_t = 10_000)]
        daily_requests: u64,
    },
    /// Revoke a key by its plaintext id. Effective on next request.
    Revoke {
        /// The plaintext `cgk_…` token to revoke.
        id: String,
    },
    /// List every key (hash prefix + label + quotas + revoke status).
    List,
    /// Set a per-model spend budget for a key (INFER-S3 / WP-E). A model with
    /// no budget set is uncapped (overall balance only).
    SetModelBudget {
        /// The plaintext `cgk_…` token.
        id: String,
        /// Model name, e.g. `llama-3.1-8b`.
        model: String,
        /// Budget in grains (decimal integer).
        grains: String,
    },
    /// List a key's per-model budgets.
    ListModelBudgets {
        /// The plaintext `cgk_…` token.
        id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let store = match PersistentKeyStore::open(&cli.keystore) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error opening keystore at {}: {e}", cli.keystore);
            return ExitCode::from(2);
        }
    };

    match cli.cmd {
        Cmd::Create {
            label,
            quota_rps,
            daily_requests,
        } => match store.create_key(label.clone(), quota_rps, daily_requests) {
            Ok(id) => {
                // The token goes to stdout (single line, captureable).
                // All other commentary goes to stderr.
                eprintln!(
                    "Minted '{label}' (quota: {quota_rps} rps, {daily_requests} req/day). \
                     This token is shown ONCE — save it now:"
                );
                println!("{id}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Cmd::Revoke { id } => match store.revoke(&id) {
            Ok(()) => {
                eprintln!("Revoked.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Cmd::List => match store.list() {
            Ok(rows) => {
                if rows.is_empty() {
                    eprintln!("(no keys minted yet)");
                } else {
                    println!(
                        "{:<8}  {:<18}  {:<20}  {:>5}  {:>10}",
                        "STATUS", "HASH (prefix)", "LABEL", "RPS", "DAILY"
                    );
                    for (hash, r) in rows {
                        let status = if r.revoked { "REVOKED" } else { "active" };
                        let prefix = &hash[..16.min(hash.len())];
                        println!(
                            "{:<8}  {:<18}  {:<20}  {:>5}  {:>10}",
                            status, prefix, r.label, r.quota_rps, r.daily_quota
                        );
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Cmd::SetModelBudget { id, model, grains } => {
            let amount = match U256::from_dec_str(&grains) {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("error: grains must be a decimal integer");
                    return ExitCode::from(1);
                }
            };
            match store.set_model_budget(&id, &model, amount) {
                Ok(()) => {
                    eprintln!("Set per-model budget: {model} = {grains} grains.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Cmd::ListModelBudgets { id } => match store.get_model_budgets(&id) {
            Ok(rows) => {
                if rows.is_empty() {
                    eprintln!("(no per-model budgets set for this key)");
                } else {
                    println!("{:<28}  {:>24}", "MODEL", "REMAINING (grains)");
                    for (model, remaining) in rows {
                        println!("{:<28}  {:>24}", model, remaining);
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
    }
}
