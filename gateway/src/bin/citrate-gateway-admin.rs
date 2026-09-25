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
//! - `migrate-encrypt` — ENCRYPT-S1 one-shot: encrypt a legacy plaintext
//!   keystore in place (staging dir + atomic rename; idempotent;
//!   `--dry-run` supported). Runbook:
//!   `.agentile/runbooks/ENCRYPTED_MONEY_STORE.md`.
//!
//! All operations require write access to the keystore dir, which is
//! `0600` and owned by the gateway service user on production hosts.
//! Since ENCRYPT-S1 the store values are encrypted at rest, so every
//! keystore command also needs the master key — sourced through the same
//! chain the gateway uses (`GATEWAY_STORE_KEY` env → key file → generate;
//! see `citrate_gateway::keyvault`).

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use citrate_gateway::keystore::PersistentKeyStore;
use citrate_gateway::signer::{EncryptedFileSigner, OperatorWallet};
use citrate_gateway::{keyvault, migrate};
use clap::{Parser, Subcommand};
use ethereum_types::{H160, U256};

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

    /// Master-key file for the at-rest store encryption (ENCRYPT-S1).
    /// Defaults to the same chain the gateway uses: `GATEWAY_STORE_KEY` env
    /// → `GATEWAY_STORE_KEY_FILE` env → `<keystore>.master.key`.
    #[arg(long)]
    store_key_file: Option<String>,

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
    /// ENCRYPT-S1: encrypt a legacy plaintext keystore in place (one-shot,
    /// idempotent). Stop the gateway service first; the pre-migration copy
    /// is kept as `<keystore>.pre-encrypt-<ts>` for rollback.
    MigrateEncrypt {
        /// Classify + count only; write nothing (not even a generated key).
        #[arg(long)]
        dry_run: bool,
    },
    /// DEV/TESTNET: generate a fresh encrypted operator keystore (V3, scrypt +
    /// AES-128-CTR) and print the operator address to fund. NOT for mainnet —
    /// mainnet custody is AWS KMS.
    OperatorKeygen {
        /// Output keystore file path, e.g. `./operator.keystore.json`.
        #[arg(long)]
        out: String,
        /// Keystore password. Prefer `--password-file` so it stays off argv.
        #[arg(long, env = "CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD")]
        password: Option<String>,
        /// Read the password from this file (trailing whitespace trimmed).
        #[arg(long)]
        password_file: Option<String>,
    },
    /// DEV/TESTNET: dry-run a pool dispatch — load the encrypted operator
    /// keystore, sign `requestPoolCompute`, submit it, print the tx hash.
    OperatorDispatch {
        /// JSON-RPC endpoint, e.g. `https://rpc.citrate.ai`.
        #[arg(long, env = "CITRATE_GATEWAY_RPC_URL")]
        rpc: String,
        /// EIP-155 chain id (Citrate testnet = 40204).
        #[arg(long, env = "CITRATE_GATEWAY_CHAIN_ID", default_value_t = 40204)]
        chain_id: u64,
        /// ComputePool contract address (0x…).
        #[arg(long, env = "CITRATE_GATEWAY_COMPUTE_POOL")]
        pool: String,
        /// Operator keystore path.
        #[arg(long, env = "CITRATE_GATEWAY_OPERATOR_KEYSTORE")]
        keystore: String,
        /// Keystore password (or `--password-file`).
        #[arg(long, env = "CITRATE_GATEWAY_OPERATOR_KEYSTORE_PASSWORD")]
        password: Option<String>,
        /// Read the password from this file.
        #[arg(long)]
        password_file: Option<String>,
        /// Pool id to dispatch to.
        #[arg(long)]
        pool_id: u64,
        /// Payment value in wei (the `value` sent with the call).
        #[arg(long, default_value = "1000000000000000000")]
        payment_wei: String,
        /// Max price per unit (wei); defaults to `payment_wei`.
        #[arg(long)]
        max_price_wei: Option<String>,
        /// Opaque job-spec bytes (utf-8); recorded on-chain.
        #[arg(long, default_value = "dry-run")]
        job_spec: String,
    },
}

/// Resolve a password from an inline value or a file (trimmed). Errors if neither.
fn resolve_password(
    password: Option<String>,
    password_file: Option<String>,
) -> Result<String, String> {
    if let Some(p) = password {
        return Ok(p);
    }
    if let Some(path) = password_file {
        return std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("reading --password-file {path}: {e}"));
    }
    Err("provide --password or --password-file".into())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Operator-signer commands never touch the API-key DB — dispatch them
    // before opening the keystore (which would create a RocksDB dir).
    match cli.cmd {
        Cmd::OperatorKeygen {
            out,
            password,
            password_file,
        } => operator_keygen(out, password, password_file),
        Cmd::OperatorDispatch {
            rpc,
            chain_id,
            pool,
            keystore,
            password,
            password_file,
            pool_id,
            payment_wei,
            max_price_wei,
            job_spec,
        } => operator_dispatch(OperatorDispatchArgs {
            rpc,
            chain_id,
            pool,
            keystore,
            password,
            password_file,
            pool_id,
            payment_wei,
            max_price_wei,
            job_spec,
        }),
        // migrate-encrypt must run BEFORE a normal encrypted open (which
        // would refuse the plaintext store it exists to fix).
        Cmd::MigrateEncrypt { dry_run } => {
            migrate_encrypt_cmd(&cli.keystore, cli.store_key_file.as_deref(), dry_run)
        }
        cmd => run_keystore_cmd(&cli.keystore, cli.store_key_file.as_deref(), cmd),
    }
}

/// Source the store master key via the gateway's chain (ENCRYPT-S1):
/// `GATEWAY_STORE_KEY` env → key file → (if allowed) generate + persist.
fn source_store_key(
    keystore_path: &str,
    key_file_flag: Option<&str>,
    allow_generate: bool,
) -> Result<([u8; 32], keyvault::KeySource), keyvault::KeyvaultError> {
    let key_file =
        keyvault::resolve_key_file(Path::new(keystore_path), key_file_flag.map(Path::new));
    keyvault::load_store_key(&key_file, allow_generate)
}

/// Run an API-key command against the persistent keystore at `keystore_path`.
fn run_keystore_cmd(keystore_path: &str, key_file_flag: Option<&str>, cmd: Cmd) -> ExitCode {
    let (master, key_source) = match source_store_key(keystore_path, key_file_flag, true) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error sourcing store master key: {e}");
            return ExitCode::from(2);
        }
    };
    eprintln!("store master key: {key_source}");
    let store = match PersistentKeyStore::open(keystore_path, master) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error opening keystore at {keystore_path}: {e}");
            return ExitCode::from(2);
        }
    };

    match cmd {
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
        // Handled in main() before the keystore is opened.
        Cmd::OperatorKeygen { .. } | Cmd::OperatorDispatch { .. } | Cmd::MigrateEncrypt { .. } => {
            unreachable!()
        }
    }
}

/// ENCRYPT-S1: drive [`citrate_gateway::migrate::migrate_encrypt`] and print
/// an operator-readable report. Dry runs never write (not even a generated
/// key); real runs source the key through the normal chain.
fn migrate_encrypt_cmd(
    keystore_path: &str,
    key_file_flag: Option<&str>,
    dry_run: bool,
) -> ExitCode {
    // Dry run: a key is optional (only used to verify an already-encrypted
    // store is under OUR key). Real run: required, generation allowed.
    let master = if dry_run {
        match source_store_key(keystore_path, key_file_flag, false) {
            Ok((k, src)) => {
                eprintln!("store master key: {src}");
                Some(k)
            }
            Err(keyvault::KeyvaultError::NotFound(path)) => {
                eprintln!(
                    "no store master key yet — a real run would generate one at {}",
                    path.display()
                );
                None
            }
            Err(e) => {
                eprintln!("error sourcing store master key: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        match source_store_key(keystore_path, key_file_flag, true) {
            Ok((k, src)) => {
                eprintln!("store master key: {src}");
                Some(k)
            }
            Err(e) => {
                eprintln!("error sourcing store master key: {e}");
                return ExitCode::from(2);
            }
        }
    };

    match migrate::migrate_encrypt(Path::new(keystore_path), master, dry_run) {
        Ok(report) => {
            match report.state {
                migrate::SourceState::AlreadyEncrypted => {
                    eprintln!(
                        "keystore at {keystore_path} is ALREADY encrypted{} — nothing to do",
                        if master.is_some() {
                            " (under this key)"
                        } else {
                            ""
                        }
                    );
                }
                migrate::SourceState::Plaintext => {
                    eprintln!(
                        "{}: plaintext keystore, {} rows:",
                        if report.dry_run {
                            "DRY RUN"
                        } else {
                            "MIGRATED"
                        },
                        report.entries
                    );
                    for (ns, n) in &report.per_namespace {
                        eprintln!("  {ns:<10} {n}");
                    }
                    if let Some(backup) = &report.backup {
                        eprintln!(
                            "pre-migration plaintext copy kept at {} — verify the service, \
                             then archive/destroy it per the runbook (it still holds \
                             plaintext money records)",
                            backup.display()
                        );
                    } else if report.dry_run {
                        eprintln!("(dry run — nothing was written)");
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("migration refused/failed (source store untouched): {e}");
            ExitCode::from(1)
        }
    }
}

/// DEV/TESTNET: generate a fresh encrypted V3 keystore + print the operator address.
fn operator_keygen(
    out: String,
    password: Option<String>,
    password_file: Option<String>,
) -> ExitCode {
    let password = match resolve_password(password, password_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let path = std::path::Path::new(&out);
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => {
            eprintln!("error: --out must be a file path, e.g. ./operator.keystore.json");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("error creating {}: {e}", dir.display());
        return ExitCode::from(1);
    }
    let mut rng = rand::thread_rng();
    if let Err(e) = eth_keystore::new(dir, &mut rng, &password, Some(name)) {
        eprintln!("error generating keystore: {e}");
        return ExitCode::from(1);
    }
    // Re-read through the same path the gateway uses, so the address we print is
    // exactly what `from_env` will load (and confirms the password roundtrips).
    let signer = match EncryptedFileSigner::from_keystore(path, &password) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error verifying keystore: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("Wrote encrypted operator keystore → {}", path.display());
    eprintln!("⚠ DEV/TESTNET custody only — mainnet uses AWS KMS.");
    eprintln!("Operator address (fund this on testnet):");
    println!("0x{}", hex::encode(signer.address().as_bytes()));
    ExitCode::SUCCESS
}

struct OperatorDispatchArgs {
    rpc: String,
    chain_id: u64,
    pool: String,
    keystore: String,
    password: Option<String>,
    password_file: Option<String>,
    pool_id: u64,
    payment_wei: String,
    max_price_wei: Option<String>,
    job_spec: String,
}

/// Parse a `0x…` 20-byte hex address.
fn parse_h160(s: &str) -> Result<H160, String> {
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex address {s}: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("address {s} must be 20 bytes, got {}", bytes.len()));
    }
    Ok(H160::from_slice(&bytes))
}

/// DEV/TESTNET: load the encrypted keystore signer + submit one `requestPoolCompute`.
fn operator_dispatch(a: OperatorDispatchArgs) -> ExitCode {
    let password = match resolve_password(a.password, a.password_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let pool = match parse_h160(&a.pool) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };
    let payment = match U256::from_dec_str(&a.payment_wei) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("error: --payment-wei must be a decimal integer");
            return ExitCode::from(1);
        }
    };
    let max_price = match a.max_price_wei {
        Some(s) => match U256::from_dec_str(&s) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("error: --max-price-wei must be a decimal integer");
                return ExitCode::from(1);
            }
        },
        None => payment,
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error starting tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(async move {
        let signer = match EncryptedFileSigner::from_keystore(&a.keystore, &password) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error loading keystore: {e}");
                return ExitCode::from(1);
            }
        };
        let operator = signer.address();
        eprintln!("operator: 0x{}", hex::encode(operator.as_bytes()));
        eprintln!(
            "dispatch: pool_id={} payment_wei={} max_price_wei={} chain_id={}",
            a.pool_id, payment, max_price, a.chain_id
        );
        // Dry-run: the spend cap is intentionally wide open (U256::MAX) — the
        // blast-radius bound is exercised by the gateway, not this one-off tool.
        let wallet = OperatorWallet::new(Arc::new(signer), a.rpc, a.chain_id, pool, U256::MAX, 100);
        match wallet
            .dispatch_pool_compute(
                U256::from(a.pool_id),
                a.job_spec.as_bytes(),
                max_price,
                payment,
            )
            .await
        {
            Ok(hash) => {
                eprintln!("submitted requestPoolCompute, tx hash:");
                println!("0x{}", hex::encode(hash.as_bytes()));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("dispatch failed: {e}");
                ExitCode::from(1)
            }
        }
    })
}
