//! The money-path tripwire scripts under `scripts/ci/` are only useful if
//! something runs them. No workflow invokes them directly, so this test runs
//! each one under `cargo test` (which `ci.yml` and `local-ci.sh` both run).
//!
//! Each script is checked twice:
//!   1. against the real tree: it must pass (exit 0, prints `ok:`);
//!   2. against a temp copy of the tree with the guarded construct removed:
//!      it must fail (exit 1, prints `TRIPWIRE FAILED`). This is the negative
//!      control: it proves the script can still detect the regression it was
//!      written for, so a script that silently rots into "always pass" or
//!      "always fail" is caught here.
//!
//! The scripts resolve their input as `<script>/../../gateway/src/<file>`, so
//! the negative control lays out `<tmp>/scripts/ci/<script>` next to
//! `<tmp>/gateway/src/<file>`. Nothing outside the temp dir is written.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway crate has a parent dir")
        .to_path_buf()
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
}

fn run_script(script: &Path) -> Outcome {
    let out = Command::new("python3")
        .arg(script)
        .env_remove("PYTHONPATH")
        .output()
        .expect("python3 must be available to run the CI tripwire scripts");
    Outcome {
        code: out.status.code(),
        stdout: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// Copy `scripts/ci/<script>` and the listed `gateway/src/<file>`s into a temp
/// tree, apply `mutate` to `target_file`, and run the copied script.
fn run_against_mutated_tree(
    script: &str,
    files: &[&str],
    target_file: &str,
    mutate: impl Fn(&str) -> String,
) -> Outcome {
    let root = repo_root();
    let tmp = tempfile::tempdir().expect("tempdir");
    let ci_dir = tmp.path().join("scripts/ci");
    let src_dir = tmp.path().join("gateway/src");
    std::fs::create_dir_all(&ci_dir).expect("mkdir scripts/ci");
    std::fs::create_dir_all(&src_dir).expect("mkdir gateway/src");
    std::fs::copy(root.join("scripts/ci").join(script), ci_dir.join(script)).expect("copy script");
    for f in files {
        let original =
            std::fs::read_to_string(root.join("gateway/src").join(f)).expect("read gateway source");
        let content = if *f == target_file {
            let mutated = mutate(&original);
            assert_ne!(
                mutated, original,
                "negative control for {script}: the mutation did not change {f}; \
                 update the test to the current source shape"
            );
            mutated
        } else {
            original
        };
        std::fs::write(src_dir.join(f), content).expect("write mutated source");
    }
    run_script(&ci_dir.join(script))
}

fn assert_passes_on_the_real_tree(script: &str) {
    let out = run_script(&repo_root().join("scripts/ci").join(script));
    assert_eq!(
        out.code,
        Some(0),
        "{script} must pass on the current tree:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("ok:"),
        "{script} output: {}",
        out.stdout
    );
}

fn assert_detects(out: Outcome, script: &str) {
    assert_eq!(
        out.code,
        Some(1),
        "{script} must FAIL on a tree with the guard removed:\n{}",
        out.stdout
    );
    assert!(
        out.stdout.contains("TRIPWIRE FAILED"),
        "{script} output: {}",
        out.stdout
    );
}

// --- durable money + batch store --------------------------------------------

const DURABLE: &str = "check_durable_money_store.py";
const DURABLE_FILES: &[&str] = &["lib.rs", "keyvault.rs"];

#[test]
fn durable_money_store_tripwire_passes_on_main() {
    assert_passes_on_the_real_tree(DURABLE);
}

#[test]
fn durable_money_store_tripwire_detects_a_volatile_production_fallback() {
    // The production boot must refuse a volatile store outside the dev
    // profile. Turning that refusal back into a silent in-memory fallback is
    // the regression this tripwire exists for.
    let out = run_against_mutated_tree(DURABLE, DURABLE_FILES, "lib.rs", |s| {
        s.replacen(
            "MarketplaceStoreDecision::RefusedProdVolatile => panic!(",
            "MarketplaceStoreDecision::RefusedProdVolatile => return None; #[allow(unreachable_code)] panic!(",
            1,
        )
    });
    assert_detects(out, DURABLE);
}

#[test]
fn durable_money_store_tripwire_detects_a_dropped_durable_open() {
    let out = run_against_mutated_tree(DURABLE, DURABLE_FILES, "lib.rs", |s| {
        s.replacen(
            "keyvault::open_store(&path)",
            "open_volatile_store(&path)",
            1,
        )
    });
    assert_detects(out, DURABLE);
}

#[test]
fn durable_money_store_tripwire_detects_build_router_not_using_the_store() {
    let out = run_against_mutated_tree(DURABLE, DURABLE_FILES, "lib.rs", |s| {
        s.replacen(
            "let store = open_marketplace_store();",
            "let store: Option<Arc<keystore::PersistentKeyStore>> = None;",
            1,
        )
    });
    assert_detects(out, DURABLE);
}

// --- per-model budget enforcement -------------------------------------------

const BUDGET: &str = "check_model_budget_enforced.py";

#[test]
fn model_budget_tripwire_passes_on_main() {
    assert_passes_on_the_real_tree(BUDGET);
}

#[test]
fn model_budget_tripwire_detects_a_dropped_debit() {
    let out = run_against_mutated_tree(BUDGET, &["chat.rs"], "chat.rs", |s| {
        s.replacen(".debit_model_budget(", ".peek_model_budget(", 1)
    });
    assert_detects(out, BUDGET);
}

#[test]
fn model_budget_tripwire_detects_a_dropped_refund() {
    let out = run_against_mutated_tree(BUDGET, &["chat.rs"], "chat.rs", |s| {
        s.replacen(".refund_model_budget(", ".noop_model_budget(", 1)
    });
    assert_detects(out, BUDGET);
}

// --- operator signer custody ------------------------------------------------

const SIGNER: &str = "check_no_plaintext_operator_key.py";

#[test]
fn operator_key_tripwire_passes_on_main() {
    assert_passes_on_the_real_tree(SIGNER);
}

#[test]
fn operator_key_tripwire_detects_a_local_signer_in_the_production_loader() {
    let out = run_against_mutated_tree(SIGNER, &["signer.rs"], "signer.rs", |s| {
        s.replacen(
            "pub async fn from_env(",
            "pub async fn from_env(/* LocalSigner::from_secret(env) */",
            1,
        )
    });
    assert_detects(out, SIGNER);
}
