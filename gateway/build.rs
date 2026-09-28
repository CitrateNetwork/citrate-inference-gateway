//! Bake the deployed git commit into the gateway binary so `GET /health` can report
//! it (audit rescore #10, dim 8 — deploys probed, not attested).
//!
//! Resolution order, evaluated at build time:
//!   1. `GIT_SHA` env var — the sanctioned override for a build whose context has no
//!      `.git/` (e.g. a source tarball / rsync deploy). Set it to `git rev-parse HEAD`.
//!   2. `git rev-parse HEAD` — works for a normal build inside a checkout (how the
//!      gateway is built on rpc-1) and in CI.
//!   3. `"unknown"` — never fails the build.
//!
//! The value only ever surfaces on `/health`; it is not a secret. A runtime env var
//! (`GIT_SHA` / `SOURCE_COMMIT`) still takes precedence over this baked-in fallback.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GIT_SHA");
    // Workspace `.git` lives one level up from this crate.
    println!("cargo:rerun-if-changed=../.git/HEAD");

    let sha = std::env::var("GIT_SHA")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_SHA={sha}");
}
