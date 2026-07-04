//! `keyvault` — sourcing the money-store master key (ENCRYPT-S1 / WP-2).
//!
//! The durable RocksDB money store ([`crate::keystore::PersistentKeyStore`])
//! encrypts every VALUE at rest under a 32-byte master key (AES-256-GCM-SIV,
//! per-namespace subkeys — see `keystore.rs`). This module answers "where does
//! that key come from?" on a **headless droplet**, where the comms-relay
//! `keyring::Entry` pattern is not portable (no Secret Service / D-Bus under
//! systemd).
//!
//! # Sourcing chain (first hit wins)
//!
//! 1. **`GATEWAY_STORE_KEY`** env var — 64 hex chars (32 bytes). In production
//!    this should be injected as a systemd credential
//!    (`SetCredentialEncrypted=` / `LoadCredentialEncrypted=` + a small
//!    `ExecStart` wrapper, or `Environment=` as an interim), so the key never
//!    lives in the unit file in plaintext. Threat model: the key is visible in
//!    `/proc/<pid>/environ` to root and to the service user — it protects
//!    against **off-box exfiltration of the DB directory** (backups,
//!    snapshots, stolen volumes, scp'd dirs), not against a live root
//!    compromise of the droplet.
//! 2. **Key file** — path from `GATEWAY_STORE_KEY_FILE` (or an explicit
//!    `--store-key-file` on the admin CLI), 64 hex chars, must be `0600`
//!    (group/other-readable files are REFUSED — fail closed on a money key).
//!    Threat model: same as (1) as long as the file lives on a different
//!    path/volume than the DB (e.g. `/etc/citrate-gateway/store.key` vs
//!    `/var/lib/citrate-gateway/keystore`); a backup job that captures both
//!    defeats it.
//! 3. **Generate + persist on first run** — a fresh random key is written
//!    (hex, `0600`) to the resolved key-file path, which defaults to
//!    `<keystore>.master.key` — a **sibling of the DB directory**. Threat
//!    model: this is the bootstrap/dev convenience tier. Because the key sits
//!    next to the data, it defeats only accidental single-file/DB-dir leaks;
//!    an attacker who copies the parent directory gets both. Production MUST
//!    graduate to (1) or (2) — see
//!    `.agentile/runbooks/ENCRYPTED_MONEY_STORE.md`.
//!
//! Losing this key loses every balance record — treat it like the operator
//! signer key (`reference: .env.testnet` custody rules) and back it up
//! off-box at provisioning time.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::keystore::PersistentKeyStore;

/// Env var carrying the master key itself (64 hex chars = 32 bytes).
pub const ENV_STORE_KEY: &str = "GATEWAY_STORE_KEY";
/// Env var carrying the key-*file* path (systemd `LoadCredential` friendly:
/// set it to `%d/store.key` style paths).
pub const ENV_STORE_KEY_FILE: &str = "GATEWAY_STORE_KEY_FILE";

/// Where the master key actually came from — logged at boot so the operator
/// can verify the droplet is on the intended tier of the sourcing chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// `GATEWAY_STORE_KEY` env var (systemd credential tier).
    Env,
    /// Existing key file at this path.
    File(PathBuf),
    /// Freshly generated this boot and persisted to this path (`0600`).
    Generated(PathBuf),
}

impl fmt::Display for KeySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySource::Env => write!(f, "env:{ENV_STORE_KEY}"),
            KeySource::File(p) => write!(f, "file:{}", p.display()),
            KeySource::Generated(p) => write!(f, "generated:{}", p.display()),
        }
    }
}

/// Why the master key could not be sourced.
#[derive(Debug, thiserror::Error)]
pub enum KeyvaultError {
    /// `GATEWAY_STORE_KEY` was set but malformed. Fail closed — a mis-pasted
    /// key silently falling through to file/generate would split the store
    /// across two keys.
    #[error("{ENV_STORE_KEY} is set but is not 64 hex chars (32 bytes)")]
    BadEnvKey,
    /// Key file exists but its contents are malformed.
    #[error("key file {0} is not 64 hex chars (32 bytes)")]
    BadFileKey(PathBuf),
    /// Key file is readable by group/other — refused for money-key material.
    #[error(
        "key file {0} has mode {1:o}; refusing group/other-readable key material — `chmod 600` it"
    )]
    TooPermissive(PathBuf, u32),
    /// I/O reading or writing the key file.
    #[error("key file {0}: {1}")]
    Io(PathBuf, String),
    /// OS RNG failure while generating a fresh key.
    #[error("rng failure generating store master key")]
    Rng,
    /// No key anywhere in the chain and generation was disabled (dry-run).
    #[error(
        "no store master key found (checked {ENV_STORE_KEY} and {0}) and generation is \
         disabled in this mode — set {ENV_STORE_KEY} or provision the key file"
    )]
    NotFound(PathBuf),
}

/// Default key-file location: a **sibling** of the keystore directory,
/// `<keystore>.master.key`. Sibling (not inside) so a naive copy of the DB
/// directory alone does not capture the key; see the module docs for why this
/// is still only the bootstrap tier.
pub fn default_key_file(keystore_path: &Path) -> PathBuf {
    let mut os = keystore_path.as_os_str().to_owned();
    os.push(".master.key");
    PathBuf::from(os)
}

/// Resolve which key-file path the chain should use:
/// explicit (CLI flag) → `GATEWAY_STORE_KEY_FILE` env → `<keystore>.master.key`.
pub fn resolve_key_file(keystore_path: &Path, explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Ok(p) = std::env::var(ENV_STORE_KEY_FILE) {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    default_key_file(keystore_path)
}

/// Load the store master key via the sourcing chain (env → file → generate).
///
/// `allow_generate=false` turns tier 3 off (used by `migrate-encrypt
/// --dry-run`, which must not write anything).
pub fn load_store_key(
    key_file: &Path,
    allow_generate: bool,
) -> Result<([u8; 32], KeySource), KeyvaultError> {
    load_store_key_with(std::env::var(ENV_STORE_KEY).ok(), key_file, allow_generate)
}

/// The testable core of [`load_store_key`] — env value injected by the caller.
pub(crate) fn load_store_key_with(
    env_val: Option<String>,
    key_file: &Path,
    allow_generate: bool,
) -> Result<([u8; 32], KeySource), KeyvaultError> {
    // Tier 1: env var (systemd credential). Set-but-malformed fails closed.
    if let Some(v) = env_val {
        if !v.trim().is_empty() {
            return parse_hex_key(&v)
                .map(|k| (k, KeySource::Env))
                .ok_or(KeyvaultError::BadEnvKey);
        }
    }

    // Tier 2: key file (0600 enforced).
    if key_file.exists() {
        check_key_file_perms(key_file)?;
        let s = std::fs::read_to_string(key_file)
            .map_err(|e| KeyvaultError::Io(key_file.to_path_buf(), e.to_string()))?;
        return parse_hex_key(&s)
            .map(|k| (k, KeySource::File(key_file.to_path_buf())))
            .ok_or_else(|| KeyvaultError::BadFileKey(key_file.to_path_buf()));
    }

    // Tier 3: generate + persist on first run.
    if !allow_generate {
        return Err(KeyvaultError::NotFound(key_file.to_path_buf()));
    }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|_| KeyvaultError::Rng)?;
    write_key_file(key_file, &key)?;
    Ok((key, KeySource::Generated(key_file.to_path_buf())))
}

/// Parse a 64-hex-char key, tolerating surrounding whitespace/newline.
fn parse_hex_key(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s.trim()).ok()?;
    bytes.try_into().ok()
}

/// Refuse group/other-readable key files (money-key material fails closed).
#[cfg(unix)]
fn check_key_file_perms(path: &Path) -> Result<(), KeyvaultError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| KeyvaultError::Io(path.to_path_buf(), e.to_string()))?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyvaultError::TooPermissive(path.to_path_buf(), mode));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_file_perms(_path: &Path) -> Result<(), KeyvaultError> {
    Ok(())
}

/// Persist a freshly generated key: hex + newline, created `0600`, parent dir
/// created if missing. `create_new` so two racing first-boots can't silently
/// overwrite each other's key — the loser re-reads the winner's file.
fn write_key_file(path: &Path, key: &[u8; 32]) -> Result<(), KeyvaultError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)
            .map_err(|e| KeyvaultError::Io(path.to_path_buf(), e.to_string()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| KeyvaultError::Io(path.to_path_buf(), e.to_string()))?;
    writeln!(f, "{}", hex::encode(key))
        .map_err(|e| KeyvaultError::Io(path.to_path_buf(), e.to_string()))?;
    f.sync_all()
        .map_err(|e| KeyvaultError::Io(path.to_path_buf(), e.to_string()))?;
    Ok(())
}

/// Why the one-call open failed — key sourcing or the store itself.
#[derive(Debug, thiserror::Error)]
pub enum OpenStoreError {
    /// Master key could not be sourced.
    #[error(transparent)]
    Key(#[from] KeyvaultError),
    /// Store open failed (includes `WrongKey` / `PlaintextStore`).
    #[error(transparent)]
    Store(#[from] crate::keystore::StoreError),
}

/// One-call production open: source the master key via the chain, then open
/// the encrypted store at `keystore_path`. Returns the [`KeySource`] so the
/// caller can log which tier the droplet is on.
pub fn open_store(
    keystore_path: &str,
) -> Result<(Arc<PersistentKeyStore>, KeySource), OpenStoreError> {
    let key_file = resolve_key_file(Path::new(keystore_path), None);
    let (key, source) = load_store_key(&key_file, true)?;
    let store = PersistentKeyStore::open(keystore_path, key)?;
    Ok((store, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_tier_wins_and_parses_hex() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("store.key");
        let hex_key = "11".repeat(32);
        let (key, source) =
            load_store_key_with(Some(format!(" {hex_key}\n")), &kf, false).unwrap();
        assert_eq!(key, [0x11u8; 32]);
        assert_eq!(source, KeySource::Env);
        assert!(!kf.exists(), "env tier must not touch the key file");
    }

    #[test]
    fn malformed_env_fails_closed_never_falls_through() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("store.key");
        let err = load_store_key_with(Some("not-hex".into()), &kf, true).unwrap_err();
        assert!(matches!(err, KeyvaultError::BadEnvKey));
        assert!(!kf.exists(), "a malformed env key must not trigger generation");
    }

    #[test]
    fn generate_then_reload_roundtrips_and_is_0600() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("sub/store.key");
        let (k1, s1) = load_store_key_with(None, &kf, true).unwrap();
        assert_eq!(s1, KeySource::Generated(kf.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(std::fs::metadata(&kf).unwrap().mode() & 0o777, 0o600);
        }
        let (k2, s2) = load_store_key_with(None, &kf, true).unwrap();
        assert_eq!(k1, k2, "second boot reuses the persisted key");
        assert_eq!(s2, KeySource::File(kf));
    }

    #[cfg(unix)]
    #[test]
    fn permissive_key_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("store.key");
        std::fs::write(&kf, format!("{}\n", "22".repeat(32))).unwrap();
        std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_store_key_with(None, &kf, true).unwrap_err();
        assert!(matches!(err, KeyvaultError::TooPermissive(_, 0o644)));
    }

    #[test]
    fn no_key_and_generation_disabled_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("store.key");
        let err = load_store_key_with(None, &kf, false).unwrap_err();
        assert!(matches!(err, KeyvaultError::NotFound(_)));
    }

    #[test]
    fn default_key_file_is_a_sibling_of_the_db_dir() {
        assert_eq!(
            default_key_file(Path::new("/var/lib/citrate-gateway/keystore")),
            PathBuf::from("/var/lib/citrate-gateway/keystore.master.key")
        );
    }
}
