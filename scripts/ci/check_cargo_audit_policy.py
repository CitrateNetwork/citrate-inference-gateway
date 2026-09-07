#!/usr/bin/env python3
"""Validate the expiry-backed cargo-audit exception policy."""

from __future__ import annotations

from datetime import date
from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "scripts/ci/cargo-audit-policy.toml"
AUDIT_CONFIG_PATH = ROOT / "audit.toml"


def load_policy() -> dict[str, dict[str, str]]:
    with POLICY_PATH.open("rb") as handle:
        document = tomllib.load(handle)
    ignores = document.get("ignore")
    if not isinstance(ignores, dict) or not ignores:
        raise ValueError("cargo-audit policy must define at least one ignore")
    policy: dict[str, dict[str, str]] = {}
    today = date.today()
    for advisory_id, entry in ignores.items():
        if not advisory_id.startswith("RUSTSEC-"):
            raise ValueError(f"invalid advisory id: {advisory_id}")
        if not isinstance(entry, dict):
            raise ValueError(f"{advisory_id}: policy entry must be a table")
        try:
            expiry = date.fromisoformat(entry["expires"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{advisory_id}: invalid expires date") from error
        if expiry <= today:
            raise ValueError(f"{advisory_id}: exception expired on {expiry}")
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"{advisory_id}: exception needs a non-empty reason")
        policy[advisory_id] = {"expires": str(expiry), "reason": reason}
    return policy


def validate_mirror(policy: dict[str, dict[str, str]]) -> None:
    with AUDIT_CONFIG_PATH.open("rb") as handle:
        document = tomllib.load(handle)
    configured = document.get("advisories", {}).get("ignore", [])
    if set(configured) != set(policy):
        missing = sorted(set(policy) - set(configured))
        extra = sorted(set(configured) - set(policy))
        raise ValueError(f"audit.toml mirror mismatch: missing={missing}, extra={extra}")


def main() -> int:
    try:
        policy = load_policy()
        validate_mirror(policy)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"cargo-audit policy: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"cargo-audit policy: OK ({len(policy)} non-expired exceptions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
