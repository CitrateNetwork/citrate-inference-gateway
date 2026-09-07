#!/usr/bin/env python3
"""Run the blocking cargo-audit gate with validated exceptions."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from check_cargo_audit_policy import load_policy, validate_mirror


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    try:
        policy = load_policy()
        validate_mirror(policy)
    except (OSError, ValueError) as error:
        print(f"cargo-audit policy: FAIL: {error}", file=sys.stderr)
        return 1

    command = ["cargo", "audit", "--color", "always", "--deny", "warnings"]
    for advisory_id in sorted(policy):
        command.extend(["--ignore", advisory_id])
    print("+ " + " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
