#!/usr/bin/env python3
"""Tripwire: the production operator signer must use KMS, never a plaintext key.

Bug-class (INFER-S1 / WP-C): the operator wallet signs pool-dispatch txs. The
handoff is explicit — custody must NOT be a plaintext key; production signs via
AWS KMS (the key never leaves KMS). `LocalSigner` holds a raw secret and exists
ONLY for tests + the anvil e2e. If a regression makes the production loader
(`OperatorWallet::from_env`) construct a `LocalSigner` (e.g. reading a private
key from an env var), the hot wallet's key would live in gateway memory/plaintext.

This check fails CI if `from_env` references `LocalSigner`, or stops gating on
the KMS feature.

Spec: .agentile/sprints/active/INFER-S1-WPC-operator-signer.md
"""
import re
import sys
from pathlib import Path

SIGNER = Path(__file__).resolve().parents[2] / "gateway" / "src" / "signer.rs"


def from_env_body(src: str) -> str:
    start = re.search(r"pub async fn from_env\(", src)
    if not start:
        sys.exit("FAIL: could not find `OperatorWallet::from_env` in gateway/src/signer.rs")
    # Body ends at the next method indented with 4 spaces ("    /// " or "    pub ").
    rest = src[start.end():]
    end = re.search(r"\n    /// The operator EOA address", rest)
    return rest[: end.start()] if end else rest


def main() -> int:
    src = SIGNER.read_text()
    body = from_env_body(src)

    problems = []
    if "LocalSigner" in body:
        problems.append(
            "OperatorWallet::from_env references `LocalSigner` — production custody "
            "must use AWS KMS, never a plaintext local key. LocalSigner is tests-only."
        )
    if 'feature = "aws-kms"' not in body:
        problems.append(
            "OperatorWallet::from_env no longer gates on the `aws-kms` feature — the "
            "production signer must be the KMS-backed one."
        )

    if problems:
        print("TRIPWIRE FAILED — plaintext operator key (INFER-S1/WP-C):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("ok: from_env uses KMS custody (no LocalSigner), gated on the aws-kms feature")
    return 0


if __name__ == "__main__":
    sys.exit(main())
