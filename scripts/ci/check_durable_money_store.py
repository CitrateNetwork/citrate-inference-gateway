#!/usr/bin/env python3
"""Tripwire: the production router's API-key (money) store must be durable.

Bug-class (INFER-S4 / WP-F / TD-22): the marketplace `ApiKeyStore` was
in-memory, so a restart wiped every key balance. The fix routes the production
builder through `marketplace_key_store()` (durable RocksDB when configured,
loud-warning in-memory only in dev). This check fails CI if a regression puts
the volatile `ApiKeyStore::new()` back into `build_router`'s state, or removes
the durable constructor.

Spec: .agentile/sprints/active/INFER-S4-WPF-durable-balances.md
"""
import re
import sys
from pathlib import Path

LIB = Path(__file__).resolve().parents[2] / "gateway" / "src" / "lib.rs"


def build_router_body(src: str) -> str:
    start = re.search(r"pub async fn build_router\(", src)
    if not start:
        sys.exit("FAIL: could not find `build_router` in gateway/src/lib.rs")
    # The function closes at the first line that is exactly `}` (column 0).
    rest = src[start.start():]
    end = re.search(r"\n\}\n", rest)
    if not end:
        sys.exit("FAIL: could not delimit the `build_router` body")
    return rest[: end.end()]


def main() -> int:
    src = LIB.read_text()
    body = build_router_body(src)

    problems = []
    if "ApiKeyStore::new()" in body:
        problems.append(
            "build_router constructs a volatile `ApiKeyStore::new()` — the "
            "marketplace money store must be durable. Use `marketplace_key_store()`."
        )
    if "marketplace_key_store()" not in body:
        problems.append(
            "build_router no longer wires `marketplace_key_store()` — the durable "
            "API-key store path is missing (WP-F regression)."
        )

    if problems:
        print("TRIPWIRE FAILED — durable money store (INFER-S4/WP-F/TD-22):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("ok: build_router wires the durable marketplace_key_store(); no volatile ApiKeyStore::new()")
    return 0


if __name__ == "__main__":
    sys.exit(main())
