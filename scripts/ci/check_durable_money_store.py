#!/usr/bin/env python3
"""Tripwire: the production gateway's money + batch stores must be durable.

Bug-class (INFER-S4 / WP-F / TD-22): the marketplace `ApiKeyStore` (balances)
and `BatchStore` (in-flight batches) were in-memory, so a restart wiped every
balance and stranded every in-flight batch's escrow. The fix routes the
production builder through `open_marketplace_store()`, which returns a durable
RocksDB store when configured and otherwise falls back to in-memory **with a
loud warning** — the volatility is never silent. Both `keys` and `batches`
share that one store so a batch refund + its balance credit commit atomically.

This check fails CI if a regression:
  - removes `open_marketplace_store()` from `build_router` (the gated path), or
  - lets `open_marketplace_store()` fall back to in-memory **silently** (no
    `tracing::warn`), or drops the durable `PersistentKeyStore::open`.

Spec: .agentile/sprints/active/INFER-S4-WPF-durable-balances.md
"""
import re
import sys
from pathlib import Path

LIB = Path(__file__).resolve().parents[2] / "gateway" / "src" / "lib.rs"


def fn_body(src: str, sig_re: str, name: str) -> str:
    start = re.search(sig_re, src)
    if not start:
        sys.exit(f"FAIL: could not find `{name}` in gateway/src/lib.rs")
    rest = src[start.start():]
    end = re.search(r"\n\}\n", rest)
    if not end:
        sys.exit(f"FAIL: could not delimit the `{name}` body")
    return rest[: end.end()]


def main() -> int:
    src = LIB.read_text()
    build = fn_body(src, r"pub async fn build_router\(", "build_router")
    opener = fn_body(src, r"fn open_marketplace_store\(", "open_marketplace_store")

    problems = []
    if "open_marketplace_store()" not in build:
        problems.append(
            "build_router no longer wires `open_marketplace_store()` — the durable "
            "(shared) store path for balances + batches is missing (WP-F regression)."
        )
    if "PersistentKeyStore::open" not in opener:
        problems.append(
            "open_marketplace_store no longer opens a durable `PersistentKeyStore` — "
            "the money + batch stores would be volatile in production."
        )
    if "tracing::warn" not in opener:
        problems.append(
            "open_marketplace_store can fall back to in-memory SILENTLY — a volatile "
            "money store must warn loudly (it must never be silent)."
        )

    if problems:
        print("TRIPWIRE FAILED — durable money + batch store (INFER-S4/WP-F/TD-22):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("ok: build_router wires open_marketplace_store(); durable open present; fallback warns loudly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
