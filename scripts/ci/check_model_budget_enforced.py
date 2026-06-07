#!/usr/bin/env python3
"""Tripwire: the chat handler must enforce per-model budgets AND refund them.

Bug-class (INFER-S3 / WP-E, R2 audit-sensitive): per-model budgets are enforced
in the chat handler (the layer can't see the model — it can't consume the body).
A regression that drops the `debit_model_budget` call silently removes the cap (a
key could overspend a model past its budget); a regression that drops
`refund_model_budget` on the error path strands the buyer's model budget on every
failed request. Both are money-relevant and easy to lose in a refactor.

This check fails CI if `chat_completions_handler` stops calling either.

Spec: .agentile/sprints/active/INFER-S3-WPE-per-model-budgets.md
"""
import re
import sys
from pathlib import Path

CHAT = Path(__file__).resolve().parents[2] / "gateway" / "src" / "chat.rs"


def handler_body(src: str) -> str:
    start = re.search(r"pub async fn chat_completions_handler\(", src)
    if not start:
        sys.exit("FAIL: could not find `chat_completions_handler` in gateway/src/chat.rs")
    rest = src[start.start():]
    end = re.search(r"\n\}\n", rest)
    if not end:
        sys.exit("FAIL: could not delimit the `chat_completions_handler` body")
    return rest[: end.end()]


def main() -> int:
    body = handler_body(CHAT.read_text())
    problems = []
    if "debit_model_budget" not in body:
        problems.append(
            "chat_completions_handler no longer calls `debit_model_budget` — the "
            "per-model spend cap is not enforced (a key can overspend a model)."
        )
    if "refund_model_budget" not in body:
        problems.append(
            "chat_completions_handler no longer calls `refund_model_budget` — a "
            "failed request strands the buyer's per-model budget."
        )

    if problems:
        print("TRIPWIRE FAILED — per-model budget enforcement (INFER-S3/WP-E):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("ok: chat handler enforces per-model budgets (debit + refund present)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
