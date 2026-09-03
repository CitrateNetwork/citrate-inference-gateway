#!/usr/bin/env bash
# local-ci.sh — run the CI gates locally (GitHub Actions org-wide dead since ~2026-07-18).
# Rust gates: fmt-changed, clippy, test. --fast = fmt+clippy. Installed via install-hooks.sh.
# Exit 0 = all pass, 1 = a gate failed. Every gate runs even if an earlier one fails.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; cd "$ROOT"
FAST=0
while [ $# -gt 0 ]; do case "$1" in
  --fast) FAST=1; shift;; --list) echo "gates: fmt-changed, clippy, test"; exit 0;;
  -h|--help) sed -n '2,4p' "$0"; exit 0;; *) echo "unknown arg: $1" >&2; exit 1;; esac; done
B=$'\033[1m'; R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; X=$'\033[0m'; [ -t 1 ] || { B=""; R=""; G=""; Y=""; X=""; }
declare -a N=() S=(); FAILED=0
gate(){ local n="$1"; shift; printf "%s▶ %s%s\n" "$B" "$n" "$X"; local o; o="$("$@" 2>&1)"; local rc=$?
  if [ $rc -eq 0 ]; then N+=("$n"); S+=("PASS"); printf "  %sPASS%s\n" "$G" "$X"
  else N+=("$n"); S+=("FAIL"); FAILED=1; printf "  %sFAIL%s\n" "$R" "$X"; echo "$o" | tail -25 | sed 's/^/    /'; fi; }
fmt_changed(){ local base; base="$(git merge-base HEAD origin/main 2>/dev/null || git rev-parse HEAD)"
  local files; files=$( { git diff --name-only --diff-filter=ACMR "$base" HEAD -- '*.rs'; git diff --name-only --diff-filter=ACMR -- '*.rs'; } | sort -u)
  [ -z "$files" ] && { echo "no changed .rs"; return 0; }; local bad=0
  while IFS= read -r f; do [ -f "$f" ] || continue; rustfmt --edition 2021 --check "$f" >/dev/null 2>&1 || { echo "needs fmt: $f"; bad=1; }; done <<< "$files"
  [ "$bad" -eq 0 ] || { echo "run: cargo fmt"; return 1; }; }
gate "fmt-changed" fmt_changed
gate "clippy" cargo clippy --workspace --all-targets --quiet -- -D warnings
if [ "$FAST" -eq 0 ]; then gate "test" cargo test --workspace --quiet; else N+=("test"); S+=("SKIP"); fi
echo; echo "──── local CI summary ────"
for i in "${!N[@]}"; do c="$G"; [ "${S[$i]}" = FAIL ] && c="$R"; [ "${S[$i]}" = SKIP ] && c="$Y"; printf "  %s%-6s%s %s\n" "$c" "${S[$i]}" "$X" "${N[$i]}"; done
[ "$FAILED" -eq 0 ] && { echo "${G}LOCAL CI PASSED${X}"; exit 0; } || { echo "${R}LOCAL CI FAILED${X}"; exit 1; }
