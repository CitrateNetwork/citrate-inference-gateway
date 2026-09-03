#!/usr/bin/env bash
# install-hooks.sh — wire local-ci.sh into git so the gate runs without being
# remembered.
#
# Installs a pre-push hook that runs `local-ci.sh --fast` (fmt + clippy +
# unwrap ratchet, ~1 min). The full suite is deliberately NOT in the hook: a
# multi-minute pre-push gets bypassed with --no-verify within a week, and a
# gate people route around is worse than no gate. Run the full one before a
# merge:
#
#   scripts/ci/local-ci.sh
#
# Bypass a single push (be honest with yourself about why):
#
#   git push --no-verify
#
# Uninstall:
#
#   rm .git/hooks/pre-push
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOK_DIR="$(git -C "$REPO_ROOT" rev-parse --git-path hooks)"
HOOK="$HOOK_DIR/pre-push"

mkdir -p "$HOOK_DIR"

if [ -e "$HOOK" ] && ! grep -q "local-ci.sh" "$HOOK" 2>/dev/null; then
  cp "$HOOK" "$HOOK.bak-$(date +%Y%m%d-%H%M%S)"
  echo "existing pre-push hook backed up"
fi

cat > "$HOOK" <<'HOOKEOF'
#!/usr/bin/env bash
# Installed by scripts/ci/install-hooks.sh — runs the fast local CI gates.
# GitHub Actions are dead org-wide; this is the gate that actually runs.
set -uo pipefail
ROOT="$(git rev-parse --show-toplevel)"
[ -x "$ROOT/scripts/ci/local-ci.sh" ] || exit 0
echo "pre-push: running local CI (--fast). Bypass with --no-verify."
"$ROOT/scripts/ci/local-ci.sh" --fast
rc=$?
if [ $rc -ne 0 ]; then
  echo
  echo "pre-push BLOCKED: local CI failed. Fix, or push with --no-verify."
fi
exit $rc
HOOKEOF

chmod +x "$HOOK"
echo "installed: $HOOK"
echo "  runs: scripts/ci/local-ci.sh --fast on every push"
echo "  full suite: scripts/ci/local-ci.sh"
