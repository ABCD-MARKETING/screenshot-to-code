#!/usr/bin/env bash
# UserPromptSubmit hook: injects the Universal Product Completeness & System
# Integration Protocol reminder into EVERY prompt, so the rule survives session
# restarts and context compaction. Vendored from essman929/AI-MEMORY
# templates/universal-completeness-repo-kit/ — do not edit here, edit there.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTX="$DIR/universal-completeness.txt"

# Drain stdin so the writer never blocks; this hook does not need the payload.
cat >/dev/null 2>&1 || true

[ -r "$CTX" ] || exit 0

if command -v jq >/dev/null 2>&1; then
  jq -n --rawfile ctx "$CTX" \
    '{hookSpecificOutput:{hookEventName:"UserPromptSubmit",additionalContext:$ctx}}'
elif command -v python3 >/dev/null 2>&1; then
  python3 - "$CTX" <<'PY'
import json, sys
ctx = open(sys.argv[1], encoding="utf-8").read()
print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": ctx}}))
PY
else
  exit 0
fi
