#!/usr/bin/env bash
# Fails if the backend's copy of the engine scope vocabulary (internal/auth/engine_scopes.go)
# differs from flwn-data-engine/app/api/tokens.py. Run in CI with both repos checked out:
#   ENGINE_DIR=../flwn-data-engine scripts/check_engine_scopes.sh
set -eu
ENGINE_DIR="${ENGINE_DIR:-../flwn-data-engine}"
engine=$(grep -E '^SCOPE_[A-Z_]+ = "' "$ENGINE_DIR/app/api/tokens.py" | sed -E 's/.*= "([^"]+)".*/\1/' | sort -u)
backend=$(grep -E '^\s*"[a-z]+(:[a-z]+)?":\s*true' internal/auth/engine_scopes.go | sed -E 's/^\s*"([^"]+)".*/\1/' | sort -u)
if [ "$engine" != "$backend" ]; then
  echo "engine scope vocabulary changed; update internal/auth/engine_scopes.go" >&2
  diff <(echo "$engine") <(echo "$backend") >&2 || true
  exit 1
fi
echo "engine scopes match ($(echo "$engine" | wc -l) scopes)"
