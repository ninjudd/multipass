#!/usr/bin/env bash
#
# Checks that check-site.sh accepts site/ and rejects every bad site under
# tests/site/, one directory per way a change could send install.sh
# somewhere else.
#
#   tests/site.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/.github/scripts/check-site.sh"
FAILURES=0

if ! "$CHECK" static "$ROOT/site"; then
  echo "FAIL: check-site.sh rejected site/" >&2
  FAILURES=$((FAILURES + 1))
fi
for dir in "$ROOT"/tests/site/*/; do
  if output="$("$CHECK" static "$dir" 2>&1)"; then
    echo "FAIL: check-site.sh accepted tests/site/$(basename "$dir")" >&2
    FAILURES=$((FAILURES + 1))
  elif ! printf '%s\n' "$output" | grep -q '^check-site.sh: '; then
    # A guard that could not run also exits nonzero; only a named problem
    # counts as a rejection.
    echo "FAIL: check-site.sh failed on tests/site/$(basename "$dir") without naming a problem: $output" >&2
    FAILURES=$((FAILURES + 1))
  else
    printf 'rejected %-24s %s\n' "$(basename "$dir")" "$(printf '%s\n' "$output" | head -n 1)"
  fi
done

if [ "$FAILURES" -gt 0 ]; then
  exit 1
fi
echo "site checks passed"
