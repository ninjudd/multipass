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

# The live check's Cache-Control rule. Vercel sends its default on
# redirects, so that default must pass, and anything that lets a cache serve
# a stored redirect without asking again must fail.
for value in "no-store" "No-Cache" "public, max-age=0, must-revalidate" "max-age=0,must-revalidate,s-maxage=0"; do
  "$CHECK" cache "$value" || {
    echo "FAIL: check-site.sh cache rejected \"$value\"" >&2
    FAILURES=$((FAILURES + 1))
  }
done
# A refusal prints nothing, so one that crashes, as an unbound variable does
# under set -u, does not count as refusing.
for value in "" " " "public" "public, max-age=0" "public, max-age=60, must-revalidate" \
  "public, max-age=0, must-revalidate, s-maxage=86400" 'no-cache="set-cookie", max-age=600' "max-age=0, proxy-revalidate"; do
  if errors="$("$CHECK" cache "$value" 2>&1)"; then
    echo "FAIL: check-site.sh cache accepted \"$value\"" >&2
    FAILURES=$((FAILURES + 1))
  elif [ -n "$errors" ]; then
    echo "FAIL: check-site.sh cache failed on \"$value\" without applying the rule: $errors" >&2
    FAILURES=$((FAILURES + 1))
  fi
done

# vercel-api.sh, against a fake curl that logs its arguments and stdin and
# answers with the body in $FAKE/body and $FAKE_STATUS, so no request leaves
# this machine.
fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}
API="$ROOT/.github/scripts/vercel-api.sh"
FAKE="$(mktemp -d "${TMPDIR:-/tmp}/multipass-site-test.XXXXXX")"
trap 'rm -rf "$FAKE"' EXIT
cat >"$FAKE/curl" <<EOF
#!/bin/sh
printf '%s\n' "\$@" >"$FAKE/argv"
cat >"$FAKE/stdin"
cat "$FAKE/body"
printf '\n%s' "\$FAKE_STATUS"
EOF
chmod +x "$FAKE/curl"
printf '{"deploymentId":"dpl_1"}' >"$FAKE/body"
api() {
  set +e
  OUT="$(env PATH="$FAKE:$PATH" VERCEL_TOKEN=secret-token VERCEL_ORG_ID=team_1 FAKE_STATUS="$1" "$API" "$2" "$3" 2>"$FAKE/stderr")"
  STATUS=$?
  set -e
}

api 200 GET /v4/aliases/example.dev
[ "$STATUS" = 0 ] || fail "vercel-api.sh exited $STATUS for a 200"
[ "$OUT" = '{"deploymentId":"dpl_1"}' ] || fail "vercel-api.sh printed $OUT for a 200"
grep -qx 'https://api.vercel.com/v4/aliases/example.dev?teamId=team_1' "$FAKE/argv" ||
  fail "vercel-api.sh did not request the path with teamId: $(cat "$FAKE/argv")"
! grep -q secret-token "$FAKE/argv" || fail "vercel-api.sh put the token in curl's arguments"
grep -qx 'Authorization: Bearer secret-token' "$FAKE/stdin" || fail "vercel-api.sh did not send the token on stdin"
! grep -qx -- --data "$FAKE/argv" || fail "vercel-api.sh sent a body with a GET"

api 201 POST "/v10/projects/prj_1/promote/dpl_2?x=1"
[ "$STATUS" = 0 ] || fail "vercel-api.sh exited $STATUS for a 201"
grep -qx 'https://api.vercel.com/v10/projects/prj_1/promote/dpl_2?x=1&teamId=team_1' "$FAKE/argv" ||
  fail "vercel-api.sh did not add teamId to a path with a query: $(cat "$FAKE/argv")"
grep -qx POST "$FAKE/argv" || fail "vercel-api.sh did not send a POST"

api 404 GET /v4/aliases/example.dev
[ "$STATUS" = 4 ] || fail "vercel-api.sh exited $STATUS for a 404, not 4"

api 403 POST /v1/projects/prj_1/rollback/dpl_1
[ "$STATUS" = 1 ] || fail "vercel-api.sh exited $STATUS for a 403, not 1"
[ -z "$OUT" ] || fail "vercel-api.sh printed the body of a 403 to stdout"
grep -q 'answered HTTP 403' "$FAKE/stderr" || fail "vercel-api.sh did not name the 403: $(cat "$FAKE/stderr")"

# serving-deployment.sh, the rollback target. Only a 404 may leave it empty;
# a 200 without an ID would leave a failed promotion live.
SERVING="$ROOT/.github/scripts/serving-deployment.sh"
serving() {
  printf '%s' "$2" >"$FAKE/body"
  set +e
  OUT="$(env PATH="$FAKE:$PATH" VERCEL_TOKEN=secret-token VERCEL_ORG_ID=team_1 FAKE_STATUS="$1" "$SERVING" example.dev 2>"$FAKE/stderr")"
  STATUS=$?
  set -e
}
serving 200 '{"deploymentId":"dpl_5m8CQaRBm3FnWRW1"}'
[ "$STATUS" = 0 ] && [ "$OUT" = dpl_5m8CQaRBm3FnWRW1 ] ||
  fail "serving-deployment.sh printed \"$OUT\" and exited $STATUS for a 200 with an ID"
serving 404 '{"error":{"code":"not_found"}}'
[ "$STATUS" = 0 ] && [ -z "$OUT" ] ||
  fail "serving-deployment.sh printed \"$OUT\" and exited $STATUS for a 404, not an empty ID"
for body in '{"deploymentId":null}' '{}' '{"deploymentId":"../v1/x"}' 'not json'; do
  serving 200 "$body"
  [ "$STATUS" = 1 ] ||
    fail "serving-deployment.sh exited $STATUS, printing \"$OUT\", for a 200 with $body"
done
serving 500 '{}'
[ "$STATUS" = 1 ] || fail "serving-deployment.sh exited $STATUS for a 500"

if [ "$FAILURES" -gt 0 ]; then
  exit 1
fi
echo "site checks passed"
