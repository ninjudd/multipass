#!/usr/bin/env bash
#
# Calls Vercel's REST API on behalf of the team, for the site workflow:
#
#   vercel-api.sh <method> <path>
#
# The CLI's promote and rollback look up the token's user first, which a
# team-scoped token cannot read, so the workflow calls these endpoints
# itself. The token comes from VERCEL_TOKEN and reaches curl on stdin, so it
# never appears in a process's arguments, and teamId=$VERCEL_ORG_ID is added
# to the path. Prints the response body and exits 0 for a 2xx answer, 4 for
# a 404, and 1 for anything else, with the body on stderr.
# docs/projects/installer/readme.md § 2.10 is the design.

set -euo pipefail

[ $# -eq 2 ] || {
  echo "usage: vercel-api.sh <method> <path>" >&2
  exit 64
}
method="$1"
path="$2"
case "$path" in
  *\?*) url="https://api.vercel.com$path&teamId=$VERCEL_ORG_ID" ;;
  *) url="https://api.vercel.com$path?teamId=$VERCEL_ORG_ID" ;;
esac
# A time limit, so a request that hangs cannot stretch the workflow's
# three-minute waits while the job holds the site concurrency group.
args=(-sS --proto '=https' --max-time 30 -H @- -X "$method" -w '\n%{http_code}')
# The endpoints the workflow posts to take no body, as the CLI sends them.
[ "$method" = GET ] || args+=(-H 'Content-Type: application/json' --data '{}')

response="$(printf 'Authorization: Bearer %s\n' "$VERCEL_TOKEN" | curl "${args[@]}" "$url")" || {
  echo "vercel-api.sh: $method $path did not complete" >&2
  exit 1
}
status="${response##*$'\n'}"
body="${response%$'\n'*}"
case "$status" in
  2??)
    printf '%s\n' "$body"
    ;;
  404)
    printf '%s\n' "$body"
    exit 4
    ;;
  *)
    printf 'vercel-api.sh: %s %s answered HTTP %s: %s\n' "$method" "$path" "$status" "$body" >&2
    exit 1
    ;;
esac
