#!/usr/bin/env bash
#
# Prints the ID of the deployment a domain's alias points to, for the site
# workflow to roll back to:
#
#   serving-deployment.sh <domain>
#
# Prints an empty line when the domain has no alias yet, as before its first
# promotion, which is the one case with nothing to roll back to. Any other
# answer without a deployment ID fails, so a failed promotion never stays
# live for want of a rollback target. The ID goes into later API paths, so
# anything but an ID fails too. docs/projects/installer/readme.md § 2.10 is
# the design.

set -euo pipefail

[ $# -eq 1 ] || {
  echo "usage: serving-deployment.sh <domain>" >&2
  exit 64
}
domain="$1"

set +e
alias="$("$(dirname "$0")/vercel-api.sh" GET "/v4/aliases/$domain")"
status=$?
set -e
case "$status" in
  0) ;;
  4)
    echo
    exit 0
    ;;
  *)
    echo "serving-deployment.sh: could not read which deployment $domain serves" >&2
    exit 1
    ;;
esac
deployment="$(printf '%s\n' "$alias" | jq -r '.deploymentId // empty' 2>/dev/null)" || deployment=""
if ! [[ "$deployment" =~ ^dpl_[A-Za-z0-9]+$ ]]; then
  echo "serving-deployment.sh: the alias of $domain names ${deployment:-no deployment}, not a deployment ID" >&2
  exit 1
fi
printf '%s\n' "$deployment"
