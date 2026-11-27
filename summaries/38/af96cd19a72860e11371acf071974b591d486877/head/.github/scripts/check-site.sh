#!/usr/bin/env bash
#
# Guards the website's install.sh redirects, the one change to site/ that
# could hurt someone: a redirect that hands `curl | bash` another script.
#
#   check-site.sh static [<site-dir>]   check <site-dir>/vercel.json, default site
#   check-site.sh live <url>            check the deployed redirects with curl
#   check-site.sh cache <value>         check one Cache-Control value, as live does
#
# A URL passes when it starts with the repository's releases URL and holds no
# dot segment and no percent sign, because curl collapses /releases/../../
# before it sends the request, so such a URL passes a prefix check and still
# leaves the repository. The real URLs hold no percent-encoding at all, so
# refusing every % also refuses %2e, %252e, and %2f without naming each. The
# design is docs/projects/installer/readme.md § 2.10.

set -euo pipefail

RELEASES="https://github.com/ninjudd/multipass/releases/"
SITE="https://getmultipass.dev/"
# vercel.json keys a static site of redirects needs. Anything else, such as
# rewrites, routes, a build command, a framework, or functions, could serve
# or run something other than these redirects.
ALLOWED_KEYS='["$schema", "redirects", "headers", "cleanUrls", "trailingSlash"]'
PROBLEMS=0

problem() {
  printf 'check-site.sh: %s\n' "$*" >&2
  PROBLEMS=$((PROBLEMS + 1))
}

under_releases() {
  case "$1" in "$RELEASES"*) ;; *) return 1 ;; esac
  case "$1/" in */../* | */./* | *%* | *\\*) return 1 ;; esac
}

# A destination on this site itself, absolute or relative. A
# protocol-relative URL such as //host/ names another host.
on_site() {
  case "$1" in
    "$SITE"*) ;;
    //* | /\\*) return 1 ;;
    /*) ;;
    *) return 1 ;;
  esac
}

check_static() {
  local dir="${1:-site}" config source destination keys redirects
  config="$dir/vercel.json"
  [ -f "$config" ] || {
    problem "$config does not exist"
    return
  }
  jq empty "$config" 2>/dev/null || {
    problem "$config is not valid JSON"
    return
  }
  # A shape jq cannot read as below would make it fail and leave the keys or
  # redirects unchecked, so the shape is checked first, and each jq runs on
  # its own rather than in a process substitution, which hides its status.
  jq -e 'type == "object" and ((.redirects // []) | type == "array" and
    all(.[]; type == "object" and ((.source // "") | type == "string") and ((.destination // "") | type == "string")))' \
    "$config" >/dev/null 2>&1 || {
    problem "$config must be an object whose redirects are a list of objects with a text source and destination"
    return
  }
  keys="$(jq -r --argjson allowed "$ALLOWED_KEYS" 'keys[] | select(. as $k | $allowed | index($k) | not)' "$config")" || {
    problem "could not read the keys of $config"
    return
  }
  redirects="$(jq -r '.redirects // [] | .[] | [(.source // ""), (.destination // "")] | @tsv' "$config")" || {
    problem "could not read the redirects of $config"
    return
  }
  while IFS= read -r key; do
    [ -z "$key" ] || problem "$config sets $key, which a site of redirects does not need"
  done <<<"$keys"
  while IFS=$'\t' read -r source destination; do
    [ -n "$redirects" ] || break
    case "$source" in
      *install.sh)
        under_releases "$destination" ||
          problem "the redirect from $source goes to $destination, outside $RELEASES"
        ;;
      *)
        on_site "$destination" ||
          problem "the redirect from $source goes to $destination, off this site"
        ;;
    esac
  done <<<"$redirects"
  # The site serves only its page, so a redirect to anywhere on it, from a
  # source that matches an install.sh path without ending in that text,
  # still reaches nothing a shell would run, and no file can be a copy of
  # the installer. The CLI never uploads .vercel, which `vercel link` writes.
  while IFS= read -r file; do
    problem "${dir%/}/${file#./} is not index.html or vercel.json, the only files the site serves; a redirect could hand it to curl | bash"
  done < <(cd "$dir" && find . -path ./.vercel -prune -o ! -type d ! -path ./index.html ! -path ./vercel.json -print)
}

# Checks that GET <url><path> answers with a temporary redirect to exactly
# <expected>, under the releases URL, and that no cache may keep it.
check_redirect() {
  local url="$1" expected="$2" headers status location cache
  headers="$(curl -sS --proto '=https' -o /dev/null -D - "$url" | tr -d '\r')" || {
    problem "could not reach $url"
    return
  }
  status="$(printf '%s\n' "$headers" | awk 'NR == 1 { print $2 }')"
  location="$(printf '%s\n' "$headers" | awk 'tolower($1) == "location:" { print $2; exit }')"
  cache="$(printf '%s\n' "$headers" | awk 'tolower($1) == "cache-control:" { $1 = ""; print; exit }')"
  case "$status" in
    302 | 307) ;;
    *) problem "$url answered $status, not a temporary redirect" ;;
  esac
  under_releases "$location" || problem "$url redirects to ${location:-nothing}, outside $RELEASES"
  [ "$location" = "$expected" ] || problem "$url redirects to ${location:-nothing}, not $expected"
  cache_revalidates "$cache" ||
    problem "$url sends cache-control:${cache:- nothing}, which lets a cache serve the redirect without asking again"
}

# True when a Cache-Control value keeps every cache from serving a stored
# redirect without asking the site again, so none can hand out an old target:
# no-store, no-cache, or max-age=0 with must-revalidate. Vercel sends its
# default, public, max-age=0, must-revalidate, on redirects whatever
# vercel.json's headers say. A positive s-maxage fails, because a shared
# cache uses it in place of max-age.
cache_revalidates() {
  local directive directives max_age="" s_maxage="" must=""
  IFS=, read -ra directives <<<"$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d ' \t')"
  for directive in "${directives[@]}"; do
    case "$directive" in
      no-store | no-cache) return 0 ;;
      max-age=*) max_age="${directive#max-age=}" ;;
      s-maxage=*) s_maxage="${directive#s-maxage=}" ;;
      must-revalidate) must=1 ;;
    esac
  done
  [ "$max_age" = 0 ] && [ -n "$must" ] && { [ -z "$s_maxage" ] || [ "$s_maxage" = 0 ]; }
}

check_live() {
  local base="${1%/}"
  [ -n "$base" ] || {
    echo "usage: check-site.sh live <url>" >&2
    exit 64
  }
  check_redirect "$base/install.sh" "${RELEASES}latest/download/install.sh"
  check_redirect "$base/v0.0.0/install.sh" "${RELEASES}download/v0.0.0/install.sh"
}

case "${1:-}" in
  static) check_static "${2:-site}" ;;
  live) check_live "${2:-}" ;;
  cache)
    cache_revalidates "${2:-}" || exit 1
    exit 0
    ;;
  *)
    echo "usage: check-site.sh static [<site-dir>] | live <url> | cache <value>" >&2
    exit 64
    ;;
esac

if [ "$PROBLEMS" -gt 0 ]; then
  exit 1
fi
echo "check-site.sh: the install.sh redirects stay in $RELEASES"
