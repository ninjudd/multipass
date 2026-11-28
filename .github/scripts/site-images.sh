#!/usr/bin/env bash
#
# Renders the website's images from the logo's SVG with headless Chrome:
#
#   site/og.png                1200x630, the link preview
#   site/apple-touch-icon.png  180x180, the home-screen icon
#   site/favicon.png           64x64, the tab icon for browsers without SVG icons
#
# Run it on a Mac with Google Chrome after changing the logo, and commit the
# images it writes. site/index.html draws the same marks inline, so change
# them there too. The favicon uses two cards rather than three, because at
# 16 pixels the third blurs into the second.
#
#   .github/scripts/site-images.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BG='#fbfaf7'
FG='#1d1c1a'
MUTED='#5f5c55'
ACCENT='#1f5f8b'

# Three offset cards, the store's small folder of files, with a keyhole in
# the front one.
mark() {
  cat <<EOF
<svg width="$1" height="$1" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <rect x="20" y="5" width="34" height="40" rx="6" fill="$ACCENT" opacity="0.3"/>
  <rect x="15" y="11" width="34" height="40" rx="6" fill="$ACCENT" opacity="0.6"/>
  <rect x="10" y="18" width="34" height="40" rx="6" fill="$FG"/>
  <circle cx="27" cy="34" r="4.6" fill="$BG"/>
  <rect x="25" y="36" width="4" height="10" rx="1.2" fill="$BG"/>
</svg>
EOF
}

favicon_mark() {
  cat <<EOF
<svg width="$1" height="$1" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
  <rect x="19" y="6" width="38" height="44" rx="7" fill="$ACCENT" opacity="0.55"/>
  <rect x="7" y="14" width="38" height="44" rx="7" fill="$FG"/>
  <circle cx="26" cy="32" r="5.4" fill="$BG"/>
  <rect x="23.6" y="34.5" width="4.8" height="11.5" rx="1.4" fill="$BG"/>
</svg>
EOF
}

# render <name> <width> <height> <body html> <page background>
render() {
  local name="$1" width="$2" height="$3" body="$4" background="$5" out
  out="$ROOT/site/$name.png"
  printf '<!doctype html><meta charset="utf-8"><style>html,body{margin:0;width:%spx;height:%spx;overflow:hidden;background:%s}</style>%s' \
    "$width" "$height" "$background" "$body" >"$WORK/$name.html"
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --default-background-color=00000000 --window-size="$width,$height" \
    --screenshot="$out" "file://$WORK/$name.html" >/dev/null 2>&1
  [ "$(sips -g pixelWidth -g pixelHeight "$out" | awk '/pixel/ { printf "%s ", $2 }')" = "$width $height " ] || {
    echo "site-images.sh: $out is not ${width}x$height" >&2
    exit 1
  }
  echo "wrote site/$name.png (${width}x$height)"
}

render favicon 64 64 "$(favicon_mark 64)" transparent

render apple-touch-icon 180 180 \
  "<div style=\"display:flex;align-items:center;justify-content:center;width:180px;height:180px\">$(mark 140)</div>" "$BG"

render og 1200 630 "<div style=\"box-sizing:border-box;width:1200px;height:630px;padding:84px 96px;display:flex;align-items:center;gap:72px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:$FG\">
  $(mark 300)
  <div style=\"display:flex;flex-direction:column;gap:26px\">
    <div style=\"font-size:104px;font-weight:700;letter-spacing:-0.03em;line-height:1\">multipass</div>
    <div style=\"font-size:36px;line-height:1.3;color:$MUTED;max-width:640px\">A minimal password manager for the few secrets you never want on someone else's server.</div>
    <div style=\"font-size:30px;font-weight:600;color:$ACCENT\">getmultipass.dev</div>
  </div>
</div>" "$BG"
