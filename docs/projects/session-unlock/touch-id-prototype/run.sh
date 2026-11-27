#!/bin/bash
# Runs the session-unlock § 6.5 Touch ID test: three Touch ID requests, one
# attached to this terminal and two from detached processes, as the agent
# will be. Run it from Terminal on a Mac with Touch ID, and touch the sensor
# each time a sheet appears.
#
#   run.sh            the three requests
#   run.sh close      the closing-the-terminal test, from a setsid child as the
#                     agent runs, which needs you to close this terminal window
#                     within 15 seconds
#
# It builds the probe with rustc into the repository's target directory and
# writes the detached results beside it. It touches nothing else.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
out="$root/target/touch-id-prototype"
probe="$out/probe"
mkdir -p "$out"
rustc --edition 2024 -O "$here/probe.rs" -o "$probe"

wait_for() {
  local file=$1
  for _ in $(seq 1 150); do
    if [ -f "$file" ] && grep -q '^done$' "$file"; then
      cat "$file"
      return 0
    fi
    sleep 0.5
  done
  echo "no result in $file after 75 seconds"
  return 1
}

detached() {
  local how=$1 reason=$2 file="$out/evaluate-$1.txt"
  rm -f "$file"
  "$probe" spawn "$how" evaluate "$file" "$reason"
  wait_for "$file"
}

if [ "${1:-}" = close ]; then
  file="$out/evaluate-close.txt"
  rm -f "$file"
  PROBE_DELAY=15 "$probe" spawn setsid evaluate "$file" "test after closing the terminal"
  echo
  echo "Close this terminal window now. In 15 seconds a sheet should ask to"
  echo "\"test after closing the terminal\". Touch the sensor, then open a new"
  echo "terminal and run:  cat $file"
  exit 0
fi

echo "== 1 of 3: attached to this terminal"
echo "A sheet should ask to \"test attached to the terminal\". Touch the sensor."
"$probe" evaluate "test attached to the terminal"
echo
echo "== 2 of 3: detached with setsid, in a session of its own"
echo "A sheet should ask to \"test from a detached session\". Touch the sensor."
detached setsid "test from a detached session"
echo
echo "== 3 of 3: detached in its own process group only"
echo "A sheet should ask to \"test from a detached process group\". Touch the sensor."
detached group "test from a detached process group"
