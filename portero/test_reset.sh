#!/usr/bin/env bash
# The reset runs the shipped script with a recording systemctl. What is under
# test is the script's own contract: the writer stops before the reader, both
# files are reset in one run, and BOTH UNITS COME BACK EVEN WHEN THE RESET
# FAILS, which is the half a by-hand reset gets wrong.
set -euo pipefail

SCRIPT=${1:?path to reset-intake.sh}
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

printf '#!%s\necho "$*" >> "$CALLS"\n' "$(command -v bash)" > "$ROOT/systemctl"
chmod +x "$ROOT/systemctl"

fail() { echo "FAIL: $*" >&2; exit 1; }
say() { printf '  %-52s %s\n' "$1" "OK"; }

echo "the reset, against its own contract:"

export CALLS="$ROOT/calls" SYSTEMCTL="$ROOT/systemctl"
export PORTERO_SPOOL="$ROOT/spool.jsonl" PORTERO_OFFSET="$ROOT/spool.offset"
printf '{"email":"a@x.com"}\n{"email":"b@x.com"}\n' > "$PORTERO_SPOOL"
printf '42' > "$PORTERO_OFFSET"

bash "$SCRIPT" > "$ROOT/out" 2>&1 || fail "reset exited non-zero: $(cat "$ROOT/out")"
[ "$(stat -c %s "$PORTERO_SPOOL")" = 0 ] || fail "spool not emptied"
say "the spool is empty"
[ ! -e "$PORTERO_OFFSET" ] || fail "offset survived"
say "the offset is gone in the same run"

expected="stop gluck-portero-intake.service
stop gluck-portero-mint.service
start gluck-portero-mint.service gluck-portero-intake.service"
[ "$(cat "$CALLS")" = "$expected" ] || fail "wrong order: $(tr '\n' '|' < "$CALLS")"
say "writer stopped first, both started last"

# The failure path. A directory where the spool should be makes truncate fail,
# and the units must still come back.
: > "$CALLS"
rm -f "$PORTERO_SPOOL"
mkdir "$PORTERO_SPOOL"
if bash "$SCRIPT" > "$ROOT/out" 2>&1; then
  fail "a reset that could not truncate reported success"
fi
say "a failed truncate fails the unit"
tail -1 "$CALLS" | grep -qx "start gluck-portero-mint.service gluck-portero-intake.service" \
  || fail "units left stopped after a failed reset: $(tr '\n' '|' < "$CALLS")"
say "and both units are started anyway"

echo
echo "one run stops, empties, removes and restarts, and restarts on failure."
