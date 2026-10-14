#!/usr/bin/env bash
set -Eeuo pipefail

: "${PORTERO_SPOOL:?}" "${PORTERO_READER_GROUP:?}" "${PORTERO_WRITER_GROUP:?}"
CHATTR=${CHATTR:-chattr}
LSATTR=${LSATTR:-lsattr}
SYSTEMCTL=${SYSTEMCTL:-systemctl}

WANT_OWNER="root:$PORTERO_READER_GROUP"
WANT_MODE=660
WANT_ACL="user::rw-
group::r--
group:$PORTERO_WRITER_GROUP:-w-
mask::rw-
other::---"

say() { echo "$1 intake spool layout $2"; }

fail_closed() {
  "$SYSTEMCTL" stop --no-block gluck-portero-intake.service || say "<3>ERROR" "could not stop intake"
}

on_error() {
  trap - ERR
  say "<3>ERROR" "failed at: $BASH_COMMAND"
  "$CHATTR" +a -- "$PORTERO_SPOOL" 2>/dev/null || true
  fail_closed
}
trap on_error ERR

read_layout() {
  owner=$(stat -c %U:%G -- "$PORTERO_SPOOL")
  mode=$(stat -c %a -- "$PORTERO_SPOOL")
  acl=$(getfacl -cp -- "$PORTERO_SPOOL" | sed '/^$/d')
  flags=$("$LSATTR" -d -- "$PORTERO_SPOOL" | cut -d' ' -f1)
  case "$flags" in *a*) appendonly=yes ;; *) appendonly=no ;; esac
}

differs() {
  local d=""
  [ "$owner" = "$WANT_OWNER" ] || d="$d owner=$owner"
  [ "$mode" = "$WANT_MODE" ] || d="$d mode=$mode"
  [ "$acl" = "$WANT_ACL" ] || d="$d acl=$(echo "$acl" | paste -sd, -)"
  [ "$appendonly" = yes ] || d="$d append_only=no"
  echo "${d# }"
}

if [ ! -e "$PORTERO_SPOOL" ]; then
  install -m 0600 -o root -g root /dev/null "$PORTERO_SPOOL"
fi

read_layout
before=$(differs)
if [ -z "$before" ]; then
  say "<6>INFO" "ok"
  exit 0
fi

"$CHATTR" -a -- "$PORTERO_SPOOL"
chown -- "$WANT_OWNER" "$PORTERO_SPOOL"
chmod -- "$WANT_MODE" "$PORTERO_SPOOL"
setfacl --set "u::rw-,g::r--,g:$PORTERO_WRITER_GROUP:-w-,m::rw-,o::---" -- "$PORTERO_SPOOL"
"$CHATTR" +a -- "$PORTERO_SPOOL"

read_layout
after=$(differs)
if [ -n "$after" ]; then
  say "<3>ERROR" "still wrong after repair: $after"
  fail_closed
  exit 1
fi
say "<4>WARNING" "repaired: $before"
