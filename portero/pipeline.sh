#!/usr/bin/env bash
# The intake pipeline, end to end, against a real lldap and a real SMTP server.
#
# What it refuses to mock: the directory (a mock of it was green while
# production 500'd) and the mail transport (the message asserted here is the one
# that left the process over a socket).
set -euo pipefail

ROOT=$(mktemp -d)
dump() {
  local f
  for f in lldap intake mint redeem sink; do
    echo "--- $f.log ---" >&2
    if [ -s "$ROOT/$f.log" ]; then cat "$ROOT/$f.log" >&2
    elif [ -e "$ROOT/$f.log" ]; then echo "(exists but empty)" >&2
    else echo "(no such file: $ROOT/$f.log)" >&2
    fi
  done
}
fail() { echo "FAIL: $*" >&2; dump; exit 1; }
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$ROOT"' EXIT

LDAP_PORT=33971
MINT_PORT=33981
REDEEM_PORT=33982
INTAKE_PORT=33983
SMTP_PORT=33987
ADMIN_PW=scratch-admin-password-2

mkdir -p "$ROOT/creds" "$ROOT/state" "$ROOT/intake" "$ROOT/mail"
cat > "$ROOT/cfg.toml" <<EOF
ldap_host = "127.0.0.1"
ldap_port = 33970
http_host = "127.0.0.1"
http_port = $LDAP_PORT
http_url = "http://127.0.0.1:$LDAP_PORT"
jwt_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ldap_base_dn = "dc=test,dc=local"
ldap_user_dn = "admin"
ldap_user_pass = "$ADMIN_PW"
database_url = "sqlite://$ROOT/users.db?mode=rwc"
key_seed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
EOF

head -c 48 /dev/urandom | base64 | tr -d '\n' > "$ROOT/creds/invite_key"
printf '%s' "$ADMIN_PW" > "$ROOT/creds/admin_password"
printf '%s' "$ADMIN_PW" > "$ROOT/creds/redeem_password"
printf '%s' 'scratch-smtp-password' > "$ROOT/creds/smtp_password"

wait_for() {
  local url=$1 name=$2
  for _ in $(seq 1 90); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then return 0; fi
    sleep 1
  done
  fail "$name never came up at $url"
}

say() { printf '  %-50s %s\n' "$1" "$2"; }
expect() {
  local what=$1 want=$2 got=$3
  [ "$want" = "$got" ] || fail "$what: expected $want, got $got"
  say "$what" "$got OK"
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
admin() { curl -s -H 'Remote-User: admin' -H 'Remote-Groups: portero-admin' "$@"; }
admin_code() {
  curl -s -o /dev/null -w '%{http_code}' \
    -H 'Remote-User: admin' -H 'Remote-Groups: portero-admin' "$@"
}
mail_count() { ls "$ROOT/mail" | wc -l | tr -d ' '; }
sql() { sqlite3 "$ROOT/intake/intake.db" "$1"; }

lldap run --config-file "$ROOT/cfg.toml" > "$ROOT/lldap.log" 2>&1 &
python3 "$SRC_TESTS/fakesmtp.py" "$SMTP_PORT" "$ROOT/mail" > "$ROOT/sink.log" 2>&1 &
wait_for "http://127.0.0.1:$LDAP_PORT" lldap

TOKEN=$(curl -fsS "http://127.0.0.1:$LDAP_PORT/auth/simple/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" \
  | sed -E 's/.*"token":"([^"]*)".*/\1/')
curl -fsS "http://127.0.0.1:$LDAP_PORT/api/graphql" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"mutation($n:String!){createGroup(name:$n){id}}","variables":{"n":"site-files-access"}}' \
  > /dev/null

export PORTERO_LLDAP_URL="http://127.0.0.1:$LDAP_PORT"
export PORTERO_GRANTABLE_GROUPS=site-files-access
export PORTERO_RESPONSE_FLOOR=0.02
export PORTERO_REDEEM_USER=admin
export PORTERO_SET_PASSWORD_BIN=lldap_set_password
export PORTERO_INTAKE_DB="$ROOT/intake/intake.db"
export PORTERO_INTAKE_CAP=3
export PORTERO_SMTP_HOST=127.0.0.1
export PORTERO_SMTP_PORT=$SMTP_PORT
export PORTERO_SMTP_STARTTLS=0
export PORTERO_SMTP_USER=scratch-smtp-user
export PORTERO_SMTP_SENDER="kelliher.info <auth@kelliher.info>"
export PORTERO_REDEEM_BASE="http://127.0.0.1:$REDEEM_PORT"
export AWS_EC2_METADATA_DISABLED=true
export PYTHONUNBUFFERED=1

# The intake unit is started with NO credentials directory at all. mint and
# redeem both refuse to start without one; this half must have nothing to hold.
env -u CREDENTIALS_DIRECTORY PORT=$INTAKE_PORT \
  python3 "$SRC/intake.py" > "$ROOT/intake.log" 2>&1 &

export CREDENTIALS_DIRECTORY="$ROOT/creds"
PORT=$MINT_PORT python3 "$SRC/mint.py" > "$ROOT/mint.log" 2>&1 &
STATE_DIRECTORY="$ROOT/state" PORT=$REDEEM_PORT python3 "$SRC/redeem.py" \
  > "$ROOT/redeem.log" 2>&1 &
wait_for "http://127.0.0.1:$INTAKE_PORT/healthz" intake
wait_for "http://127.0.0.1:$MINT_PORT/healthz" mint
wait_for "http://127.0.0.1:$REDEEM_PORT/healthz" redeem

echo "the intake pipeline, against a real directory and a real SMTP server:"
say "intake runs with no credentials directory" "OK"

# ── the public write ─────────────────────────────────────────────────────
expect "POST an address to intake" 202 \
  "$(code -X POST "http://127.0.0.1:$INTAKE_PORT/intake" -d 'email=dad@example.com')"
expect "one row landed" 1 "$(sql 'SELECT COUNT(*) FROM intake')"
expect "nothing was mailed by the public half" 0 "$(mail_count)"

GOOD=$(curl -s -X POST "http://127.0.0.1:$INTAKE_PORT/intake" -d 'email=two@example.com')
DUPE=$(curl -s -X POST "http://127.0.0.1:$INTAKE_PORT/intake" -d 'email=two@example.com')
JUNK=$(curl -s -X POST "http://127.0.0.1:$INTAKE_PORT/intake" -d 'email=not-an-email')
[ "$GOOD" = "$DUPE" ] || fail "a duplicate renders differently from a new address"
[ "$GOOD" = "$JUNK" ] || fail "a malformed address renders differently"
say "new, duplicate and malformed are byte-identical" "OK"

# the cap, enforced by the schema and invisible to the caller
curl -s -X POST "http://127.0.0.1:$INTAKE_PORT/intake" -d 'email=three@example.com' > /dev/null
FULL=$(curl -s -X POST "http://127.0.0.1:$INTAKE_PORT/intake" -d 'email=four@example.com')
[ "$GOOD" = "$FULL" ] || fail "a full table renders differently"
expect "the cap held at PORTERO_INTAKE_CAP" 3 "$(sql 'SELECT COUNT(*) FROM intake')"
say "a full table is indistinguishable from an accepted one" "OK"

# ── the authenticated read ───────────────────────────────────────────────
expect "listing requires authentication" 401 \
  "$(code "http://127.0.0.1:$MINT_PORT/intake")"
expect "listing requires the group" 403 \
  "$(curl -s -o /dev/null -w '%{http_code}' -H 'Remote-User: admin' \
      -H 'Remote-Groups: files-admin' "http://127.0.0.1:$MINT_PORT/intake")"
admin "http://127.0.0.1:$MINT_PORT/intake" > "$ROOT/list.json"
grep -q 'dad@example.com' "$ROOT/list.json" || fail "the listing omits the row"
say "mint lists the pending rows" "OK"
RID=$(python3 -c "
import json
rows = json.load(open('$ROOT/list.json'))['rows']
print([r['id'] for r in rows if r['email'] == 'dad@example.com'][0])")

# ── approve, which creates the account and mails the link ────────────────
admin -X POST "http://127.0.0.1:$MINT_PORT/intake/$RID/approve" \
  -H 'Content-Type: application/json' \
  -d '{"username":"dad","site_access_groups":["site-files-access"],"ttl_seconds":3600}' \
  > "$ROOT/approve.json"
grep -q '"mailed": *true' "$ROOT/approve.json" || fail "approve did not mail: $(cat "$ROOT/approve.json")"
expect "one message reached the SMTP server" 1 "$(mail_count)"

MSG="$ROOT/mail/msg-1.txt"
grep -q 'ENVELOPE-TO <dad@example.com>' "$MSG" || fail "wrong envelope recipient: $(head -2 "$MSG")"
grep -q 'ENVELOPE-FROM <auth@kelliher.info>' "$MSG" || fail "wrong envelope sender"
say "the envelope names the address from the ROW" "OK"

# Parsed the way a mail client parses it. A 130-character link pushes the body
# past 78 columns, so the transport encodes it quoted-printable with a soft
# line break mid-token: grepping the raw message yields half a token and a
# 404 that looks like a signing bug.
link() {
  python3 - "$1" <<'PY'
import email, email.policy, re, sys
raw = open(sys.argv[1], "rb").read().split(b"---\n", 1)[1]
msg = email.message_from_bytes(raw, policy=email.policy.default)
found = re.findall(r"http://127\.0\.0\.1:\d+/i/[A-Za-z0-9_.-]+",
                   msg.get_content())
print(found[0] if found else "")
PY
}
URL=$(link "$MSG")
test -n "$URL" || fail "no invite link in the delivered message"
TOK=${URL##*/i/}
say "the delivered message carries the link" "OK"

DAD_GROUPS=$(curl -fsS "http://127.0.0.1:$LDAP_PORT/api/graphql" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"{user(userId:\"dad\"){groups{displayName}}}"}')
case "$DAD_GROUPS" in
  *site-files-access*) say "the approved account holds site-files-access" "OK" ;;
  *) fail "group not granted: $DAD_GROUPS" ;;
esac

login() {
  curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$LDAP_PORT/auth/simple/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"dad\",\"password\":\"$1\"}"
}
expect "login before redeeming the mailed link" 401 "$(login 'MailedToDad-9912')"

# ── send by id: the same link, no token in any request line ─────────────
admin -X POST "http://127.0.0.1:$MINT_PORT/intake/$RID/send" > "$ROOT/send.json"
grep -q '"mailed": *true' "$ROOT/send.json" || fail "send by id did not mail"
expect "a second message arrived" 2 "$(mail_count)"
URL2=$(link "$ROOT/mail/msg-2.txt")
[ "$URL" = "$URL2" ] || fail "a resend minted a SECOND live link"
say "a resend carries the one live link, not another" "OK"

# ── tampering with the row the public unit can write ────────────────────
sqlite3 "$ROOT/intake/intake.db" \
  "UPDATE intake SET email='attacker@example.com' WHERE id=$RID"
expect "send refuses a row whose recipient was rewritten" 409 \
  "$(admin_code -X POST "http://127.0.0.1:$MINT_PORT/intake/$RID/send")"
expect "and mailed nothing" 2 "$(mail_count)"
sqlite3 "$ROOT/intake/intake.db" \
  "UPDATE intake SET email='dad@example.com' WHERE id=$RID"

sqlite3 "$ROOT/intake/intake.db" \
  "INSERT INTO intake (email, received_at, state, username, nonce, expires_at, mac)
   VALUES ('attacker@example.com', 0, 'approved', 'admin', 'deadbeef', 2000000000, 'forged')"
FORGED=$(sql "SELECT id FROM intake WHERE email='attacker@example.com'")
expect "send refuses a row forged wholesale" 409 \
  "$(admin_code -X POST "http://127.0.0.1:$MINT_PORT/intake/$FORGED/send")"
expect "still nothing mailed" 2 "$(mail_count)"

# ── the mailed link redeems, once ────────────────────────────────────────
expect "GET the mailed link" 200 "$(code "$URL")"
expect "POST the chosen password" 200 \
  "$(code -X POST "$URL" -d 'password=MailedToDad-9912' -d 'confirm=MailedToDad-9912')"
expect "login after redeeming" 200 "$(login 'MailedToDad-9912')"
expect "replay the mailed link" 404 "$(code "$URL")"

# ── a duplicate address is lldap's constraint, mapped to a status ────────
# Real lldap, real constraint: it answers a GraphQL error carrying
# "UNIQUE constraint failed: users.lowercase_email", which reached an operator
# as an uncaught 500 on the box before this was handled.
BEFORE_ROWS=$(sql "SELECT COUNT(*) || ':' || SUM(state='approved') FROM intake")
expect "a second account for one address is 409" 409 \
  "$(admin_code -X POST "http://127.0.0.1:$MINT_PORT/invites" \
      -H 'Content-Type: application/json' \
      -d '{"username":"dadtwo","email":"dad@example.com","ttl_seconds":3600}')"
expect "the intake table did not move" "$BEFORE_ROWS" \
  "$(sql "SELECT COUNT(*) || ':' || SUM(state='approved') FROM intake")"

# ── a GET flood must not spend the endpoint, and must not spend a nonce ──
admin -X POST "http://127.0.0.1:$MINT_PORT/invites" \
  -H 'Content-Type: application/json' \
  -d '{"username":"mum","email":"mum@example.com","ttl_seconds":3600}' \
  > "$ROOT/invite2.json"
URL3=$(python3 -c "import json;print(json.load(open('$ROOT/invite2.json'))['url'])")
for _ in $(seq 1 40); do curl -s -o /dev/null "$URL3"; done
say "40 scanner GETs on one link" "sent"
expect "the link still renders its form" 200 "$(code "$URL3")"
expect "and still redeems after the flood" 200 \
  "$(code -X POST "$URL3" -d 'password=ChosenByMum-4471' -d 'confirm=ChosenByMum-4471')"

# ── no token in any log ──────────────────────────────────────────────────
if grep -q "$TOK" "$ROOT/mint.log" "$ROOT/redeem.log" "$ROOT/intake.log" "$ROOT/lldap.log"; then
  fail "the mailed token appears in a log"
fi
say "the mailed token is in no log" "OK"
if grep -qE 'dad@example.com' "$ROOT/intake.log"; then
  fail "the intake unit logged the submitted address"
fi
say "the intake unit logged no address" "OK"

echo
echo "intake writes, mint decides and mails, the link redeems once."
