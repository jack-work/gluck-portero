#!/usr/bin/env bash
# The whole invite loop against a REAL lldap. No mocks.
#
# This exists because mocks lied twice in one evening. One returned {"user":
# None} where lldap raises a GraphQL error, and the unit suites were green while
# the mint endpoint 500'd on every call. A mock that encodes your assumption
# cannot falsify it.
#
# The two properties the whole design rests on are asserted here against a live
# directory, so the build fails if either breaks:
#
#   zero credential  a minted account cannot log in until the invite is redeemed
#   single use       the link works exactly once
set -euo pipefail

ROOT=$(mktemp -d)
dump() {
  local f
  for f in lldap mint redeem; do
    echo "--- $f.log ---" >&2
    if [ -s "$ROOT/$f.log" ]; then
      cat "$ROOT/$f.log" >&2
    elif [ -e "$ROOT/$f.log" ]; then
      echo "(exists but empty)" >&2
    else
      echo "(no such file: $ROOT/$f.log)" >&2
    fi
  done
}
fail() { echo "FAIL: $*" >&2; dump; exit 1; }
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$ROOT"' EXIT

LDAP_PORT=33871
MINT_PORT=33881
REDEEM_PORT=33882
ADMIN_PW=scratch-admin-password-1

mkdir -p "$ROOT/creds" "$ROOT/state"
cat > "$ROOT/cfg.toml" <<EOF
ldap_host = "127.0.0.1"
ldap_port = 33870
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

wait_for() {
  local url=$1 name=$2
  for _ in $(seq 1 90); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "FAIL: $name never came up at $url" >&2
  exit 1
}

say() { printf '  %-44s %s\n' "$1" "$2"; }
expect() {
  local what=$1 want=$2 got=$3
  if [ "$want" != "$got" ]; then
    fail "$what: expected $want, got $got"
  fi
  say "$what" "$got OK"
}

lldap run --config-file "$ROOT/cfg.toml" > "$ROOT/lldap.log" 2>&1 &
wait_for "http://127.0.0.1:$LDAP_PORT" lldap

TOKEN=$(curl -fsS "http://127.0.0.1:$LDAP_PORT/auth/simple/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" \
  | sed -E 's/.*"token":"([^"]*)".*/\1/')

# The site-access group the invite will grant.
curl -fsS "http://127.0.0.1:$LDAP_PORT/api/graphql" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"mutation($n:String!){createGroup(name:$n){id}}","variables":{"n":"site-files-access"}}' \
  > /dev/null

export CREDENTIALS_DIRECTORY="$ROOT/creds"
export PORTERO_LLDAP_URL="http://127.0.0.1:$LDAP_PORT"
export PORTERO_GRANTABLE_GROUPS=site-files-access
export PORTERO_RESPONSE_FLOOR=0.02
export PORTERO_REDEEM_USER=admin
export PORTERO_SET_PASSWORD_BIN=lldap_set_password
export AWS_EC2_METADATA_DISABLED=true
# Unbuffered, or a crash's traceback sits in a buffer that never flushes and the
# log file is empty exactly when it matters.
export PYTHONUNBUFFERED=1

PORT=$MINT_PORT python3 "$SRC/mint.py" > "$ROOT/mint.log" 2>&1 &
STATE_DIRECTORY="$ROOT/state" PORT=$REDEEM_PORT python3 "$SRC/redeem.py" > "$ROOT/redeem.log" 2>&1 &
wait_for "http://127.0.0.1:$MINT_PORT/healthz" mint
wait_for "http://127.0.0.1:$REDEEM_PORT/healthz" redeem

echo "the loop, against a real directory:"

# ── mint ─────────────────────────────────────────────────────────────────
curl -fsS -X POST "http://127.0.0.1:$MINT_PORT/invites" \
  -H 'Remote-User: admin' -H 'Remote-Groups: portero-admin' \
  -H 'Content-Type: application/json' \
  -d '{"username":"dad","email":"dad@example.com",
       "site_access_groups":["site-files-access"],"ttl_seconds":3600}' \
  > "$ROOT/invite.json"

URL=$(python3 -c "import json;print(json.load(open('$ROOT/invite.json'))['url'])")
TOK=${URL##*/i/}
test -n "$TOK" || { echo "FAIL: mint returned no token" >&2; exit 1; }
say "mint created the account and a link" "OK"

# NOT named GROUPS: that is a bash builtin array of the current user's group
# ids, so the assignment is silently discarded and the variable reads back as
# a plausible-looking number. It was 100 in the nix sandbox and 1000 on a
# laptop, because those were the real gids.
DAD_GROUPS=$(curl -fsS "http://127.0.0.1:$LDAP_PORT/api/graphql" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"{user(userId:\"dad\"){groups{displayName}}}"}')
case "$DAD_GROUPS" in
  *site-files-access*) say "account holds site-files-access" "OK" ;;
  *) echo "FAIL: group not granted: $DAD_GROUPS" >&2; exit 1 ;;
esac

login() {
  curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$LDAP_PORT/auth/simple/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"dad\",\"password\":\"$1\"}"
}

# ── ZERO CREDENTIAL ──────────────────────────────────────────────────────
expect "login before redeeming, blank password"  401 "$(login '')"
expect "login before redeeming, guessed password" 401 "$(login 'ChosenByDad-77123')"

# ── the form ─────────────────────────────────────────────────────────────
expect "GET the link" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$REDEEM_PORT/i/$TOK")"
curl -s "http://127.0.0.1:$REDEEM_PORT/i/$TOK" | grep -q 'Set my password' \
  || { echo "FAIL: form did not render" >&2; exit 1; }
say "the form renders" "OK"

# a typo must NOT burn the link
expect "short password refused" 400 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$REDEEM_PORT/i/$TOK" \
      -d 'password=short' -d 'confirm=short')"
expect "link still usable after a typo" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$REDEEM_PORT/i/$TOK")"

# ── redeem ───────────────────────────────────────────────────────────────
expect "POST the chosen password" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$REDEEM_PORT/i/$TOK" \
      -d 'password=ChosenByDad-77123' -d 'confirm=ChosenByDad-77123')"
expect "login after redeeming" 200 "$(login 'ChosenByDad-77123')"
expect "a wrong password is still wrong" 401 "$(login 'not-it')"

# ── SINGLE USE ───────────────────────────────────────────────────────────
expect "replay the same link" 404 \
  "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$REDEEM_PORT/i/$TOK")"

# refusals must be indistinguishable
USED=$(curl -s "http://127.0.0.1:$REDEEM_PORT/i/$TOK")
BOGUS=$(curl -s "http://127.0.0.1:$REDEEM_PORT/i/not-a-real-token")
[ "$USED" = "$BOGUS" ] \
  || { echo "FAIL: used and invalid tokens render differently" >&2; exit 1; }
say "used and invalid are byte-identical" "OK"

case "$USED" in *dad*) echo "FAIL: refusal names the user" >&2; exit 1 ;; esac
say "refusal names no user" "OK"

# the token must never reach a log
if grep -q "$TOK" "$ROOT/redeem.log" "$ROOT/mint.log"; then
  echo "FAIL: the token appears in a log" >&2
  exit 1
fi
say "the token is in no log" "OK"

echo
echo "zero credential and single use both hold against a real lldap."
