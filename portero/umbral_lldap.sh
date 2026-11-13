#!/usr/bin/env bash
set -euo pipefail

ROOT=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$ROOT"' EXIT
LDAP_PORT=${LDAP_PORT:-33971}
ADMIN_PW=scratch-admin-password-2

mkdir -p "$ROOT/creds" "$ROOT/state"
cat > "$ROOT/cfg.toml" <<CFG
ldap_host = "127.0.0.1"
ldap_port = $((LDAP_PORT - 1))
http_host = "127.0.0.1"
http_port = $LDAP_PORT
http_url = "http://127.0.0.1:$LDAP_PORT"
jwt_secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ldap_base_dn = "dc=test,dc=local"
ldap_user_dn = "admin"
ldap_user_pass = "$ADMIN_PW"
database_url = "sqlite://$ROOT/users.db?mode=rwc"
key_seed = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CFG
head -c 48 /dev/urandom | base64 | tr -d '\n' > "$ROOT/creds/invite_key"
printf '%s' "$ADMIN_PW" > "$ROOT/creds/admin_password"

lldap run --config-file "$ROOT/cfg.toml" > "$ROOT/lldap.log" 2>&1 &
for _ in $(seq 1 90); do
  curl -fsS -o /dev/null "http://127.0.0.1:$LDAP_PORT" 2>/dev/null && break
  sleep 1
done

export CREDENTIALS_DIRECTORY="$ROOT/creds"
export PORTERO_LLDAP_URL="http://127.0.0.1:$LDAP_PORT"
export PORTERO_GRANTABLE_GROUPS=friends
export PORTERO_UMBRAL=1
export PORTERO_UMBRAL_DB="$ROOT/state/umbral.db"
export PORTERO_INTAKE_DB="$ROOT/state/intake.db"
export PORTERO_INTAKE_SPOOL="$ROOT/state/none"
export PORTERO_INTAKE_OFFSET="$ROOT/state/offset"
export STATE_DIRECTORY="$ROOT/state"
export PYTHONUNBUFFERED=1
export UMBRAL_TEST_SET_PASSWORD="lldap_set_password"
python3 "${SRC_TESTS:-$(dirname "$0")}/test_umbral_lldap.py" || { cat "$ROOT/lldap.log" >&2; exit 1; }
