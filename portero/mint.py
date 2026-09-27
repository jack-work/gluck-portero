#!/usr/bin/env python3
"""The private half. It creates the account and hands back one link.

The account it creates is deliberately unusable: zero groups and no password.
Verified against lldap: createUser with no password succeeds, and that account
returns 401 for an empty password and for a guessed one. So there is no
temporary credential anywhere in this system, which is why no agent, no log and
no email can leak one.

Reached only through Authelia. Holds lldap_admin. Holds no invite state: the
token carries its own signed claim.
"""

import logging
import os
import re
import sys

import requests
from flask import Flask, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import invites

LLDAP_URL = os.environ.get("PORTERO_LLDAP_URL", "http://127.0.0.1:17170")
ADMIN_USER = os.environ.get("PORTERO_ADMIN_USER", "admin")
REQUIRED_GROUP = os.environ.get("PORTERO_REQUIRED_GROUP", "portero-admin")
REDEEM_BASE = os.environ.get("PORTERO_REDEEM_BASE", "https://invite.kelliher.info")
DEFAULT_TTL = int(os.environ.get("PORTERO_DEFAULT_TTL", str(72 * 3600)))
MAX_TTL = int(os.environ.get("PORTERO_MAX_TTL", str(14 * 24 * 3600)))

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Groups this endpoint is permitted to grant. An allowlist, not a pattern:
# mint holds lldap_admin, so without it a mint call could ask for lldap_admin.
GRANTABLE = [
    g for g in os.environ.get("PORTERO_GRANTABLE_GROUPS", "").replace(",", " ").split() if g
]

app = Flask(__name__)
log = logging.getLogger("portero-mint")


def credential(name):
    base = os.environ.get("CREDENTIALS_DIRECTORY")
    if not base:
        raise RuntimeError("no CREDENTIALS_DIRECTORY: refusing to start")
    with open(os.path.join(base, name), "r", encoding="utf-8") as fh:
        return fh.read().strip()


SIGNING_KEY = invites.load_key(
    os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "invite_key")
)
ADMIN_PASSWORD = credential("admin_password")


def caller():
    return request.headers.get("Remote-User", "")


def caller_groups():
    raw = request.headers.get("Remote-Groups", "")
    return [g.strip() for g in raw.split(",") if g.strip()]


def lldap_token():
    r = requests.post(
        f"{LLDAP_URL}/auth/simple/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["token"]


def gql(token, query, variables=None):
    r = requests.post(
        f"{LLDAP_URL}/api/graphql",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query, "variables": variables or {}},
        timeout=15,
    )
    r.raise_for_status()
    body = r.json()
    # lldap returns application/json 200 with an "errors" key on failure. The
    # existing lldap-bootstrap helper does not check this, which is how a failed
    # provisioning step looks identical to a successful one.
    if body.get("errors"):
        raise RuntimeError(f"graphql error: {body['errors']}")
    return body["data"]


def user_exists(token, username):
    data = gql(token, "query($id:String!){user(userId:$id){id}}", {"id": username})
    return data.get("user") is not None


def group_id(token, name):
    data = gql(token, "query{groups{id displayName}}")
    for g in data["groups"]:
        # lldap group matching is case-sensitive; compare exactly.
        if g["displayName"] == name:
            return g["id"]
    return None


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.get("/invites/whoami")
def whoami():
    return jsonify(user=caller(), groups=caller_groups())


@app.post("/invites")
def create_invite():
    if not caller():
        return jsonify(error="unauthenticated"), 401
    if REQUIRED_GROUP not in caller_groups():
        return jsonify(error=f"requires group {REQUIRED_GROUP}"), 403

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    email = (body.get("email") or "").strip()
    display_name = (body.get("display_name") or "").strip()
    ttl = int(body.get("ttl_seconds") or DEFAULT_TTL)
    groups = body.get("site_access_groups") or []

    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="invalid username (want ^[a-z][a-z0-9_-]{2,31}$)"), 400
    if not EMAIL_RE.fullmatch(email):
        return jsonify(error="invalid email"), 400
    if not 60 <= ttl <= MAX_TTL:
        return jsonify(error=f"ttl_seconds must be between 60 and {MAX_TTL}"), 400
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        return jsonify(error="site_access_groups must be a list of strings"), 400
    refused = [g for g in groups if g not in GRANTABLE]
    if refused:
        return jsonify(error=f"not grantable here: {refused}",
                       grantable=GRANTABLE), 400

    token = lldap_token()
    if user_exists(token, username):
        return jsonify(error="user already exists"), 409

    # Resolve every group BEFORE creating anything, so a typo does not leave a
    # half-provisioned account behind. Unknown group names are not validated by
    # Authelia and never match, so a silent miss here would be invisible later.
    group_ids = {}
    for g in groups:
        gid = group_id(token, g)
        if gid is None:
            return jsonify(error=f"group does not exist in the directory: {g}"), 400
        group_ids[g] = gid

    # No password field. The account exists and cannot be used.
    gql(
        token,
        "mutation($u:CreateUserInput!){createUser(user:$u){id}}",
        {"u": {"id": username, "email": email,
               "displayName": display_name or username}},
    )

    # Granting site access at mint time is safe BECAUSE the account has no
    # credential, and it dodges Authelia's profile-refresh window: the invitee's
    # first session is created after the grant, so it is born holding the group.
    # Granting after he already has a session can take until the next refresh.
    for g, gid in group_ids.items():
        gql(
            token,
            "mutation($u:String!,$g:Int!){addUserToGroup(userId:$u,groupId:$g){ok}}",
            {"u": username, "g": gid},
        )

    invite, nonce, expires_at = invites.mint(SIGNING_KEY, username, ttl)
    log.info(
        "invite minted for %s by %s, groups %s, nonce %s, expires %s",
        username, caller(), sorted(group_ids), nonce, expires_at,
    )
    return (
        jsonify(
            username=username,
            url=f"{REDEEM_BASE}/i/{invite}",
            expires_at=expires_at,
            site_access_groups=sorted(group_ids),
            note=(
                "Send this link yourself. It works once. The account exists with "
                "no password until the invitee sets one, so there is no temporary "
                "credential for anyone to leak."
            ),
        ),
        201,
    )


@app.delete("/invites/<username>")
def revoke(username):
    """Revocation is deleting the account. A token naming a user that does not
    exist cannot be redeemed, because setting its password fails."""
    if not caller():
        return jsonify(error="unauthenticated"), 401
    if REQUIRED_GROUP not in caller_groups():
        return jsonify(error=f"requires group {REQUIRED_GROUP}"), 403
    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="invalid username"), 400

    token = lldap_token()
    if not user_exists(token, username):
        return jsonify(error="no such user"), 404
    gql(token, "mutation($id:String!){deleteUser(userId:$id){ok}}", {"id": username})
    log.info("account %s deleted by %s", username, caller())
    return jsonify(deleted=username), 200


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from waitress import serve
    port = int(os.environ.get("PORT", "9101"))
    serve(app, host="127.0.0.1", port=port, threads=4, ident=None)


if __name__ == "__main__":
    sys.exit(main())
