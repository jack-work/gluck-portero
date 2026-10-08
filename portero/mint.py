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
import threading
import time

import requests
from flask import Flask, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import invites
import mailer
from pending_admin import IntakeAdmin, mac_fields

LLDAP_URL = os.environ.get("PORTERO_LLDAP_URL", "http://127.0.0.1:17170")
ADMIN_USER = os.environ.get("PORTERO_ADMIN_USER", "admin")
REQUIRED_GROUP = os.environ.get("PORTERO_REQUIRED_GROUP", "portero-admin")
REDEEM_BASE = os.environ.get("PORTERO_REDEEM_BASE", "https://invite.kelliher.info")
DEFAULT_TTL = int(os.environ.get("PORTERO_DEFAULT_TTL", str(72 * 3600)))
MAX_TTL = int(os.environ.get("PORTERO_MAX_TTL", str(14 * 24 * 3600)))
INTAKE_DB = os.environ.get(
    "PORTERO_INTAKE_DB", "/var/lib/gluck-portero-intake/intake.db"
)
INTAKE_CAP = int(os.environ.get("PORTERO_INTAKE_CAP", "200"))

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


_intake = None
_intake_lock = threading.Lock()


def intake():
    global _intake
    with _intake_lock:
        if _intake is None:
            _intake = IntakeAdmin(INTAKE_DB, INTAKE_CAP)
        return _intake


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


def gql(token, query, variables=None, tolerate=()):
    """Run a GraphQL call. Raises on any error unless the message is tolerated.

    lldap answers HTTP 200 with an "errors" key on failure, so a body has to be
    inspected rather than a status code trusted. Failing loudly is the default;
    `tolerate` is for the narrow cases where an error IS the expected answer.
    """
    r = requests.post(
        f"{LLDAP_URL}/api/graphql",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query, "variables": variables or {}},
        timeout=15,
    )
    r.raise_for_status()
    body = r.json()
    errors = body.get("errors")
    if errors:
        messages = " ".join(str(e.get("message", "")) for e in errors)
        if tolerate and any(t in messages for t in tolerate):
            return None
        raise RuntimeError(f"graphql error: {errors}")
    return body["data"]


def user_exists(token, username):
    """True if the account exists.

    lldap reports an absent user as a GraphQL ERROR ("Entity not found"), not as
    a null field, so the absence has to be tolerated explicitly here. Everywhere
    else an error still fails loudly.
    """
    data = gql(
        token,
        "query($id:String!){user(userId:$id){id}}",
        {"id": username},
        tolerate=("Entity not found",),
    )
    return bool(data and data.get("user"))


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


def forbidden():
    if not caller():
        return jsonify(error="unauthenticated"), 401
    if REQUIRED_GROUP not in caller_groups():
        return jsonify(error=f"requires group {REQUIRED_GROUP}"), 403
    return None


def invalid(username, email, ttl, groups):
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
        return jsonify(error=f"not grantable here: {refused}", grantable=GRANTABLE), 400
    return None


def provision(username, email, display_name, ttl, groups):
    """Create the credential-less account, grant site access, mint one link."""
    token = lldap_token()
    if user_exists(token, username):
        return {"error": "user already exists"}, 409

    # Resolve every group BEFORE creating anything, so a typo does not leave a
    # half-provisioned account behind. Unknown group names are not validated by
    # Authelia and never match, so a silent miss here would be invisible later.
    group_ids = {}
    for g in groups:
        gid = group_id(token, g)
        if gid is None:
            return {"error": f"group does not exist in the directory: {g}"}, 400
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
        {
            "username": username,
            "url": f"{REDEEM_BASE}/i/{invite}",
            "nonce": nonce,
            "expires_at": expires_at,
            "site_access_groups": sorted(group_ids),
        },
        201,
    )


@app.post("/invites")
def create_invite():
    denied = forbidden()
    if denied:
        return denied

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    email = (body.get("email") or "").strip()
    display_name = (body.get("display_name") or "").strip()
    ttl = int(body.get("ttl_seconds") or DEFAULT_TTL)
    groups = body.get("site_access_groups") or []

    bad = invalid(username, email, ttl, groups)
    if bad:
        return bad

    payload, status = provision(username, email, display_name, ttl, groups)
    if status != 201:
        return jsonify(payload), status
    payload.pop("nonce")
    payload["note"] = (
        "Send this link yourself. It works once. The account exists with no "
        "password until the invitee sets one, so there is no temporary "
        "credential for anyone to leak."
    )
    return jsonify(payload), status



@app.delete("/invites/<username>")
def revoke(username):
    """Revocation is deleting the account. A token naming a user that does not
    exist cannot be redeemed, because setting its password fails."""
    denied = forbidden()
    if denied:
        return denied
    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="invalid username"), 400

    token = lldap_token()
    if not user_exists(token, username):
        return jsonify(error="no such user"), 404
    gql(token, "mutation($id:String!){deleteUser(userId:$id){ok}}", {"id": username})
    log.info("account %s deleted by %s", username, caller())
    return jsonify(deleted=username), 200


PUBLIC_ROW = (
    "id", "email", "note", "received_at", "state", "username",
    "decided_by", "decided_at", "expires_at", "sent_at", "send_count",
)


def view(row):
    return {k: row[k] for k in PUBLIC_ROW}


def deliver(row_id, email, url, expires_at, username):
    try:
        mailer.send_invite(email, url, expires_at)
    except mailer.MailFailed as exc:
        log.error("invite mail failed for %s: %s", username, exc)
        return str(exc)
    intake().record_sent(row_id)
    log.info("invite mailed to %s for %s by %s", email, username, caller())
    return None


@app.get("/intake")
def list_intake():
    denied = forbidden()
    if denied:
        return denied
    state = request.args.get("state", "pending")
    if state == "all":
        state = None
    rows = intake().listing(state=state)
    return jsonify(
        rows=[view(r) for r in rows],
        counts=intake().counts(),
        pending_capacity=INTAKE_CAP,
    )


@app.post("/intake/<int:row_id>/reject")
def reject_intake(row_id):
    denied = forbidden()
    if denied:
        return denied
    if not intake().reject(row_id, caller()):
        return jsonify(error="no pending intake row with that id"), 409
    log.info("intake row %s rejected by %s", row_id, caller())
    return jsonify(rejected=row_id), 200


@app.post("/intake/<int:row_id>/approve")
def approve_intake(row_id):
    denied = forbidden()
    if denied:
        return denied

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    display_name = (body.get("display_name") or "").strip()
    ttl = int(body.get("ttl_seconds") or DEFAULT_TTL)
    groups = body.get("site_access_groups") or []

    row = intake().get(row_id)
    if row is None:
        return jsonify(error="no such intake row"), 404
    if row["state"] != "pending":
        return jsonify(error=f"intake row is {row['state']}, not pending"), 409

    email = row["email"]
    bad = invalid(username, email, ttl, groups)
    if bad:
        return bad

    if not intake().claim(row_id, username, caller()):
        return jsonify(error="intake row was decided by someone else"), 409

    try:
        payload, status = provision(username, email, display_name, ttl, groups)
    except Exception:
        intake().release(row_id)
        raise
    if status != 201:
        intake().release(row_id)
        return jsonify(payload), status

    mac = invites.decision_mac(
        SIGNING_KEY,
        {"id": row_id, "email": email, "username": username,
         "nonce": payload["nonce"], "expires_at": payload["expires_at"]},
    )
    intake().record_claim_material(row_id, payload["nonce"], payload["expires_at"], mac)

    failure = deliver(row_id, email, payload["url"], payload["expires_at"], username)
    payload.pop("nonce")
    payload["intake_id"] = row_id
    payload["mailed"] = failure is None
    if failure:
        payload["mail_error"] = failure
        return jsonify(payload), 502
    return jsonify(payload), 201


@app.post("/intake/<int:row_id>/send")
def send_intake(row_id):
    """Mail the link for a row already approved, by id. The link itself never
    appears in a request line, so no proxy log can hold a live token."""
    denied = forbidden()
    if denied:
        return denied

    row = intake().get(row_id)
    if row is None:
        return jsonify(error="no such intake row"), 404
    if row["state"] != "approved" or not row["username"]:
        return jsonify(error=f"intake row is {row['state']}, approve it first"), 409
    if not invites.decision_ok(SIGNING_KEY, mac_fields(row), row["mac"]):
        log.error("intake row %s fails its decision MAC: refusing to send", row_id)
        return jsonify(error="intake row is not authentic; re-approve it"), 409

    username = row["username"]
    if not user_exists(lldap_token(), username):
        return jsonify(error="the account no longer exists; it was revoked"), 409

    now = int(time.time())
    nonce, expires_at = row["nonce"], row["expires_at"]
    if not nonce or not expires_at or expires_at <= now + 60:
        token, nonce, expires_at = invites.mint(SIGNING_KEY, username, DEFAULT_TTL)
        mac = invites.decision_mac(
            SIGNING_KEY,
            {"id": row_id, "email": row["email"], "username": username,
             "nonce": nonce, "expires_at": expires_at},
        )
        intake().record_claim_material(row_id, nonce, expires_at, mac)
        log.info("intake row %s re-minted for %s, nonce %s", row_id, username, nonce)
    else:
        token = invites.sign(SIGNING_KEY, username, expires_at, nonce)

    failure = deliver(row_id, row["email"], f"{REDEEM_BASE}/i/{token}",
                      expires_at, username)
    if failure:
        return jsonify(intake_id=row_id, mailed=False, mail_error=failure), 502
    return jsonify(intake_id=row_id, username=username, mailed=True,
                   expires_at=expires_at), 200



def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from waitress import serve
    port = int(os.environ.get("PORT", "9101"))
    serve(app, host="127.0.0.1", port=port, threads=4, ident=None)


if __name__ == "__main__":
    sys.exit(main())
