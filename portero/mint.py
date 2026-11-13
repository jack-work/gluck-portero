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

import grp
import logging
import os
import re
import socket
import sys
import threading
import time

import requests
from flask import Flask, g as per_request, jsonify, redirect, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import invites
import journal
import mailer
import oidc
import pending_admin
import umbral
from pending_admin import IntakeAdmin, mac_fields

LLDAP_URL = os.environ.get("PORTERO_LLDAP_URL", "http://127.0.0.1:17170")
ADMIN_USER = os.environ.get("PORTERO_ADMIN_USER", "admin")
REQUIRED_GROUP = os.environ.get("PORTERO_REQUIRED_GROUP", "portero-admin")
REDEEM_BASE = os.environ.get("PORTERO_REDEEM_BASE", "https://invite.kelliher.info")
DEFAULT_TTL = int(os.environ.get("PORTERO_DEFAULT_TTL", str(72 * 3600)))
MAX_TTL = int(os.environ.get("PORTERO_MAX_TTL", str(14 * 24 * 3600)))
STATE_DIR = os.environ.get("STATE_DIRECTORY", "/var/lib/gluck-portero-mint")
INTAKE_DB = os.environ.get("PORTERO_INTAKE_DB", os.path.join(STATE_DIR, "intake.db"))
INTAKE_OFFSET = os.environ.get(
    "PORTERO_INTAKE_OFFSET", os.path.join(STATE_DIR, "spool.offset")
)
INTAKE_SPOOL = os.environ.get(
    "PORTERO_INTAKE_SPOOL", "/var/lib/gluck-portero-intake/spool.jsonl"
)
INTAKE_CAP = int(os.environ.get("PORTERO_INTAKE_CAP", "200"))
INGEST_SECONDS = float(os.environ.get("PORTERO_INGEST_SECONDS", "60"))
ORIGIN = os.environ.get("PORTERO_ORIGIN", "https://portero.kelliher.info")
GATE = oidc.BearerGate(
    issuer=os.environ.get("PORTERO_OIDC_ISSUER", ""),
    jwks_url=os.environ.get("PORTERO_OIDC_JWKS_URL", ""),
    userinfo_url=os.environ.get("PORTERO_OIDC_USERINFO_URL", ""),
    client_ids=os.environ.get("PORTERO_OIDC_CLIENT_IDS", "").split(","),
)

UMBRAL = os.environ.get("PORTERO_UMBRAL", "") == "1"
UMBRAL_SPOOL = os.environ.get("PORTERO_UMBRAL_SPOOL", "/var/lib/umbral-spool/requests.jsonl")
UMBRAL_DB = os.environ.get("PORTERO_UMBRAL_DB", os.path.join(STATE_DIR, "umbral.db"))
UMBRAL_CAP = int(os.environ.get("PORTERO_UMBRAL_CAP", "200"))
UMBRAL_READER_GROUP = os.environ.get("PORTERO_UMBRAL_READER_GROUP", "portero-spool-reader")
UMBRAL_WRITER_GROUP = os.environ.get("PORTERO_UMBRAL_WRITER_GROUP", "umbral-spool")
UMBRAL_ADMIN_SOCKET = os.environ.get("PORTERO_UMBRAL_ADMIN_SOCKET", "/run/umbral/admin.sock")
UMBRAL_PEER = os.environ.get("PORTERO_UMBRAL_PEER", "umbral")
NOTIFY_TOKEN_URL = os.environ.get("PORTERO_NOTIFY_TOKEN_URL", "")
NOTIFY_CLIENT_ID = os.environ.get("PORTERO_NOTIFY_CLIENT_ID", "")
NOTIFY_HERALD_URL = os.environ.get("PORTERO_NOTIFY_HERALD_URL", "")
NOTIFY_TO = os.environ.get("PORTERO_NOTIFY_TO", "gluck")
NOTIFY_MAIL = os.environ.get("PORTERO_NOTIFY_MAIL", "")

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
# lldap owns the uniqueness of an address, enforced by a database constraint.
# The constraint is the arbiter rather than a SELECT here, because a pre-check
# plus an insert is the read-then-write pattern this estate has been bitten by.
EMAIL_TAKEN = "UNIQUE constraint failed: users.lowercase_email"
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
            _intake = IntakeAdmin(INTAKE_DB, INTAKE_CAP,
                                  spool_path=INTAKE_SPOOL,
                                  offset_path=INTAKE_OFFSET)
        return _intake


def identity():
    if "portero_identity" in per_request:
        return per_request.portero_identity
    if "Authorization" in request.headers:
        try:
            who = GATE.verify(request.headers["Authorization"])
        except oidc.Refused as exc:
            log.warning("bearer refused: %r", str(exc))
            who = (401, "bearer token refused")
        except oidc.Unavailable as exc:
            log.error("bearer check unavailable: %r", str(exc))
            who = (503, "identity provider unavailable")
    else:
        user = request.headers.get("Remote-User", "")
        raw = request.headers.get("Remote-Groups", "")
        groups = [x.strip() for x in raw.split(",") if x.strip()]
        who = oidc.Identity(user, groups, user, None) if user else (401, "unauthenticated")
    per_request.portero_identity = who
    return who


def caller():
    who = identity()
    return who.username if isinstance(who, oidc.Identity) else ""


def caller_groups():
    who = identity()
    return list(who.groups) if isinstance(who, oidc.Identity) else []


def lldap_token():
    r = requests.post(
        f"{LLDAP_URL}/auth/simple/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["token"]


def gql(token, query, variables=None, tolerate=()):
    """Run a GraphQL call. Raises on any error unless every error is tolerated
    and the data carries nothing.

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
        every_error_tolerated = all(
            any(t in str(e.get("message", "")) for t in tolerate) for e in errors
        )
        data_is_empty = not any((body.get("data") or {}).values())
        if tolerate and every_error_tolerated and data_is_empty:
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
    who = identity()
    if not isinstance(who, oidc.Identity):
        return jsonify(error=who[1]), who[0]
    return jsonify(user=who.username, groups=list(who.groups), via="bearer" if who.client_id else "session")


def cross_site():
    if request.method != "POST" or "Authorization" in request.headers:
        return None
    if request.mimetype != "application/json":
        return jsonify(error="a session POST must be application/json"), 415
    origin = request.headers.get("Origin")
    if origin is not None and origin != ORIGIN:
        return jsonify(error="cross-origin request refused"), 403
    return None


def forbidden():
    who = identity()
    if not isinstance(who, oidc.Identity):
        return jsonify(error=who[1]), who[0]
    if REQUIRED_GROUP not in who.groups:
        return jsonify(error=f"requires group {REQUIRED_GROUP}"), 403
    return cross_site()


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
    try:
        gql(
            token,
            "mutation($u:CreateUserInput!){createUser(user:$u){id}}",
            {"u": {"id": username, "email": email,
                   "displayName": display_name or username}},
        )
    except RuntimeError as exc:
        if EMAIL_TAKEN not in str(exc):
            raise
        log.info("refused %r: the address already belongs to an account", username)
        return {"error": "that email address already belongs to an account"}, 409

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
        "invite minted for %r by %r, groups %s, nonce %s, expires %s",
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


HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN_ASSETS = {
    "admin.js": "text/javascript; charset=utf-8",
    "admin.css": "text/css; charset=utf-8",
    "zanni.css": "text/css; charset=utf-8",
}
ADMIN_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src data:; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)


def admin_file(name, content_type):
    try:
        with open(os.path.join(HERE, name), "rb") as fh:
            body = fh.read()
    except FileNotFoundError:
        return jsonify(error="not found"), 404
    return body, 200, {
        "Content-Type": content_type,
        "Content-Security-Policy": ADMIN_CSP,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }


@app.get("/")
def root():
    denied = forbidden()
    if denied:
        return denied
    return redirect("/admin", 302)


@app.get("/admin")
def admin_page():
    denied = forbidden()
    if denied:
        return denied
    return admin_file("admin.html", "text/html; charset=utf-8")


@app.get("/admin/config")
def admin_config():
    denied = forbidden()
    if denied:
        return denied
    return jsonify(user=caller(), grantable=GRANTABLE)


@app.get("/admin/<name>")
def admin_asset(name):
    denied = forbidden()
    if denied:
        return denied
    if name not in ADMIN_ASSETS:
        return jsonify(error="not found"), 404
    return admin_file(name, ADMIN_ASSETS[name])


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
    log.info("account %r deleted by %r", username, caller())
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
        log.error("invite mail failed for %r: %r", username, str(exc))
        return str(exc)
    intake().record_sent(row_id)
    log.info("invite mailed to %r for %r by %r", email, username, caller())
    return None


def log_ingest(got, spool_bytes):
    if got.outcome == pending_admin.FAILED:
        log.error("mint ingest outcome=error offset=%d spool_bytes=%d errno=%s",
                  got.offset, spool_bytes, got.errno)
        return
    level = logging.WARNING if got.outcome == pending_admin.HELD else logging.INFO
    log.log(level, "mint ingest outcome=%s landed=%d offset=%d spool_bytes=%d",
            got.outcome, got.landed, got.offset, spool_bytes)


def ingest_tick():
    try:
        got = intake().ingest()
    except Exception:
        log.exception("mint ingest outcome=error offset=-1 spool_bytes=-1 errno=EXCEPTION")
        return None
    log_ingest(got, intake().spool_bytes()[0])
    return got


def ingest_every(seconds, stop):
    while not stop.wait(seconds):
        ingest_tick()
        if UMBRAL:
            try:
                umbral_ingest()
            except Exception:
                log.exception("umbral ingest outcome=error")


@app.get("/intake")
def list_intake():
    denied = forbidden()
    if denied:
        return denied
    state = request.args.get("state", "pending")
    if state == "all":
        state = None
    got = intake().ingest()
    rows = intake().listing(state=state)
    total, consumed = intake().spool_bytes()
    log_ingest(got, total)
    return jsonify(
        rows=[view(r) for r in rows],
        counts=intake().counts(),
        pending_capacity=INTAKE_CAP,
        ingest=got.outcome,
        ingest_errno=got.errno,
        ingested_now=None if got.outcome == pending_admin.FAILED else got.landed,
        spool_bytes=total,
        spool_consumed=consumed,
        spool_max=int(os.environ.get("PORTERO_INTAKE_SPOOL_MAX", str(1 << 20))),
    )


@app.post("/intake/<int:row_id>/reject")
def reject_intake(row_id):
    denied = forbidden()
    if denied:
        return denied
    if not intake().reject(row_id, caller()):
        return jsonify(error="no pending intake row with that id"), 409
    log.info("intake row %s rejected by %r", row_id, caller())
    return jsonify(rejected=row_id), 200


@app.post("/intake/<int:row_id>/retire")
def retire_intake(row_id):
    denied = forbidden()
    if denied:
        return denied
    row = intake().get(row_id)
    if row is None:
        return jsonify(error="no such intake row"), 404
    if row["state"] != "approved":
        return jsonify(error=f"intake row is {row['state']}, not approved"), 409
    username = row["username"]
    if username and user_exists(lldap_token(), username):
        return jsonify(error=f"the account still exists; DELETE /invites/{username} first"), 409
    if not intake().retire(row_id):
        return jsonify(error="intake row changed underneath; read it again"), 409
    log.info("intake row %s retired by %r, account %r gone", row_id, caller(), username)
    return jsonify(retired=row_id, username=username), 200


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
        log.info("intake row %s re-minted for %r, nonce %s", row_id, username, nonce)
    else:
        token = invites.sign(SIGNING_KEY, username, expires_at, nonce)

    failure = deliver(row_id, row["email"], f"{REDEEM_BASE}/i/{token}",
                      expires_at, username)
    if failure:
        return jsonify(intake_id=row_id, mailed=False, mail_error=failure), 502
    return jsonify(intake_id=row_id, username=username, mailed=True,
                   expires_at=expires_at), 200



_umbral = None
_umbral_lock = threading.Lock()


def umbral_gql(query, variables=None, tolerate=()):
    return gql(lldap_token(), query, variables, tolerate)


def umbral_parts():
    global _umbral
    with _umbral_lock:
        if _umbral is None:
            store = umbral.Store(UMBRAL_DB, UMBRAL_CAP)
            directory = umbral.Directory(umbral_gql)
            secret = os.path.join(os.environ.get("CREDENTIALS_DIRECTORY", ""), "herald_client_secret")
            notifier = umbral.Notifier(
                token_url=NOTIFY_TOKEN_URL, client_id=NOTIFY_CLIENT_ID,
                secret_file=secret if os.path.exists(secret) else "",
                herald_url=NOTIFY_HERALD_URL, to=NOTIFY_TO,
                mail=(lambda text: mailer.send_note(NOTIFY_MAIL, "umbral link", text)) if NOTIFY_MAIL else None,
            )
            _umbral = {
                "store": store,
                "dir": directory,
                "linker": umbral.Linker(directory, store, notifier),
                "sessions": umbral.Sessions(UMBRAL_ADMIN_SOCKET),
            }
        return _umbral


def umbral_ingest():
    parts = umbral_parts()
    try:
        fd = umbral.open_checked(UMBRAL_SPOOL, grp.getgrnam(UMBRAL_READER_GROUP).gr_gid,
                                 grp.getgrnam(UMBRAL_WRITER_GROUP).gr_gid)
    except (umbral.LayoutWrong, OSError, KeyError) as exc:
        log.error("umbral ingest outcome=refused reason=%s", str(exc) or type(exc).__name__)
        return "refused"
    try:
        landed, skipped, offset = parts["store"].ingest(fd)
    except umbral.LayoutWrong as exc:
        log.error("umbral ingest outcome=refused reason=%s", exc)
        return "refused"
    finally:
        os.close(fd)
    level = logging.WARNING if skipped else logging.INFO
    log.log(level, "umbral ingest outcome=ok landed=%d skipped=%d offset=%d", landed, skipped, offset)
    return "ok"


def umbral_disabled():
    if not UMBRAL:
        return jsonify(error="umbral is not enabled here"), 404
    return forbidden()


UMBRAL_ROW = ("id", "provider", "subject", "email", "hd", "name", "note", "received_at",
              "state", "username", "decided_by", "decided_at")


@app.get("/umbral/requests")
def umbral_requests():
    denied = umbral_disabled()
    if denied:
        return denied
    state = request.args.get("state", "pending")
    ingest = umbral_ingest()
    parts = umbral_parts()
    rows = []
    for r in parts["store"].listing(state=None if state == "all" else state):
        row = {k: r[k] for k in UMBRAL_ROW}
        row["workspace_warning"] = (
            f"{r['email']} is a Google Workspace address ({r['hd']}). That domain's "
            "administrator can sign in as this person (same subject), so they can act as "
            "this friend." if r["provider"] == "google" and r["hd"] else "")
        row["claims_existing"] = []
        if r["state"] == "pending":
            row["claims_existing"] = parts["dir"].by_email(r["email"])
        rows.append(row)
    return jsonify(rows=rows, ingest=ingest, grantable=GRANTABLE)


@app.post("/umbral/requests/<int:row_id>/approve")
def umbral_approve(row_id):
    denied = umbral_disabled()
    if denied:
        return denied
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    display_name = (body.get("display_name") or "").strip()
    groups = body.get("site_access_groups") or []
    parts = umbral_parts()
    row = parts["store"].get(row_id)
    if row is None:
        return jsonify(error="no such request"), 404
    if row["state"] != "pending":
        return jsonify(error=f"request is {row['state']}, not pending"), 409
    bad = invalid(username, row["email"], DEFAULT_TTL, groups)
    if bad:
        return bad
    if not parts["store"].claim(row_id, username, caller()):
        return jsonify(error="request was decided by someone else"), 409
    try:
        payload, status = provision_linked(parts, username, row, display_name or row["name"], groups)
    except Exception:
        parts["store"].release(row_id)
        raise
    if status != 201:
        parts["store"].release(row_id)
        return jsonify(payload), status
    parts["store"].record("approve", username, row["provider"], row["subject"], caller())
    try:
        parts["sessions"].clear_pending(row["provider"], row["subject"])
    except OSError as exc:
        log.error("umbral pending not cleared for %s %s: %s", row["provider"], row["subject"], type(exc).__name__)
    try:
        mailer.send_welcome(row["email"], umbral.LABELS[row["provider"]])
        payload["mailed"] = True
    except mailer.MailFailed as exc:
        log.error("umbral welcome mail failed for %r: %r", username, str(exc))
        payload["mailed"] = False
        payload["mail_error"] = str(exc)
    log.info("umbral request %s approved as %r by %r, groups %s", row_id, username, caller(), payload["site_access_groups"])
    return jsonify(payload), 201


def provision_linked(parts, username, row, display_name, groups):
    token = lldap_token()
    if user_exists(token, username):
        return {"error": "user already exists"}, 409
    if parts["dir"].holders(row["provider"], row["subject"]):
        return {"error": "this provider account is already linked to an account"}, 409
    group_ids = {}
    for g in groups:
        gid = group_id(token, g)
        if gid is None:
            return {"error": f"group does not exist in the directory: {g}"}, 400
        group_ids[g] = gid
    try:
        gql(
            token,
            "mutation($u:CreateUserInput!){createUser(user:$u){id}}",
            {"u": {"id": username, "email": row["email"], "displayName": display_name,
                   "attributes": [{"name": umbral.PROVIDERS[row["provider"]], "value": [row["subject"]]}]}},
        )
    except RuntimeError as exc:
        if EMAIL_TAKEN not in str(exc):
            raise
        return {"error": "that email address already belongs to an account; "
                         "its holder links a provider at login.kelliher.info/link"}, 409
    for g, gid in group_ids.items():
        gql(token, "mutation($u:String!,$g:Int!){addUserToGroup(userId:$u,groupId:$g){ok}}",
            {"u": username, "g": gid})
    holders = parts["dir"].holders(row["provider"], row["subject"])
    if holders != [username]:
        log.error("umbral approval left %s %s on %r", row["provider"], row["subject"], holders)
        return {"error": "subject ended up on more than one account; check lldap"}, 409
    return {"username": username, "provider": row["provider"], "subject": row["subject"],
            "site_access_groups": sorted(group_ids)}, 201


@app.post("/umbral/requests/<int:row_id>/reject")
def umbral_reject(row_id):
    denied = umbral_disabled()
    if denied:
        return denied
    parts = umbral_parts()
    row = parts["store"].get(row_id)
    if row is None or not parts["store"].reject(row_id, caller()):
        return jsonify(error="no pending request with that id"), 409
    try:
        parts["sessions"].clear_pending(row["provider"], row["subject"])
    except OSError as exc:
        log.error("umbral pending not cleared for %s %s: %s", row["provider"], row["subject"], type(exc).__name__)
    log.info("umbral request %s rejected by %r", row_id, caller())
    return jsonify(rejected=row_id), 200


@app.get("/umbral/events")
def umbral_events():
    denied = umbral_disabled()
    if denied:
        return denied
    return jsonify(events=umbral_parts()["store"].events())


@app.post("/umbral/accounts/<uid>/unlink")
def umbral_unlink(uid):
    denied = umbral_disabled()
    if denied:
        return denied
    provider = (request.get_json(silent=True) or {}).get("provider", "")
    try:
        subject = umbral_parts()["linker"].unlink(uid, provider, caller())
    except umbral.Refused as exc:
        return jsonify(error=exc.reason), exc.status
    return jsonify(unlinked=uid, provider=provider, subject=subject), 200


@app.get("/umbral/sessions")
def umbral_sessions():
    denied = umbral_disabled()
    if denied:
        return denied
    try:
        rows = umbral_parts()["sessions"].listing(request.args.get("uid", ""))
    except (OSError, RuntimeError) as exc:
        log.error("umbral admin unreachable: %s", type(exc).__name__)
        return jsonify(error="umbral is unreachable"), 502
    return jsonify(sessions=rows)


@app.post("/umbral/sessions/<handle>/kill")
def umbral_kill(handle):
    denied = umbral_disabled()
    if denied:
        return denied
    try:
        ok = umbral_parts()["sessions"].kill(handle)
    except OSError as exc:
        log.error("umbral admin unreachable: %s", type(exc).__name__)
        return jsonify(error="umbral is unreachable"), 502
    if not ok:
        return jsonify(error="no such session"), 404
    log.info("umbral session killed by %r", caller())
    return jsonify(killed=handle), 200


@app.post("/umbral/sessions/kill")
def umbral_kill_uid():
    denied = umbral_disabled()
    if denied:
        return denied
    uid = (request.get_json(silent=True) or {}).get("uid", "")
    if not isinstance(uid, str) or not uid:
        return jsonify(error="uid required"), 400
    try:
        n = umbral_parts()["sessions"].kill_uid(uid)
    except (OSError, RuntimeError) as exc:
        log.error("umbral admin unreachable: %s", type(exc).__name__)
        return jsonify(error="umbral is unreachable"), 502
    log.info("umbral sessions of %r killed by %r: %d", uid, caller(), n)
    return jsonify(killed=n, uid=uid), 200



def inherited_sockets():
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return {}
    count = int(os.environ.get("LISTEN_FDS", "0"))
    names = os.environ.get("LISTEN_FDNAMES", "").split(":") if os.environ.get("LISTEN_FDNAMES") else []
    out = {}
    for i in range(count):
        name = names[i] if i < len(names) else "unknown"
        out.setdefault(name, []).append(socket.socket(fileno=3 + i))
    return out


def serve_umbral_links(socks):
    if len(socks) != 1:
        sys.exit("want exactly one socket named link")
    server = umbral.LinkServer(socks[0], umbral_parts()["linker"], UMBRAL_PEER)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    journal.configure()
    if INGEST_SECONDS > 0:
        threading.Thread(target=ingest_every, args=(INGEST_SECONDS, threading.Event()), daemon=True).start()
    from waitress import serve
    named = inherited_sockets()
    if UMBRAL:
        umbral_parts()["dir"].ensure_attributes()
        if "link" not in named:
            sys.exit("umbral is enabled but systemd passed no socket named link")
        serve_umbral_links(named.pop("link"))
    elif "link" in named:
        sys.exit("a link socket was passed but umbral is not enabled")
    sockets = [s for socks in named.values() for s in socks]
    if sockets:
        serve(app, sockets=sockets, threads=4, ident=None)
    elif os.environ.get("PORTERO_LISTEN") == "socket":
        sys.exit("no listening socket from systemd; refusing to fall back to TCP")
    else:
        port = int(os.environ.get("PORT", "9101"))
        serve(app, host="127.0.0.1", port=port, threads=4, ident=None)


if __name__ == "__main__":
    sys.exit(main())
