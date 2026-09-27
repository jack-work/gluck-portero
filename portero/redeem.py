#!/usr/bin/env python3
"""The public half. It can set a password and it can do nothing else.

This is the only unauthenticated endpoint on the estate that touches the
directory, so the rules are narrow on purpose:

  no user creation, no group change, no listing, no enumeration
  one generic response for invalid, expired and already-used
  the token is never written to a log
  the directory credential is lldap_password_manager, never lldap_admin

doc/THREAT-MODEL.md carries the reasoning.
"""

import logging
import os
import subprocess
import sys
import threading
import time

import requests
from flask import Flask, Response, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import invites
from spent import Spent

LLDAP_URL = os.environ.get("PORTERO_LLDAP_URL", "http://127.0.0.1:17170")
SERVICE_USER = os.environ.get("PORTERO_REDEEM_USER", "portero-redeem")
LOGIN_URL = os.environ.get("PORTERO_LOGIN_URL", "https://auth.kelliher.info")
MIN_PASSWORD = int(os.environ.get("PORTERO_MIN_PASSWORD", "12"))
MAX_PASSWORD = 256
STATE_DIR = os.environ.get("STATE_DIRECTORY", "/var/lib/gluck-portero-redeem")
SET_PASSWORD_BIN = os.environ.get("PORTERO_SET_PASSWORD_BIN", "lldap_set_password")

# A whole-endpoint budget, not a per-IP one. Per-IP limits are evaded by
# rotating IPs; this endpoint should see a handful of requests in its life, so a
# global ceiling is both sufficient and unevadable.
RATE_LIMIT = int(os.environ.get("PORTERO_RATE_LIMIT", "20"))
RATE_WINDOW = int(os.environ.get("PORTERO_RATE_WINDOW", "60"))

# Every response takes at least this long, so a caller cannot tell a token that
# failed its signature from one that was already spent.
FLOOR_SECONDS = float(os.environ.get("PORTERO_RESPONSE_FLOOR", "0.35"))


def credential(name):
    """Read a secret from the unit's LoadCredential directory."""
    base = os.environ.get("CREDENTIALS_DIRECTORY")
    if not base:
        raise RuntimeError("no CREDENTIALS_DIRECTORY: refusing to start")
    with open(os.path.join(base, name), "r", encoding="utf-8") as fh:
        return fh.read().strip()


app = Flask(__name__)
log = logging.getLogger("portero-redeem")

SIGNING_KEY = invites.load_key(
    os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "invite_key")
)
SERVICE_PASSWORD = credential("redeem_password")
STORE = Spent(os.path.join(STATE_DIR, "spent.db"))

_hits = []
_hits_lock = threading.Lock()


def rate_limited(now=None):
    now = now if now is not None else time.monotonic()
    with _hits_lock:
        cutoff = now - RATE_WINDOW
        while _hits and _hits[0] < cutoff:
            _hits.pop(0)
        if len(_hits) >= RATE_LIMIT:
            return True
        _hits.append(now)
        return False


PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=referrer content=no-referrer>
<title>{title}</title>
<style>
 body{{font:16px/1.55 system-ui,sans-serif;max-width:27rem;margin:5rem auto;padding:0 1.2rem;color:#1b1b1b}}
 h1{{font-size:1.3rem;margin:0 0 .4rem}}
 p{{color:#555}} label{{display:block;margin:1.4rem 0 .3rem;font-weight:600}}
 input{{width:100%;padding:.6rem;font-size:1rem;border:1px solid #bbb;border-radius:4px}}
 button{{margin-top:1.4rem;padding:.6rem 1.1rem;font-size:1rem;border:0;border-radius:4px;background:#1b1b1b;color:#fff}}
 .err{{color:#a11;font-weight:600}}
</style>
<h1>{title}</h1>
{body}
"""

FORM = """<p>Choose a password for <strong>{username}</strong>. You will set up
two-factor authentication after you sign in.</p>
{error}
<form method=post autocomplete=off>
 <label for=p>New password</label>
 <input id=p name=password type=password minlength="{minlen}" required autofocus>
 <label for=c>Repeat it</label>
 <input id=c name=confirm type=password minlength="{minlen}" required>
 <button type=submit>Set my password</button>
</form>
<p style="margin-top:2rem;font-size:.85rem">At least {minlen} characters. This
link works once and then stops working.</p>
"""

# The single response for invalid, expired, already-used, and unknown. It must
# not distinguish them, or it becomes an oracle for which usernames exist.
REFUSED = """<p>This invitation link is not valid. It may have expired, or it
may already have been used.</p>
<p style="font-size:.85rem">Ask for a new one.</p>"""

DONE = """<p>Your password is set.</p>
<p><a href="{login}">Sign in</a>, and you will be asked to set up two-factor
authentication.</p>"""


def page(title, body, status=200):
    resp = Response(PAGE.format(title=title, body=body), status=status,
                    mimetype="text/html; charset=utf-8")
    # The token sits in the URL, so it must not travel in a Referer header.
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
    return resp


def refused():
    return page("Invitation not valid", REFUSED, status=404)


def settle(started):
    """Hold every response to the same floor, so timing says nothing."""
    remaining = FLOOR_SECONDS - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)


def lldap_token():
    r = requests.post(
        f"{LLDAP_URL}/auth/simple/login",
        json={"username": SERVICE_USER, "password": SERVICE_PASSWORD},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["token"]


def set_password(username, password):
    """Set the password without ever placing it in argv.

    lldap 0.6.x offers only --password or LLDAP_USER_PASSWORD. /proc/<pid>/cmdline
    is world-readable and /proc on spain has no hidepid, so argv is disqualified.
    The environment of one short-lived child is the sanctioned alternative.
    """
    env = dict(os.environ)
    env["LLDAP_USER_PASSWORD"] = password
    proc = subprocess.run(
        [SET_PASSWORD_BIN, "--base-url", LLDAP_URL,
         "--token", lldap_token(), "--username", username],
        env=env, capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        # stderr may echo the request; log the code only.
        log.error("set_password failed for %s: rc=%s", username, proc.returncode)
        return False
    return True


@app.get("/healthz")
def healthz():
    return Response("ok\n", mimetype="text/plain")


@app.route("/i/<token>", methods=["GET", "POST"])
def redeem(token):
    started = time.monotonic()
    if rate_limited():
        settle(started)
        return page("Too many attempts",
                    "<p>Too many attempts. Try again in a minute.</p>", status=429)

    try:
        claim = invites.verify(SIGNING_KEY, token)
    except invites.InvalidToken:
        settle(started)
        return refused()

    username, nonce = claim["username"], claim["nonce"]

    if STORE.is_spent(nonce):
        settle(started)
        return refused()

    if request.method == "GET":
        settle(started)
        return page("Set your password",
                    FORM.format(username=username, minlen=MIN_PASSWORD, error=""))

    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""
    problem = None
    if len(password) < MIN_PASSWORD:
        problem = f"Too short. Use at least {MIN_PASSWORD} characters."
    elif len(password) > MAX_PASSWORD:
        problem = "Too long."
    elif password != confirm:
        problem = "The two passwords do not match."
    if problem:
        settle(started)
        return page("Set your password",
                    FORM.format(username=username, minlen=MIN_PASSWORD,
                                error=f'<p class="err">{problem}</p>'), status=400)

    # Spend the nonce BEFORE setting the password. If the password set then
    # fails, the link is burnt and a new invite is needed. The other order
    # would leave a window in which one link sets a password twice.
    if not STORE.claim(nonce, username):
        settle(started)
        return refused()

    if not set_password(username, password):
        settle(started)
        return page("Something went wrong",
                    "<p>The password could not be set. Ask for a new invitation.</p>",
                    status=500)

    log.info("invite redeemed for %s", username)
    settle(started)
    return page("You are set up", DONE.format(login=LOGIN_URL))


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from waitress import serve
    port = int(os.environ.get("PORT", "9102"))
    serve(app, host="127.0.0.1", port=port, threads=4, ident=None)


if __name__ == "__main__":
    sys.exit(main())
