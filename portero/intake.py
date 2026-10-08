#!/usr/bin/env python3
"""The intake half. It writes an address into a capped table and nothing else.

It holds no credential, reaches no directory, reads no row back and sends no
mail. The only effect a request can have is one INSERT the caller never sees
the outcome of: accepted, duplicate, malformed, flooded and full all render the
same bytes with the same status after the same floor.

So there is nothing here to steal and nothing to enumerate. Deciding on an
address is the authenticated mint half's job.
"""

import logging
import os
import re
import sys
import time

from flask import Flask, Response, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from budget import Budget
from pending import Intake

DB_PATH = os.environ.get("PORTERO_INTAKE_DB", "/var/lib/gluck-portero-intake/intake.db")
CAP = int(os.environ.get("PORTERO_INTAKE_CAP", "200"))
FLOOR_SECONDS = float(os.environ.get("PORTERO_RESPONSE_FLOOR", "0.35"))
MAX_EMAIL = 254
MAX_NOTE = 280

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

FLOOD = Budget(
    int(os.environ.get("PORTERO_INTAKE_BUDGET", "120")),
    int(os.environ.get("PORTERO_INTAKE_WINDOW", "60")),
)

app = Flask(__name__)
log = logging.getLogger("portero-intake")
STORE = Intake(DB_PATH, CAP)

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
</style>
<h1>{title}</h1>
{body}
"""

FORM = """<p>Leave an email address and the owner of this site will decide
whether to send you an invitation. Nothing is sent automatically.</p>
<form method=post autocomplete=off>
 <label for=e>Email address</label>
 <input id=e name=email type=email maxlength="{maxemail}" required autofocus>
 <label for=n>Anything we should know (optional)</label>
 <input id=n name=note type=text maxlength="{maxnote}">
 <button type=submit>Ask for an invitation</button>
</form>
"""

TAKEN = """<p>Thank you. If an invitation is sent, it will arrive by email.</p>
<p style="font-size:.85rem">No reply is guaranteed, and asking twice does not
help.</p>"""


def page(title, body, status=200):
    resp = Response(PAGE.format(title=title, body=body), status=status,
                    mimetype="text/html; charset=utf-8")
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
    )
    return resp


def settle(started):
    remaining = FLOOR_SECONDS - (time.monotonic() - started)
    if remaining > 0:
        time.sleep(remaining)


@app.get("/healthz")
def healthz():
    return Response("ok\n", mimetype="text/plain")


@app.get("/intake")
def form():
    return page("Ask for an invitation",
                FORM.format(maxemail=MAX_EMAIL, maxnote=MAX_NOTE))


@app.post("/intake")
def offer():
    started = time.monotonic()
    accepted = FLOOD.spend()
    email = (request.form.get("email") or "").strip()
    note = (request.form.get("note") or "").strip()
    if accepted and EMAIL_RE.fullmatch(email) and len(email) <= MAX_EMAIL:
        STORE.offer(email.lower(), note[:MAX_NOTE])
        log.info("intake offer written")
    else:
        log.info("intake offer dropped")
    settle(started)
    return page("Thank you", TAKEN, status=202)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    from waitress import serve
    port = int(os.environ.get("PORT", "9103"))
    serve(app, host="127.0.0.1", port=port, threads=4, ident=None)


if __name__ == "__main__":
    sys.exit(main())
