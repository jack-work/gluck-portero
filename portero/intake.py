#!/usr/bin/env python3
"""The intake half. It appends an address to a write-only spool and nothing else.

It holds no credential, reaches no directory, sends no mail, and **cannot read
back what it has written**: the spool is opened O_WRONLY|O_APPEND, so a read on
that descriptor fails with EBADF. That property is the kernel's rather than
this file's, and it survives a future author who stops reading this comment.

The only effect a request can have is one append the caller never sees the
outcome of: accepted, duplicate, malformed, flooded and full all render the same
bytes with the same status after the same floor.

The spool is pre-created root-owned and is never created, renamed or removed
here, so no dynamic user ever owns it. Deciding on an address, and the table
itself, belong to the authenticated mint half.
"""

import logging
import os
import re
import sys
import time

from flask import Flask, Response, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import spool
from budget import Budget
from spool import Spool

SPOOL_PATH = os.environ.get(
    "PORTERO_INTAKE_SPOOL", "/var/lib/gluck-portero-intake/spool.jsonl"
)
SPOOL_MAX = int(os.environ.get("PORTERO_INTAKE_SPOOL_MAX", str(1 << 20)))
RECORD_MAX = int(os.environ.get("PORTERO_INTAKE_RECORD_MAX", str(spool.RECORD_MAX)))
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

FLOODED = "flooded"
MALFORMED = "malformed"

LEVELS = {
    spool.WRITTEN: logging.INFO,
    spool.FULL: logging.WARNING,
    spool.OVERSIZE: logging.WARNING,
    spool.ERROR: logging.ERROR,
    FLOODED: logging.WARNING,
    MALFORMED: logging.INFO,
}
STORE = Spool(SPOOL_PATH, SPOOL_MAX, RECORD_MAX)

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


class JournalFormatter(logging.Formatter):
    """Prefix every line with its sd-daemon priority, so journald records a
    real PRIORITY instead of 6 for everything written to stderr."""

    def __init__(self):
        super().__init__("%(levelname)s %(message)s")

    def format(self, record):
        if record.levelno >= logging.CRITICAL:
            prio = 2
        elif record.levelno >= logging.ERROR:
            prio = 3
        elif record.levelno >= logging.WARNING:
            prio = 4
        elif record.levelno >= logging.INFO:
            prio = 6
        else:
            prio = 7
        return f"<{prio}>" + super().format(record)


def spool_size():
    try:
        return STORE.size()
    except OSError:
        return -1


def record_outcome(outcome, errno_name=None):
    """The one line netmon parses. Its exact form is pinned in test_intake.py."""
    line = (f"intake offer outcome={outcome} spool_bytes={spool_size()} "
            f"spool_max={STORE.max_bytes}")
    if outcome == spool.ERROR:
        line += f" errno={errno_name or 'EUNKNOWN'}"
    log.log(LEVELS[outcome], "%s", line)


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
    if not accepted:
        outcome, errno_name = FLOODED, None
    elif not (EMAIL_RE.fullmatch(email) and len(email) <= MAX_EMAIL):
        outcome, errno_name = MALFORMED, None
    else:
        outcome, errno_name = STORE.offer(email.lower(), note[:MAX_NOTE])
    record_outcome(outcome, errno_name)
    settle(started)
    return page("Thank you", TAKEN, status=202)


def main():
    handler = logging.StreamHandler()
    handler.setFormatter(JournalFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    from waitress import serve
    port = int(os.environ.get("PORT", "9103"))
    serve(app, host="127.0.0.1", port=port, threads=4, ident=None)


if __name__ == "__main__":
    sys.exit(main())
