import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("PORTERO_URL", "https://portero.kelliher.info").rstrip("/")
ISSUER = os.environ.get("PORTERO_ISSUER", "https://auth.kelliher.info")
CLIENT = "portero-cli"
HUSH = os.environ.get("PORTERO_HUSH", "hush")


class Failed(Exception):
    pass


def token():
    try:
        out = subprocess.run([HUSH, "oauth", "get", CLIENT], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        raise Failed("hush is not on PATH") from None
    if out.returncode != 0 or not out.stdout.strip():
        raise Failed(f"no token from hush for {CLIENT}: run `portero login`")
    return out.stdout.strip()


def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={
        "Authorization": "Bearer " + token(),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "portero-cli/1",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            return json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as err:
        try:
            message = json.loads(err.read()).get("error", "")
        except ValueError:
            message = ""
        hint = {401: "token refused: run `portero login`",
                403: "your account is not in portero-admin",
                503: "the identity provider is unavailable; try again"}.get(err.code, "")
        raise Failed(f"{err.code} {message or err.reason}" + (f" ({hint})" if hint else "")) from None
    except urllib.error.URLError as err:
        raise Failed(f"cannot reach {BASE}: {err.reason}") from None


def when(epoch):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch)) if epoch else ""


def table(rows, columns):
    cells = [[str(r.get(k) if r.get(k) is not None else "") for k, _ in columns] for r in rows]
    widths = [max([len(h)] + [len(c[i]) for c in cells]) for i, (_, h) in enumerate(columns)]
    lines = ["  ".join(h.ljust(w) for (_, h), w in zip(columns, widths)).rstrip()]
    lines += ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in cells]
    return "\n".join(lines)


def show(args, data, human):
    print(json.dumps(data, indent=2, sort_keys=True) if args.json else human(data))


def cmd_login(args):
    code = subprocess.call([HUSH, "oauth", "device-login", CLIENT, "--issuer", ISSUER])
    if code != 0:
        raise Failed("login failed")
    who = call("GET", "/invites/whoami")
    print(f"signed in as {who['user']}" + ("" if "portero-admin" in who["groups"] else " (NOT in portero-admin)"))


def cmd_intake(args):
    data = call("GET", "/intake" + ("?state=all" if args.all else ""))

    def human(d):
        rows = [dict(r, received=when(r["received_at"]), note=(r["note"] or "").replace("\n", " ")[:40])
                for r in sorted(d["rows"], key=lambda r: r["id"])]
        if not rows:
            text = "no pending signups" if not args.all else "no signups"
        else:
            columns = [("id", "ID"), ("state", "STATE"), ("email", "EMAIL"), ("username", "USER"),
                       ("received", "RECEIVED"), ("note", "NOTE")]
            if not args.all:
                columns = [c for c in columns if c[0] not in ("state", "username")]
            text = table(rows, columns)
        if d.get("ingest") == "error":
            text += f"\nwarning: the spool could not be read ({d.get('ingest_errno')}); signups are waiting"
        return text

    show(args, data, human)


def cmd_approve(args):
    body = {"username": args.username, "display_name": args.name or "",
            "site_access_groups": [s for s in (args.sites or "").split(",") if s]}
    data = call("POST", f"/intake/{args.id}/approve", body)
    show(args, data, lambda d: f"approved #{args.id} as {d['username']}, link expires {when(d['expires_at'])}, "
                               + ("invite mailed" if d.get("mailed") else f"mail FAILED: {d.get('mail_error')}"))


def cmd_reject(args):
    show(args, call("POST", f"/intake/{args.id}/reject", {}), lambda d: f"rejected #{args.id}")


def cmd_retire(args):
    show(args, call("POST", f"/intake/{args.id}/retire", {}), lambda d: f"retired #{args.id} ({d['username']})")


def cmd_send(args):
    show(args, call("POST", f"/intake/{args.id}/send", {}),
         lambda d: f"mailed #{args.id} to {d['username']}, link expires {when(d['expires_at'])}")


def parser():
    p = argparse.ArgumentParser(prog="portero", description="Handle portero's signup intake from a terminal.")
    p.add_argument("--json", action="store_true", help="print the server's JSON instead of a table")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("login", help="sign in with the device flow; hush keeps the token").set_defaults(run=cmd_login)
    i = sub.add_parser("intake", help="list signups (pending unless --all)")
    i.add_argument("--all", action="store_true", help="every state, not only pending")
    i.set_defaults(run=cmd_intake)
    a = sub.add_parser("approve", help="create the account and mail its invite")
    a.add_argument("id", type=int)
    a.add_argument("username")
    a.add_argument("--sites", help="comma-separated site access groups to grant")
    a.add_argument("--name", help="display name")
    a.set_defaults(run=cmd_approve)
    for name, run, text in (("reject", cmd_reject, "refuse a pending signup"),
                            ("retire", cmd_retire, "close an approved row whose account is gone"),
                            ("send", cmd_send, "mail an approved row's invite again")):
        c = sub.add_parser(name, help=text)
        c.add_argument("id", type=int)
        c.set_defaults(run=run)
    for c in sub.choices.values():
        c.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        args.run(args)
    except Failed as err:
        print(f"portero: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
