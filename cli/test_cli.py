#!/usr/bin/env python3
"""The portero CLI against a recording HTTP server and a fake hush.

The properties:

  the token comes from hush and travels only in the Authorization header,
  never in any argv
  each command calls the endpoint it names, with a JSON body
  failures exit non-zero with the server's reason and a hint
  the human output is a table; --json is the server's JSON
"""

import io
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "eyJ.fake-token.sig"
ROWS = [
    {"id": 7, "email": "dad@example.com", "note": "hello\nthere", "received_at": 1792000000,
     "state": "pending", "username": None},
    {"id": 3, "email": "old@example.com", "note": "", "received_at": 1791000000,
     "state": "rejected", "username": None},
]


class Server:
    def __init__(self):
        srv = self
        self.requests = []
        self.answer = lambda method, path, body: (200, {"rows": ROWS, "ingest": "ok"})

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def handle_one(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                srv.requests.append((method, self.path, dict(self.headers), body))
                status, payload = srv.answer(method, self.path, body)
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self.handle_one("GET")

            def do_POST(self):
                self.handle_one("POST")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Base(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.dir = tempfile.mkdtemp()
        self.argv_log = os.path.join(self.dir, "argv.log")
        self.hush = os.path.join(self.dir, "hush")
        self.fake_hush(0)
        os.environ["PORTERO_URL"] = self.server.url
        os.environ["PORTERO_HUSH"] = self.hush
        sys.modules.pop("portero", None)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import portero
        self.cli = portero

    def fake_hush(self, code):
        with open(self.hush, "w") as fh:
            fh.write(f"""#!/bin/sh
printf '%s\\n' "$*" >> {self.argv_log}
if [ "$1 $2 $3" = "oauth get portero-cli" ] && [ {code} = 0 ]; then echo {TOKEN}; fi
exit {code}
""")
        os.chmod(self.hush, os.stat(self.hush).st_mode | stat.S_IEXEC)

    def tearDown(self):
        self.server.close()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()


class Token(Base):
    def test_the_token_rides_only_in_the_header(self):
        code, _, _ = self.run_cli("intake")
        self.assertEqual(code, 0)
        _, _, headers, _ = self.server.requests[0]
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        argv = open(self.argv_log).read()
        self.assertEqual(argv.strip(), "oauth get portero-cli")
        self.assertNotIn(TOKEN, argv)

    def test_no_token_means_no_request_and_a_login_hint(self):
        self.fake_hush(1)
        code, _, err = self.run_cli("intake")
        self.assertEqual(code, 1)
        self.assertIn("portero login", err)
        self.assertEqual(self.server.requests, [])

    def test_login_uses_the_device_flow_for_this_client(self):
        self.server.answer = lambda m, p, b: (200, {"user": "gluck", "groups": ["portero-admin"], "via": "bearer"})
        code, out, _ = self.run_cli("login")
        self.assertEqual(code, 0)
        self.assertIn("oauth device-login portero-cli --issuer https://auth.kelliher.info", open(self.argv_log).read())
        self.assertIn("signed in as gluck", out)


class Commands(Base):
    def last(self):
        return self.server.requests[-1]

    def test_intake_lists_pending_as_a_table(self):
        code, out, _ = self.run_cli("intake")
        self.assertEqual(code, 0)
        self.assertEqual(self.last()[:2], ("GET", "/intake"))
        self.assertEqual(out.splitlines()[0].split(), ["ID", "EMAIL", "RECEIVED", "NOTE"])
        self.assertIn("dad@example.com", out)
        self.assertIn("hello there", out)

    def test_intake_all_asks_for_every_state(self):
        _, out, _ = self.run_cli("intake", "--all")
        self.assertEqual(self.last()[1], "/intake?state=all")
        self.assertIn("rejected", out)

    def test_json_is_the_servers_json(self):
        for argv in (("--json", "intake"), ("intake", "--json")):
            with self.subTest(argv=argv):
                _, out, _ = self.run_cli(*argv)
                self.assertEqual(json.loads(out)["rows"], ROWS)

    def test_approve_sends_username_name_and_sites(self):
        self.server.answer = lambda m, p, b: (201, {"username": "dad", "expires_at": 1792100000, "mailed": True})
        code, out, _ = self.run_cli("approve", "7", "dad", "--sites", "site-files-access,site-cal-access", "--name", "Dad K")
        self.assertEqual(code, 0)
        method, path, headers, body = self.last()
        self.assertEqual((method, path), ("POST", "/intake/7/approve"))
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(body, {"username": "dad", "display_name": "Dad K",
                                "site_access_groups": ["site-files-access", "site-cal-access"]})
        self.assertIn("invite mailed", out)

    def test_reject_retire_send_post_to_their_routes(self):
        self.server.answer = lambda m, p, b: (200, {"username": "dad", "expires_at": 1792100000})
        for verb in ("reject", "retire", "send"):
            with self.subTest(verb=verb):
                self.assertEqual(self.run_cli(verb, "7")[0], 0)
                self.assertEqual(self.last()[:2], ("POST", f"/intake/7/{verb}"))
                self.assertEqual(self.last()[3], {})


class Failures(Base):
    def test_server_errors_exit_one_with_reason_and_hint(self):
        for status, error, hint in ((401, "bearer token refused", "portero login"),
                                    (403, "requires group portero-admin", "not in portero-admin"),
                                    (409, "intake row is approved, not pending", ""),
                                    (503, "identity provider unavailable", "try again")):
            with self.subTest(status=status):
                self.server.answer = lambda m, p, b, s=status, e=error: (s, {"error": e})
                code, out, err = self.run_cli("reject", "7")
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertIn(f"{status} {error}", err)
                self.assertIn(hint, err)

    def test_an_unreachable_server_exits_one(self):
        os.environ["PORTERO_URL"] = "http://127.0.0.1:1"
        sys.modules.pop("portero", None)
        import portero
        self.cli = portero
        code, _, err = self.run_cli("intake")
        self.assertEqual(code, 1)
        self.assertIn("cannot reach", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
