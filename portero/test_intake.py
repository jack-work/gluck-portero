#!/usr/bin/env python3
"""Intake endpoint tests.

This is the second unauthenticated endpoint on the estate, and it is the one
with no credential at all. The properties:

  every POST renders the same bytes with the same status: accepted, duplicate,
    malformed, flooded and full are indistinguishable
  there is no route that returns a stored row
  nothing is ever mailed from here
  the submitted address never reaches a log
"""

import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPOOL = os.path.join(tempfile.mkdtemp(), "spool.jsonl")
open(_SPOOL, "wb").close()
os.environ["PORTERO_INTAKE_SPOOL"] = _SPOOL
os.environ["PORTERO_RESPONSE_FLOOR"] = "0.05"

sys.path.insert(0, _HERE)
import intake as I  # noqa: E402
import spool  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        I.app.config["TESTING"] = True
        self.c = I.app.test_client()
        I.FLOOD.reset()
        I.STORE.max_bytes = 1 << 20
        open(_SPOOL, "wb").close()

    def rows(self):
        records, _ = spool.read_from(_SPOOL, 0)
        return records

    def offer(self, email="dad@example.com", note=""):
        return self.c.post("/intake", data={"email": email, "note": note})


class OneResponse(Base):
    def test_a_good_address_is_stored(self):
        r = self.offer()
        self.assertEqual(r.status_code, 202)
        self.assertEqual([x["email"] for x in self.rows()], ["dad@example.com"])

    def test_every_outcome_renders_the_same_bytes(self):
        good = self.offer("one@example.com")
        duplicate = self.offer("one@example.com")
        malformed = self.offer("not-an-email")
        empty = self.offer("")
        oversize = self.offer("a" * 300 + "@example.com")
        for other in (duplicate, malformed, empty, oversize):
            self.assertEqual(other.status_code, good.status_code)
            self.assertEqual(other.data, good.data)

    def test_a_full_spool_is_also_indistinguishable(self):
        before = self.offer("first@example.com")
        I.STORE.max_bytes = os.path.getsize(_SPOOL)
        full = self.offer("one-too-many@example.com")
        self.assertEqual(full.status_code, before.status_code)
        self.assertEqual(full.data, before.data)
        self.assertEqual([r["email"] for r in self.rows()], ["first@example.com"])

    def test_a_full_spool_is_not_measurably_faster(self):
        # The refusal is an fstat and no write, which is a CHEAPER path than an
        # accepted append, so byte equality is not enough: the floor has to be
        # measured rather than merely present in the source.
        import time
        self.offer("first@example.com")
        t0 = time.monotonic(); self.offer("second@example.com"); accepted = time.monotonic() - t0
        I.STORE.max_bytes = os.path.getsize(_SPOOL)
        t0 = time.monotonic(); self.offer("third@example.com"); refused = time.monotonic() - t0
        self.assertGreaterEqual(refused, I.FLOOR_SECONDS * 0.9)
        self.assertLess(abs(refused - accepted), I.FLOOR_SECONDS * 0.5,
                        f"accepted {accepted:.3f}s vs refused {refused:.3f}s")

    def test_the_duplicate_and_the_flooded_are_not_measurably_faster_either(self):
        import time
        self.offer("one@example.com")
        t0 = time.monotonic(); self.offer("one@example.com"); dupe = time.monotonic() - t0
        I.FLOOD.limit = 0
        try:
            t0 = time.monotonic(); self.offer("two@example.com"); flooded = time.monotonic() - t0
        finally:
            I.FLOOD.limit = 120
        for name, seen in (("duplicate", dupe), ("flooded", flooded)):
            self.assertGreaterEqual(seen, I.FLOOR_SECONDS * 0.9, name)

    def test_a_flooded_request_is_also_indistinguishable(self):
        normal = self.offer("first@example.com")
        I.FLOOD.limit = 0
        try:
            flooded = self.offer("second@example.com")
        finally:
            I.FLOOD.limit = 120
        self.assertEqual(flooded.status_code, normal.status_code)
        self.assertEqual(flooded.data, normal.data)
        self.assertEqual([x["email"] for x in self.rows()], ["first@example.com"])

    def test_the_address_is_lowercased(self):
        self.offer("Dad@Example.COM")
        self.assertEqual(self.rows()[0]["email"], "dad@example.com")

    def test_the_public_half_cannot_read_its_own_spool(self):
        # The property this redesign exists for, asserted against the app the
        # unit actually serves rather than against the module in isolation.
        self.offer("dad@example.com")
        with self.assertRaises(OSError) as caught:
            os.read(I.STORE._fd, 64)
        self.assertEqual(caught.exception.errno, 9, "want EBADF")

    def test_the_note_is_truncated_not_refused(self):
        self.offer("dad@example.com", "x" * 5000)
        self.assertEqual(len(self.rows()[0]["note"]), I.MAX_NOTE)


class NoReadPath(Base):
    def test_no_route_returns_a_row(self):
        self.offer("secret@example.com")
        seen = []
        for rule in I.app.url_map.iter_rules():
            if "GET" in rule.methods:
                body = self.c.get(str(rule)).data
                seen.append(body)
        self.assertTrue(seen)
        for body in seen:
            self.assertNotIn(b"secret@example.com", body)

    def test_the_only_routes_are_the_form_the_submit_and_healthz(self):
        rules = sorted(str(r) for r in I.app.url_map.iter_rules()
                       if not str(r).startswith("/static"))
        self.assertEqual(rules, ["/healthz", "/intake", "/intake"])

    def test_the_form_is_the_same_page_whatever_is_stored(self):
        first = self.c.get("/intake").data
        self.offer("dad@example.com")
        self.assertEqual(self.c.get("/intake").data, first)


class NoCredentialNoMail(Base):
    def test_the_module_imports_no_mailer_no_client_and_no_sqlite(self):
        self.assertNotIn("mailer", sys.modules.get("intake").__dict__)
        self.assertNotIn("sqlite3", sys.modules.get("intake").__dict__)
        self.assertNotIn("pending_admin", sys.modules.get("intake").__dict__)
        for forbidden in ("smtplib", "requests", "subprocess"):
            here = os.path.join(_HERE, "intake.py")
            with open(here, encoding="utf-8") as fh:
                self.assertNotIn(forbidden, fh.read())

    def test_it_reads_no_credential(self):
        with open(os.path.join(_HERE, "intake.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("CREDENTIALS_DIRECTORY", src)
        self.assertNotIn("invite_key", src)


class Logging(Base):
    def test_the_address_is_never_logged(self):
        with self.assertLogs("portero-intake", level="INFO") as cap:
            self.offer("private-person@example.com")
            self.offer("not-an-email")
        blob = "\n".join(cap.output)
        self.assertNotIn("private-person", blob)
        self.assertIn("written", blob)
        self.assertIn("dropped", blob)


class Headers(Base):
    def test_no_referrer_and_no_store(self):
        r = self.offer()
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(r.headers["Cache-Control"], "no-store, max-age=0")
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
