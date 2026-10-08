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
os.environ["PORTERO_INTAKE_DB"] = os.path.join(tempfile.mkdtemp(), "intake.db")
os.environ["PORTERO_INTAKE_CAP"] = "4"
os.environ["PORTERO_RESPONSE_FLOOR"] = "0.01"

sys.path.insert(0, _HERE)
import intake as I  # noqa: E402
from pending_admin import IntakeAdmin  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        I.app.config["TESTING"] = True
        self.c = I.app.test_client()
        I.FLOOD.reset()
        self.admin = IntakeAdmin(I.DB_PATH, I.CAP)
        self.admin._db.execute("DELETE FROM intake")

    def tearDown(self):
        self.admin.close()

    def rows(self):
        return self.admin.listing(state=None)

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

    def test_a_full_table_is_also_indistinguishable(self):
        for i in range(I.CAP):
            self.offer(f"user{i}@example.com")
        before = self.offer("first@example.com")
        full = self.offer("one-too-many@example.com")
        self.assertEqual(full.data, before.data)
        self.assertEqual(len(self.rows()), I.CAP)

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
    def test_the_module_imports_no_mailer_and_no_directory_client(self):
        self.assertNotIn("mailer", sys.modules.get("intake").__dict__)
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
