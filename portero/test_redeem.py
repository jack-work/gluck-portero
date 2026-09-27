#!/usr/bin/env python3
"""Redeem endpoint tests.

What is under test is the public surface of the only unauthenticated endpoint on
the estate that touches the directory. The properties:

  a token we did not sign is refused
  invalid, expired and already-used are INDISTINGUISHABLE
  a link works exactly once, even if the second attempt is concurrent
  the token never appears in a log
  the response carries no-referrer, because the token is in the URL
"""

import os
import sys
import tempfile
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CREDS = tempfile.mkdtemp()
_STATE = tempfile.mkdtemp()
KEY = b"k" * 48
with open(os.path.join(_CREDS, "invite_key"), "wb") as fh:
    fh.write(KEY)
with open(os.path.join(_CREDS, "redeem_password"), "w") as fh:
    fh.write("service-account-password")

os.environ["CREDENTIALS_DIRECTORY"] = _CREDS
os.environ["STATE_DIRECTORY"] = _STATE
os.environ["PORTERO_RESPONSE_FLOOR"] = "0.01"
os.environ["PORTERO_RATE_LIMIT"] = "1000"

sys.path.insert(0, _HERE)
import invites  # noqa: E402
import redeem as R  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        R.app.config["TESTING"] = True
        self.c = R.app.test_client()
        self.calls = []
        R.set_password = lambda u, p: (self.calls.append((u, p)), True)[1]
        with R._hits_lock:
            R._hits.clear()

    def tok(self, user="dad", ttl=3600):
        t, nonce, _ = invites.mint(KEY, user, ttl)
        return t, nonce


class Refusal(Base):
    def test_garbage_token_is_refused(self):
        for bad in ("nope", "a.b", "a.b.c", "", "x" * 2000):
            r = self.c.get(f"/i/{bad}")
            self.assertIn(r.status_code, (404, 308, 405))

    def test_token_signed_by_another_key_is_refused(self):
        other, _, _ = invites.mint(b"z" * 48, "dad", 3600)
        r = self.c.get(f"/i/{other}")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"Set your password", r.data)

    def test_expired_token_is_refused(self):
        t, _, _ = invites.mint(KEY, "dad", 60, now=time.time() - 3600)
        r = self.c.get(f"/i/{t}")
        self.assertEqual(r.status_code, 404)

    def test_invalid_expired_and_used_are_indistinguishable(self):
        # The oracle test. All three must produce the same status and the same
        # bytes, or the endpoint reveals which usernames and tokens exist.
        invalid = self.c.get("/i/totally-invalid")

        expired, _, _ = invites.mint(KEY, "dad", 60, now=time.time() - 3600)
        expired_r = self.c.get(f"/i/{expired}")

        used, nonce = self.tok("dad")
        R.STORE.claim(nonce, "dad")
        used_r = self.c.get(f"/i/{used}")

        self.assertEqual(invalid.status_code, expired_r.status_code)
        self.assertEqual(expired_r.status_code, used_r.status_code)
        self.assertEqual(invalid.data, expired_r.data)
        self.assertEqual(expired_r.data, used_r.data)

    def test_refusal_does_not_name_the_user(self):
        t, nonce = self.tok("verysecretusername")
        R.STORE.claim(nonce, "verysecretusername")
        r = self.c.get(f"/i/{t}")
        self.assertNotIn(b"verysecretusername", r.data)


class Flow(Base):
    def test_get_shows_the_form_for_a_valid_token(self):
        t, _ = self.tok()
        r = self.c.get(f"/i/{t}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Set my password", r.data)
        self.assertIn(b"dad", r.data)

    def test_post_sets_the_password(self):
        t, nonce = self.tok()
        r = self.c.post(f"/i/{t}", data={"password": "a-good-long-password",
                                         "confirm": "a-good-long-password"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.calls, [("dad", "a-good-long-password")])
        self.assertTrue(R.STORE.is_spent(nonce))

    def test_link_works_exactly_once(self):
        t, _ = self.tok()
        first = self.c.post(f"/i/{t}", data={"password": "a-good-long-password",
                                            "confirm": "a-good-long-password"})
        self.assertEqual(first.status_code, 200)
        second = self.c.post(f"/i/{t}", data={"password": "another-long-password",
                                             "confirm": "another-long-password"})
        self.assertEqual(second.status_code, 404)
        self.assertEqual(len(self.calls), 1, "password was set twice")

    def test_short_password_refused_and_nonce_not_spent(self):
        t, nonce = self.tok()
        r = self.c.post(f"/i/{t}", data={"password": "short", "confirm": "short"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.calls, [])
        self.assertFalse(R.STORE.is_spent(nonce), "a typo must not burn the link")

    def test_mismatch_refused_and_nonce_not_spent(self):
        t, nonce = self.tok()
        r = self.c.post(f"/i/{t}", data={"password": "a-good-long-password",
                                         "confirm": "a-different-password"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.calls, [])
        self.assertFalse(R.STORE.is_spent(nonce))

    def test_nonce_is_spent_even_if_set_password_fails(self):
        t, nonce = self.tok()
        R.set_password = lambda u, p: False
        r = self.c.post(f"/i/{t}", data={"password": "a-good-long-password",
                                         "confirm": "a-good-long-password"})
        self.assertEqual(r.status_code, 500)
        self.assertTrue(R.STORE.is_spent(nonce),
                        "the link must burn rather than allow a second attempt")


class Headers(Base):
    def test_no_referrer_because_the_token_is_in_the_url(self):
        t, _ = self.tok()
        r = self.c.get(f"/i/{t}")
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(r.headers["Cache-Control"], "no-store, max-age=0")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'none'", r.headers["Content-Security-Policy"])

    def test_refusal_also_carries_the_headers(self):
        r = self.c.get("/i/bogus")
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")


class Limits(Base):
    def test_rate_limit_trips(self):
        R.RATE_LIMIT, R.RATE_WINDOW = 3, 60
        try:
            codes = [self.c.get("/i/bogus").status_code for _ in range(5)]
        finally:
            R.RATE_LIMIT, R.RATE_WINDOW = 1000, 60
        self.assertEqual(codes[:3], [404, 404, 404])
        self.assertEqual(codes[3:], [429, 429])

    def test_healthz_is_open(self):
        self.assertEqual(self.c.get("/healthz").status_code, 200)


class Logging(Base):
    def test_token_is_never_logged(self):
        t, _ = self.tok()
        with self.assertLogs("portero-redeem", level="INFO") as cap:
            self.c.post(f"/i/{t}", data={"password": "a-good-long-password",
                                         "confirm": "a-good-long-password"})
        blob = "\n".join(cap.output)
        self.assertNotIn(t, blob)
        payload = t.split(".")[0]
        self.assertNotIn(payload, blob)
        self.assertIn("dad", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
