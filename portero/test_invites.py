#!/usr/bin/env python3
"""Invite token tests.

The load-bearing property: a token this process did not sign must never be
interpreted, and every rejection must look the same from outside.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import invites as tok  # noqa: E402

KEY = b"k" * 48
OTHER = b"z" * 48


class Mint(unittest.TestCase):
    def test_round_trip(self):
        t, nonce, exp = tok.mint(KEY, "dad", 3600)
        claim = tok.verify(KEY, t)
        self.assertEqual(claim["username"], "dad")
        self.assertEqual(claim["nonce"], nonce)
        self.assertEqual(claim["expires_at"], exp)

    def test_nonce_is_unique_and_long(self):
        seen = set()
        for _ in range(200):
            _, nonce, _ = tok.mint(KEY, "dad", 60)
            self.assertEqual(len(nonce), tok.NONCE_BYTES)
            seen.add(nonce)
        self.assertEqual(len(seen), 200)

    def test_ttl_must_be_positive(self):
        for bad in (0, -1, -3600):
            with self.assertRaises(ValueError):
                tok.mint(KEY, "dad", bad)

    def test_short_key_refused(self):
        import tempfile

        with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
            fh.write(b"tooshort")
            p = fh.name
        try:
            with self.assertRaises(ValueError):
                tok.load_key(p)
        finally:
            os.unlink(p)


class Verify(unittest.TestCase):
    def bad(self, token, key=KEY, now=None):
        with self.assertRaises(tok.InvalidToken):
            tok.verify(key, token, now=now)

    def test_wrong_key_is_refused(self):
        t, _, _ = tok.mint(KEY, "dad", 3600)
        self.bad(t, key=OTHER)

    def test_expired_is_refused(self):
        t, _, exp = tok.mint(KEY, "dad", 10, now=1000)
        tok.verify(KEY, t, now=1005)
        self.bad(t, now=exp)
        self.bad(t, now=exp + 1)

    def test_tampered_payload_is_refused(self):
        # Re-sign nothing: change the username and keep the signature.
        t, _, _ = tok.mint(KEY, "dad", 3600)
        payload, sig = t.split(".")
        forged = tok._b64e(b'{"e":9999999999,"n":"ff","u":"admin"}')
        self.bad(f"{forged}.{sig}")

    def test_forged_payload_is_never_parsed(self):
        # A payload naming admin, with a signature this key did not produce,
        # must not be interpreted at all.
        forged = tok._b64e(b'{"e":9999999999,"n":"ff","u":"admin"}')
        self.bad(f"{forged}.{tok._b64e(b'nope')}")

    def test_signature_swap_between_tokens(self):
        a, _, _ = tok.mint(KEY, "dad", 3600)
        b, _, _ = tok.mint(KEY, "someone-else", 3600)
        pa, _ = a.split(".")
        _, sb = b.split(".")
        self.bad(f"{pa}.{sb}")

    def test_structural_garbage(self):
        for t in ("", ".", "a.", ".b", "a.b.c", "nodot", "!!!.???"):
            self.bad(t)

    def test_non_string_and_oversize(self):
        for t in (None, 123, b"bytes", [], {}):
            self.bad(t)
        self.bad("a" * (tok.MAX_TOKEN_LEN + 1) + ".sig")

    def test_unsigned_alg_none_style_attack(self):
        # Empty signature must not validate, whatever the payload says.
        payload = tok._b64e(b'{"e":9999999999,"n":"ff","u":"admin"}')
        self.bad(f"{payload}.")

    def test_every_rejection_is_the_same_exception(self):
        cases = ["", "nodot", "a.b.c", tok._b64e(b"{}") + ".zz"]
        for c in cases:
            try:
                tok.verify(KEY, c)
                self.fail(f"accepted {c!r}")
            except tok.InvalidToken as err:
                self.assertEqual(str(err), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
