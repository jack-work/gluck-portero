#!/usr/bin/env python3
"""Spent-nonce store tests. The property is single use under concurrency."""

import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spent import Spent  # noqa: E402


class Claim(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Spent(os.path.join(self.dir, "s.db"))

    def tearDown(self):
        self.store.close()

    def test_first_claim_wins_and_second_loses(self):
        self.assertTrue(self.store.claim("abc", "dad"))
        self.assertFalse(self.store.claim("abc", "dad"))
        self.assertFalse(self.store.claim("abc", "someone-else"))

    def test_distinct_nonces_are_independent(self):
        self.assertTrue(self.store.claim("a", "dad"))
        self.assertTrue(self.store.claim("b", "dad"))
        self.assertEqual(self.store.count(), 2)

    def test_is_spent(self):
        self.assertFalse(self.store.is_spent("zz"))
        self.store.claim("zz", "dad")
        self.assertTrue(self.store.is_spent("zz"))

    def test_survives_reopen(self):
        self.store.claim("persist", "dad")
        self.store.close()
        again = Spent(os.path.join(self.dir, "s.db"))
        try:
            self.assertFalse(again.claim("persist", "dad"))
        finally:
            again.close()

    def test_uniqueness_comes_from_the_database_not_a_prior_read(self):
        # The deterministic version of the race, and the one that actually
        # asks the question. A thread test cannot reliably interleave under
        # the GIL: it passed against a read-then-write implementation, which
        # is exactly the bug it was meant to catch.
        #
        # So: make the read LIE. If claim() decides by consulting is_spent,
        # the second claim succeeds and the token is reusable. If it decides
        # by the primary key, the lie changes nothing.
        self.assertTrue(self.store.claim("pk", "dad"))
        self.store.is_spent = lambda nonce: False
        self.assertFalse(
            self.store.claim("pk", "dad"),
            "claim() consulted a read instead of the primary key",
        )

    def test_exactly_one_winner_under_concurrency(self):
        # Kept as a smoke test only. It does NOT prove atomicity: see above.
        wins = []
        lock = threading.Lock()
        barrier = threading.Barrier(16)

        def go():
            barrier.wait()
            if self.store.claim("racy", "dad"):
                with lock:
                    wins.append(1)

        threads = [threading.Thread(target=go) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(wins), 1, "exactly one claim must succeed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
