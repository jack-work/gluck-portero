#!/usr/bin/env python3
"""Intake table tests.

The properties:

  the writer has no statement that reads a row back
  the cap is enforced by the schema, not by the application
  an approval is a conditional UPDATE, so two admins produce one winner
  a row edited behind mint's back fails its decision MAC
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import invites  # noqa: E402
import pending  # noqa: E402
from pending_admin import IntakeAdmin, mac_fields  # noqa: E402

KEY = b"k" * 48


class Base(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "intake.db")
        self.cap = 5
        self.w = pending.Intake(self.path, self.cap)
        self.a = IntakeAdmin(self.path, self.cap)

    def tearDown(self):
        self.w.close()
        self.a.close()


class Writer(Base):
    def test_offer_is_written(self):
        self.w.offer("dad@example.com", "hello")
        rows = self.a.listing()
        self.assertEqual([r["email"] for r in rows], ["dad@example.com"])
        self.assertEqual(rows[0]["state"], "pending")

    def test_offer_returns_nothing_whatever_happens(self):
        # The write-only property: the public unit learns nothing from a write,
        # so it cannot be used to test whether an address is already known.
        self.assertIsNone(self.w.offer("dad@example.com"))
        self.assertIsNone(self.w.offer("dad@example.com"))
        self.assertIsNone(self.w.offer("not an email"))

    def test_duplicate_is_swallowed_and_stores_one_row(self):
        self.w.offer("dad@example.com")
        self.w.offer("dad@example.com")
        self.assertEqual(len(self.a.listing()), 1)

    def test_writer_module_issues_no_select(self):
        # Negative control for the claim "no read path": the only SELECT in the
        # writer's module is inside the cap trigger's own WHEN clause.
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "pending.py"), encoding="utf-8") as fh:
            src = fh.read()
        body = src.split("class Intake")[1]
        self.assertNotIn("SELECT", body.upper())

    def test_cap_is_enforced_by_the_schema(self):
        for i in range(self.cap):
            self.w.offer(f"user{i}@example.com")
        self.w.offer("one-too-many@example.com")
        rows = self.a.listing()
        self.assertEqual(len(rows), self.cap)
        self.assertNotIn("one-too-many@example.com", [r["email"] for r in rows])

    def test_cap_counts_only_pending_rows(self):
        for i in range(self.cap):
            self.w.offer(f"user{i}@example.com")
        self.assertTrue(self.a.reject(1, "admin"))
        self.w.offer("now-there-is-room@example.com")
        self.assertIn("now-there-is-room@example.com",
                      [r["email"] for r in self.a.listing()])

    def test_the_trigger_fires_without_the_application(self):
        # Break the application's politeness and go straight at sqlite: the cap
        # must hold even for a caller that does not catch the exception.
        for i in range(self.cap):
            self.w.offer(f"user{i}@example.com")
        db = pending.connect(self.path, self.cap)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("INSERT INTO intake (email, received_at) VALUES (?,?)",
                       ("raw@example.com", 0))
        db.close()


class SharedFiles(unittest.TestCase):
    """Two units, two dynamic uids, one table. The modes have to allow it."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "intake.db")
        self.old_umask = os.umask(0o077)

    def tearDown(self):
        os.umask(self.old_umask)

    def test_every_file_is_group_writable_after_connect(self):
        # The failure this defends: sqlite's base mode is 0644, so under any
        # umask the group write bit is absent and the mint unit cannot write a
        # table the intake unit created.
        w = pending.Intake(self.path, 4)
        w.offer("dad@example.com")
        try:
            for suffix in ("", "-wal", "-shm"):
                f = self.path + suffix
                self.assertTrue(os.path.exists(f), f)
                mode = os.stat(f).st_mode & 0o777
                self.assertTrue(mode & 0o060 == 0o060,
                                f"{suffix or 'db'} is {oct(mode)}, not group rw")
        finally:
            w.close()

    def test_a_second_opener_does_not_lose_the_mode(self):
        w = pending.Intake(self.path, 4)
        a = IntakeAdmin(self.path, 4)
        try:
            a.claim(1, "dad", "admin")
            for suffix in ("", "-wal", "-shm"):
                mode = os.stat(self.path + suffix).st_mode & 0o777
                self.assertEqual(mode & 0o060, 0o060, suffix)
        finally:
            w.close()
            a.close()


class StateMachine(Base):
    def setUp(self):
        super().setUp()
        self.w.offer("dad@example.com")
        self.row = self.a.listing()[0]["id"]

    def test_claim_has_exactly_one_winner(self):
        self.assertTrue(self.a.claim(self.row, "dad", "admin"))
        self.assertFalse(self.a.claim(self.row, "someone-else", "admin2"))
        self.assertEqual(self.a.get(self.row)["username"], "dad")

    def test_release_puts_a_row_back(self):
        self.a.claim(self.row, "dad", "admin")
        self.assertTrue(self.a.release(self.row))
        row = self.a.get(self.row)
        self.assertEqual(row["state"], "pending")
        self.assertIsNone(row["username"])

    def test_reject_only_applies_to_pending(self):
        self.assertTrue(self.a.reject(self.row, "admin"))
        self.assertFalse(self.a.reject(self.row, "admin"))

    def test_claimed_row_cannot_be_rejected(self):
        self.a.claim(self.row, "dad", "admin")
        self.assertFalse(self.a.reject(self.row, "admin"))

    def test_send_count_accumulates(self):
        self.a.record_sent(self.row, now=10)
        self.a.record_sent(self.row, now=20)
        row = self.a.get(self.row)
        self.assertEqual(row["send_count"], 2)
        self.assertEqual(row["sent_at"], 20)

    def test_listing_filters_by_state(self):
        self.w.offer("second@example.com")
        self.a.claim(self.row, "dad", "admin")
        self.assertEqual(len(self.a.listing(state="pending")), 1)
        self.assertEqual(len(self.a.listing(state="approved")), 1)
        self.assertEqual(self.a.counts(), {"pending": 1, "approved": 1})


class DecisionMac(Base):
    def setUp(self):
        super().setUp()
        self.w.offer("dad@example.com")
        self.id = self.a.listing()[0]["id"]
        self.a.claim(self.id, "dad", "admin")
        self.nonce, self.expires = "a" * 32, 2_000_000_000
        self.a.record_claim_material(
            self.id, self.nonce, self.expires,
            invites.decision_mac(KEY, {"id": self.id, "email": "dad@example.com",
                                       "username": "dad", "nonce": self.nonce,
                                       "expires_at": self.expires}),
        )

    def test_an_untouched_row_verifies(self):
        row = self.a.get(self.id)
        self.assertTrue(invites.decision_ok(KEY, mac_fields(row), row["mac"]))

    def test_a_rewritten_recipient_fails(self):
        # The attack: the public intake unit can write this table. Point an
        # approved row at an attacker's address and wait for an admin to resend.
        self.a._db.execute("UPDATE intake SET email='evil@example.com' WHERE id=?",
                           (self.id,))
        row = self.a.get(self.id)
        self.assertFalse(invites.decision_ok(KEY, mac_fields(row), row["mac"]))

    def test_a_rewritten_username_fails(self):
        self.a._db.execute("UPDATE intake SET username='admin' WHERE id=?",
                           (self.id,))
        row = self.a.get(self.id)
        self.assertFalse(invites.decision_ok(KEY, mac_fields(row), row["mac"]))

    def test_a_forged_approved_row_fails(self):
        self.a._db.execute(
            "INSERT INTO intake (email, received_at, state, username, nonce, "
            "expires_at, mac) VALUES (?,?,?,?,?,?,?)",
            ("evil@example.com", 0, "approved", "admin", "b" * 32,
             2_000_000_000, "whatever"),
        )
        row = self.a.listing(state="approved")[-1]
        self.assertFalse(invites.decision_ok(KEY, mac_fields(row), row["mac"]))

    def test_another_key_cannot_produce_the_mac(self):
        row = self.a.get(self.id)
        self.assertFalse(invites.decision_ok(b"z" * 48, mac_fields(row), row["mac"]))

    def test_missing_mac_fails(self):
        self.assertFalse(invites.decision_ok(KEY, {"id": 1}, None))
        self.assertFalse(invites.decision_ok(KEY, {"id": 1}, ""))


class Resign(unittest.TestCase):
    def test_a_stored_nonce_rebuilds_the_same_token(self):
        # Why the row stores a nonce and not a token: the nonce is useless to a
        # holder of the database, and mint can rebuild the one live link.
        token, nonce, expires = invites.mint(KEY, "dad", 3600)
        self.assertEqual(invites.sign(KEY, "dad", expires, nonce), token)

    def test_the_rebuilt_token_verifies(self):
        _, nonce, expires = invites.mint(KEY, "dad", 3600)
        again = invites.sign(KEY, "dad", expires, nonce)
        self.assertEqual(invites.verify(KEY, again)["nonce"], nonce)

    def test_a_nonce_alone_does_not_make_a_token(self):
        _, nonce, expires = invites.mint(KEY, "dad", 3600)
        forged = invites.sign(b"z" * 48, "dad", expires, nonce)
        with self.assertRaises(invites.InvalidToken):
            invites.verify(KEY, forged)


if __name__ == "__main__":
    unittest.main(verbosity=2)
