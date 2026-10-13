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
import spool  # noqa: E402
from pending_admin import IntakeAdmin, mac_fields  # noqa: E402

KEY = b"k" * 48


class Base(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.path = os.path.join(d, "intake.db")
        self.spool_path = os.path.join(d, "spool.jsonl")
        open(self.spool_path, "wb").close()
        self.cap = 5
        self.w = spool.Spool(self.spool_path, 1 << 20)
        self.a = IntakeAdmin(self.path, self.cap, spool_path=self.spool_path,
                             offset_path=os.path.join(d, "spool.offset"))

    def offer(self, email, note=""):
        """A submission, the way one really arrives: appended then ingested."""
        self.w.offer(email, note)
        return self.a.ingest()

    def tearDown(self):
        self.w.close()
        self.a.close()


class Ingest(Base):
    def test_offer_is_written(self):
        self.offer("dad@example.com", "hello")
        rows = self.a.listing()
        self.assertEqual([r["email"] for r in rows], ["dad@example.com"])
        self.assertEqual(rows[0]["state"], "pending")

    def test_the_public_half_learns_nothing_from_a_write(self):
        # It cannot be used to test whether an address is already known. The
        # spool's own tests prove the descriptor is unreadable; this proves the
        # append returns no outcome either.
        self.assertIsNone(self.w.offer("dad@example.com"))
        self.assertIsNone(self.w.offer("dad@example.com"))
        self.assertIsNone(self.w.offer("not an email"))

    def test_a_duplicate_address_lands_once_in_the_table(self):
        # At-least-once ingestion plus UNIQUE(email) is exactly-once.
        self.offer("dad@example.com")
        self.offer("dad@example.com")
        self.assertEqual(len(self.a.listing()), 1)

    def test_replayed_ingestion_cannot_duplicate_a_row(self):
        self.offer("dad@example.com")
        with open(self.a.offset_path, "w", encoding="utf-8") as fh:
            fh.write("0")
        self.assertEqual(self.a.ingest(), 0, "the INSERT must be swallowed")
        self.assertEqual(len(self.a.listing()), 1)

    def test_duplicate_is_swallowed_and_stores_one_row(self):
        self.offer("dad@example.com")
        self.offer("dad@example.com")
        self.assertEqual(len(self.a.listing()), 1)

    def test_cap_is_enforced_by_the_schema(self):
        for i in range(self.cap):
            self.offer(f"user{i}@example.com")
        self.offer("one-too-many@example.com")
        rows = self.a.listing()
        self.assertEqual(len(rows), self.cap)
        self.assertNotIn("one-too-many@example.com", [r["email"] for r in rows])

    def test_cap_counts_only_pending_rows(self):
        # setUp already holds one pending row, so the last of these waits.
        # An earlier version of this test expected the NEXT submission to land
        # after a reject, which was only true because the waiting one had been
        # silently consumed and lost.
        for i in range(self.cap):
            self.offer(f"user{i}@example.com")
        last = f"user{self.cap - 1}@example.com"
        self.assertNotIn(last, [r["email"] for r in self.a.listing()])
        self.assertTrue(self.a.reject(1, "admin"))
        self.offer("now-there-is-room@example.com")
        emails = [r["email"] for r in self.a.listing()]
        self.assertIn(last, emails, "the oldest waiting record takes the freed slot")
        self.assertNotIn("now-there-is-room@example.com", emails)

    def setUp(self):
        super().setUp()
        self.offer("dad@example.com")
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
        self.offer("second@example.com")
        self.a.claim(self.row, "dad", "admin")
        self.assertEqual(len(self.a.listing(state="pending")), 1)
        self.assertEqual(len(self.a.listing(state="approved")), 1)
        self.assertEqual(self.a.counts(), {"pending": 1, "approved": 1})


class DecisionMac(Base):
    def setUp(self):
        super().setUp()
        self.offer("dad@example.com")
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



class FullTableDefers(Base):
    """A full table is a queue, not a drain.

    The first version swallowed the cap refusal together with duplicates and
    advanced the offset past it, so a real signup arriving while 200 rows were
    pending was consumed and lost, and freeing a slot did not bring it back.
    """

    def fill(self):
        for i in range(self.cap):
            self.offer(f"user{i}@example.com")

    def test_the_refused_record_stays_in_the_spool(self):
        self.fill()
        self.w.offer("waiting@example.com")
        self.assertEqual(self.a.ingest(), 0)
        self.assertLess(self.a.offset(), os.path.getsize(self.spool_path))
        self.assertNotIn("waiting@example.com",
                         [r["email"] for r in self.a.listing(state=None)])

    def test_it_lands_once_a_slot_frees(self):
        self.fill()
        self.w.offer("waiting@example.com")
        self.a.ingest()
        self.a.reject(self.a.listing()[0]["id"], "admin")
        self.assertEqual(self.a.ingest(), 1)
        self.assertIn("waiting@example.com",
                      [r["email"] for r in self.a.listing(state=None)])
        self.assertEqual(self.a.offset(), os.path.getsize(self.spool_path))

    def test_records_behind_it_wait_in_order(self):
        self.fill()
        self.w.offer("first@example.com")
        self.w.offer("second@example.com")
        self.a.ingest()
        self.a.reject(self.a.listing()[0]["id"], "admin")
        self.a.ingest()
        emails = [r["email"] for r in self.a.listing(state=None)]
        self.assertIn("first@example.com", emails)
        self.assertNotIn("second@example.com", emails,
                         "one freed slot admits exactly one record")

    def test_a_duplicate_still_advances_when_there_is_room(self):
        self.offer("dad@example.com")
        self.w.offer("dad@example.com")
        self.w.offer("next@example.com")
        self.assertEqual(self.a.ingest(), 1)
        self.assertEqual(self.a.offset(), os.path.getsize(self.spool_path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
