#!/usr/bin/env python3
"""Spool tests.

The properties this file defends, in order of how much they would cost:

  no row is lost when an append lands during a consumption
  the writer cannot read, enforced by the kernel rather than by review
  a torn tail waits for the rest instead of being dropped or half-parsed
  the cap is a size, and declining looks identical to accepting
"""

import json
import os
import tempfile
import unittest

import spool


def fresh(max_bytes=1 << 20):
    path = os.path.join(tempfile.mkdtemp(), "spool.jsonl")
    open(path, "wb").close()
    return path, spool.Spool(path, max_bytes)


class Blindness(unittest.TestCase):
    def test_the_writer_descriptor_cannot_be_read(self):
        # The upgrade this design exists for: "the public half cannot read the
        # table back" stops being a claim about code and becomes EBADF.
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("dad@example.com")
        with self.assertRaises(OSError) as caught:
            os.read(s._fd, 64)
        self.assertEqual(caught.exception.errno, 9, "want EBADF")

    def test_the_writer_never_opens_for_reading(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "spool.py"), encoding="utf-8") as fh:
            src = fh.read()
        writer = src.split("class Spool")[1].split("def entries_from")[0]
        self.assertNotIn("O_RDWR", writer)
        self.assertNotIn("O_RDONLY", writer)
        self.assertNotIn("open(", writer.replace("os.open(", ""))


class NoLoss(unittest.TestCase):
    def test_an_append_during_consumption_is_not_lost(self):
        # The race the consumer must not have: read to EOF, then a submission
        # lands, then the consumer advances. With a truncate the new row would
        # be destroyed; with an offset it is simply next.
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("first@example.com")
        rows, off = spool.read_from(path, 0)
        self.assertEqual([r["email"] for r in rows], ["first@example.com"])
        s.offer("during@example.com")
        rows2, off2 = spool.read_from(path, off)
        self.assertEqual([r["email"] for r in rows2], ["during@example.com"])
        self.assertGreater(off2, off)

    def test_consuming_twice_yields_nothing_the_second_time(self):
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("one@example.com")
        _, off = spool.read_from(path, 0)
        self.assertEqual(spool.read_from(path, off), ([], off))

    def test_replaying_an_offset_replays_rows_rather_than_skipping_them(self):
        # At-least-once is the contract: a crash before the offset is stored
        # re-reads, and UNIQUE(email) in the table swallows the duplicate.
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("one@example.com")
        s.offer("two@example.com")
        first, _ = spool.read_from(path, 0)
        again, _ = spool.read_from(path, 0)
        self.assertEqual([r["email"] for r in first], [r["email"] for r in again])

    def test_an_offset_past_the_end_restarts_rather_than_failing(self):
        # After a root-side reclaim the stored offset is beyond the file.
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("one@example.com")
        rows, off = spool.read_from(path, 10_000)
        self.assertEqual([r["email"] for r in rows], ["one@example.com"])
        self.assertGreater(off, 0)


class TornTail(unittest.TestCase):
    def test_a_partial_line_is_not_consumed(self):
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("whole@example.com")
        with open(path, "ab") as fh:
            fh.write(b'{"email":"half@examp')
        rows, off = spool.read_from(path, 0)
        self.assertEqual([r["email"] for r in rows], ["whole@example.com"])
        self.assertEqual(off, os.path.getsize(path) - len('{"email":"half@examp'))

    def test_the_rest_of_a_torn_line_is_consumed_when_it_arrives(self):
        path, s = fresh()
        self.addCleanup(s.close)
        with open(path, "ab") as fh:
            fh.write(b'{"email":"half@exa')
        rows, off = spool.read_from(path, 0)
        self.assertEqual(rows, [])
        self.assertEqual(off, 0)
        with open(path, "ab") as fh:
            fh.write(b'mple.com","note":"","at":1}\n')
        rows, off = spool.read_from(path, 0)
        self.assertEqual([r["email"] for r in rows], ["half@example.com"])

    def test_a_garbage_line_is_skipped_without_losing_its_neighbours(self):
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("before@example.com")
        with open(path, "ab") as fh:
            fh.write(b"not json at all\n")
        s.offer("after@example.com")
        rows, _ = spool.read_from(path, 0)
        self.assertEqual([r["email"] for r in rows],
                         ["before@example.com", "after@example.com"])


class Cap(unittest.TestCase):
    def test_the_cap_is_a_size_and_holds(self):
        path, s = fresh(max_bytes=200)
        self.addCleanup(s.close)
        for i in range(50):
            s.offer(f"user{i}@example.com")
        self.assertLessEqual(os.path.getsize(path), 200)

    def test_each_outcome_is_reported(self):
        path, s = fresh()
        self.addCleanup(s.close)
        self.assertEqual(s.offer("one@example.com"), (spool.WRITTEN, None))
        s.max_bytes = os.path.getsize(path)
        self.assertEqual(s.offer("two@example.com"), (spool.FULL, None))
        s.max_bytes = 1 << 20
        self.assertEqual(s.offer("x@example.com", "n" * (spool.RECORD_MAX + 1)),
                         (spool.OVERSIZE, None))

    def test_a_write_error_names_the_errno(self):
        path, s = fresh()
        self.addCleanup(s.close)
        real = s._fd
        s._fd = os.open(path, os.O_RDONLY)
        try:
            self.assertEqual(s.offer("one@example.com"), (spool.ERROR, "EBADF"))
        finally:
            os.close(s._fd)
            s._fd = real

    def test_a_short_write_is_an_error_not_a_success(self):
        # A write that returns fewer bytes than the record leaves a torn line.
        # The kernel rarely does this to a regular file, so it is forced here.
        path, s = fresh()
        self.addCleanup(s.close)
        real_write = spool.os.write
        spool.os.write = lambda fd, data: real_write(fd, data[:-1])
        try:
            self.assertEqual(s.offer("one@example.com"), (spool.ERROR, "SHORT_WRITE"))
        finally:
            spool.os.write = real_write

    def test_an_oversize_record_is_declined_not_truncated(self):
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("x@example.com", "n" * (spool.RECORD_MAX + 1))
        self.assertEqual(os.path.getsize(path), 0)

    def test_a_full_spool_does_not_corrupt_what_is_already_there(self):
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("one@example.com")
        kept = open(path, "rb").read()
        # The boundary is measured, not guessed: an earlier version of this test
        # picked 120 bytes and a second record fitted inside it.
        s.max_bytes = os.path.getsize(path)
        for i in range(10):
            s.offer(f"rejected{i}@example.com")
        self.assertEqual(open(path, "rb").read(), kept)



class Utf8(unittest.TestCase):
    """A legitimate submission is never declined for its size.

    The first version escaped non-ASCII as \\uXXXX, six bytes a character, so a
    200-character note in French crossed RECORD_MAX and was silently declined.
    """

    def test_a_non_ascii_note_is_written_and_read_back_intact(self):
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("dad@example.com", "é" * 200)
        rows, _ = spool.read_from(path, 0)
        self.assertEqual([r["note"] for r in rows], ["é" * 200])

    def test_the_largest_legitimate_record_fits(self):
        # intake admits 254 characters of address and 280 of note; four-byte
        # characters are the worst case UTF-8 allows.
        path, s = fresh()
        self.addCleanup(s.close)
        email = "😀" * 248 + "@x.com"
        self.assertEqual(len(email), 254)
        s.offer(email, "😀" * 280)
        rows, _ = spool.read_from(path, 0)
        self.assertEqual([r["email"] for r in rows], [email])


class Positions(unittest.TestCase):
    def test_entries_carry_byte_positions_a_consumer_can_resume_from(self):
        path, s = fresh()
        self.addCleanup(s.close)
        for e in ("a@x.com", "b@x.com", "c@x.com"):
            s.offer(e)
        entries, end = spool.entries_from(path, 0)
        self.assertEqual(entries[0][1], 0)
        self.assertEqual(entries[-1][2], end)
        for (_, _, prev_end), (_, begin, _) in zip(entries, entries[1:]):
            self.assertEqual(prev_end, begin)
        resumed, _ = spool.entries_from(path, entries[2][1])
        self.assertEqual([r["email"] for r, _, _ in resumed], ["c@x.com"])

    def test_a_non_object_line_is_skipped_rather_than_crashing_the_consumer(self):
        path, s = fresh()
        self.addCleanup(s.close)
        s.offer("before@example.com")
        with open(path, "ab") as fh:
            fh.write(b"5\n")
        s.offer("after@example.com")
        rows, _ = spool.read_from(path, 0)
        self.assertEqual([r["email"] for r in rows],
                         ["before@example.com", "after@example.com"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
