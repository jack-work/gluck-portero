#!/usr/bin/env python3
"""The intake table and its state machine. The mint half owns both.

The table lives in mint's own StateDirectory, which systemd re-chowns to the
unit's current uid at every start, so a reboot that reassigns dynamic uids
cannot leave it owned by a stranger. The public half never opens it, never
imports this module, and reaches the pipeline only by appending to the spool.

Every transition is a conditional UPDATE, so two administrators racing on one
row produce one winner and no half-approved account.

Rows arrive by ingesting the spool at a byte offset. Ingestion is at-least-once
and the table's UNIQUE(email) makes it exactly-once: a crash before the offset
is stored re-reads, and the duplicate INSERT is swallowed.
"""

import errno
import os
import sqlite3
import threading
import time
from collections import namedtuple

import spool

SCHEMA = """
CREATE TABLE IF NOT EXISTS intake (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  email       TEXT NOT NULL UNIQUE,
  note        TEXT NOT NULL DEFAULT '',
  received_at INTEGER NOT NULL,
  state       TEXT NOT NULL DEFAULT 'pending',
  username    TEXT,
  decided_by  TEXT,
  decided_at  INTEGER,
  nonce       TEXT,
  expires_at  INTEGER,
  mac         TEXT,
  sent_at     INTEGER,
  send_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS intake_state ON intake(state, id);
"""

STATES = ("pending", "approved", "rejected", "retired")


TABLE_FULL = "intake is full"


def cap_trigger(cap):
    return f"""
DROP TRIGGER IF EXISTS intake_cap;
CREATE TRIGGER intake_cap BEFORE INSERT ON intake
WHEN (SELECT COUNT(*) FROM intake WHERE state = 'pending') >= {int(cap)}
BEGIN
  SELECT RAISE(ABORT, '{TABLE_FULL}');
END;
"""


def connect(path, cap):
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript(SCHEMA)
    db.executescript(cap_trigger(cap))
    return db



OK, HELD, FAILED = "ok", "held", "error"
BAD_OFFSET = "BAD_OFFSET"

Ingested = namedtuple("Ingested", "outcome landed offset errno")


class OffsetCorrupt(ValueError):
    pass


def errno_name(exc):
    return errno.errorcode.get(exc.errno, "EUNKNOWN")


MAC_FIELDS = ("id", "email", "username", "nonce", "expires_at")
NOTE_MAX = 280


def mac_fields(row):
    return {k: row[k] for k in MAC_FIELDS}


class IntakeAdmin:
    def __init__(self, path, cap, spool_path=None, offset_path=None):
        self._lock = threading.Lock()
        self._ingest_lock = threading.Lock()
        self._db = connect(path, cap)
        self.cap = int(cap)
        self.spool_path = spool_path
        self.offset_path = offset_path

    def offset(self):
        try:
            with open(self.offset_path, "r", encoding="utf-8") as fh:
                text = fh.read().strip()
        except FileNotFoundError:
            return 0
        if not (text.isascii() and text.isdigit()):
            raise OffsetCorrupt(text)
        return int(text)

    def _offset_or_failure(self):
        try:
            return self.offset(), None
        except OffsetCorrupt:
            return -1, BAD_OFFSET
        except OSError as exc:
            return -1, errno_name(exc)

    def ingest(self):
        with self._ingest_lock:
            return self._ingest()

    def _ingest(self):
        if not self.spool_path or not self.offset_path:
            return Ingested(OK, 0, 0, None)
        start, failure = self._offset_or_failure()
        if failure:
            return Ingested(FAILED, 0, start, failure)
        try:
            entries, end = spool.entries_from(self.spool_path, start)
        except OSError as exc:
            return Ingested(FAILED, 0, start, errno_name(exc))
        landed, outcome = 0, OK
        with self._lock:
            for row, begin, _ in entries:
                try:
                    self._db.execute(
                        "INSERT INTO intake (email, note, received_at) VALUES (?,?,?)",
                        (str(row.get("email", ""))[:254].lower().strip(),
                         str(row.get("note", ""))[:NOTE_MAX],
                         int(row.get("at") or time.time())),
                    )
                    landed += 1
                except sqlite3.IntegrityError as exc:
                    if TABLE_FULL in str(exc):
                        end, outcome = begin, HELD
                        break
        if end != start:
            tmp = self.offset_path + ".new"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(str(end))
                os.replace(tmp, self.offset_path)
            except OSError as exc:
                return Ingested(FAILED, landed, start, errno_name(exc))
        return Ingested(outcome, landed, end, None)

    def spool_bytes(self):
        try:
            size = os.path.getsize(self.spool_path)
        except (OSError, TypeError):
            size = -1
        return size, self._offset_or_failure()[0]

    def _rows(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def get(self, row_id):
        rows = self._rows("SELECT * FROM intake WHERE id = ?", (int(row_id),))
        return rows[0] if rows else None

    def listing(self, state=None, limit=500):
        if state is None:
            return self._rows(
                "SELECT * FROM intake ORDER BY id DESC LIMIT ?", (int(limit),)
            )
        return self._rows(
            "SELECT * FROM intake WHERE state = ? ORDER BY id LIMIT ?",
            (state, int(limit)),
        )

    def counts(self):
        rows = self._rows("SELECT state, COUNT(*) AS n FROM intake GROUP BY state")
        return {r["state"]: r["n"] for r in rows}

    def claim(self, row_id, username, by, now=None):
        """Move one pending row to approved. True for exactly one caller."""
        now = int(now if now is not None else time.time())
        with self._lock:
            cur = self._db.execute(
                "UPDATE intake SET state='approved', username=?, decided_by=?, "
                "decided_at=? WHERE id=? AND state='pending'",
                (username, by, now, int(row_id)),
            )
            return cur.rowcount == 1

    def release(self, row_id):
        with self._lock:
            cur = self._db.execute(
                "UPDATE intake SET state='pending', username=NULL, decided_by=NULL, "
                "decided_at=NULL, nonce=NULL, expires_at=NULL, mac=NULL "
                "WHERE id=? AND state='approved'",
                (int(row_id),),
            )
            return cur.rowcount == 1

    def reject(self, row_id, by, now=None):
        now = int(now if now is not None else time.time())
        with self._lock:
            cur = self._db.execute(
                "UPDATE intake SET state='rejected', decided_by=?, decided_at=? "
                "WHERE id=? AND state='pending'",
                (by, now, int(row_id)),
            )
            return cur.rowcount == 1

    def retire(self, row_id):
        with self._lock:
            cur = self._db.execute(
                "UPDATE intake SET state='retired', nonce=NULL, expires_at=NULL, mac=NULL "
                "WHERE id=? AND state='approved'",
                (int(row_id),),
            )
            return cur.rowcount == 1

    def record_claim_material(self, row_id, nonce, expires_at, mac):
        with self._lock:
            self._db.execute(
                "UPDATE intake SET nonce=?, expires_at=?, mac=? WHERE id=?",
                (nonce, int(expires_at), mac, int(row_id)),
            )

    def record_sent(self, row_id, now=None):
        now = int(now if now is not None else time.time())
        with self._lock:
            self._db.execute(
                "UPDATE intake SET sent_at=?, send_count=send_count+1 WHERE id=?",
                (now, int(row_id)),
            )

    def close(self):
        with self._lock:
            self._db.close()
