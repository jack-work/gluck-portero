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

import os
import sqlite3
import threading
import time

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

STATES = ("pending", "approved", "rejected")


def cap_trigger(cap):
    return f"""
DROP TRIGGER IF EXISTS intake_cap;
CREATE TRIGGER intake_cap BEFORE INSERT ON intake
WHEN (SELECT COUNT(*) FROM intake WHERE state = 'pending') >= {int(cap)}
BEGIN
  SELECT RAISE(ABORT, 'intake is full');
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



MAC_FIELDS = ("id", "email", "username", "nonce", "expires_at")
NOTE_MAX = 280


def mac_fields(row):
    return {k: row[k] for k in MAC_FIELDS}


class IntakeAdmin:
    def __init__(self, path, cap, spool_path=None, offset_path=None):
        self._lock = threading.Lock()
        self._db = connect(path, cap)
        self.cap = int(cap)
        self.spool_path = spool_path
        self.offset_path = offset_path

    def offset(self):
        try:
            with open(self.offset_path, "r", encoding="utf-8") as fh:
                return int(fh.read().strip() or 0)
        except (OSError, ValueError):
            return 0

    def ingest(self):
        """Pull new spool records into the table. Returns how many landed.

        The offset advances only after the rows are committed, so a crash
        re-reads them and UNIQUE(email) refuses the duplicates. Nothing is ever
        written to the spool from here: no truncate, no rename, no unlink, so an
        append landing mid-ingest is simply next.
        """
        if not self.spool_path or not self.offset_path:
            return 0
        start = self.offset()
        try:
            records, end = spool.read_from(self.spool_path, start)
        except OSError:
            return 0
        landed = 0
        with self._lock:
            for row in records:
                try:
                    self._db.execute(
                        "INSERT INTO intake (email, note, received_at) VALUES (?,?,?)",
                        (str(row.get("email", ""))[:254].lower().strip(),
                         str(row.get("note", ""))[:NOTE_MAX],
                         int(row.get("at") or time.time())),
                    )
                    landed += 1
                except sqlite3.IntegrityError:
                    pass
        if end != start:
            tmp = self.offset_path + ".new"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(str(end))
            os.replace(tmp, self.offset_path)
        return landed

    def spool_bytes(self):
        """What the operator needs to see a full spool coming."""
        try:
            return os.path.getsize(self.spool_path), self.offset()
        except (OSError, TypeError):
            return 0, 0

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
