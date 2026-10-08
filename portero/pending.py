#!/usr/bin/env python3
"""The intake table, and the write-only half of it.

The public intake unit holds this module and nothing else that touches the
database. It can INSERT and it has no statement that reads a row back: no
SELECT, no cursor, no return value carrying stored data. The cap is a schema
trigger rather than a count in the application, so the writer stays blind.

The reader and the state machine live in pending_admin.py, which only the
authenticated mint unit imports.
"""

import os
import sqlite3
import threading
import time

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

# sqlite creates its files from a base mode of 0644, so no umask can add the
# group write bit: the intake unit's files come out 0640 and the mint unit,
# a different dynamic user in the same group, cannot write the table. Proven on
# spain with two transient DynamicUser units, where the reader could SELECT and
# its UPDATE failed with "attempt to write a readonly database".
SHARED_MODE = 0o660
SIDECARS = ("", "-wal", "-shm", "-journal")


def cap_trigger(cap):
    return f"""
DROP TRIGGER IF EXISTS intake_cap;
CREATE TRIGGER intake_cap BEFORE INSERT ON intake
WHEN (SELECT COUNT(*) FROM intake WHERE state = 'pending') >= {int(cap)}
BEGIN
  SELECT RAISE(ABORT, 'intake is full');
END;
"""


def share(path):
    """Make every file of this database writable by the group that owns it.

    Only a file's creator can chmod it and either unit may be the creator, so
    both call this and the one that cannot fails silently. connect() writes the
    schema before calling it, which forces the WAL sidecars into existence, so
    no sidecar exists unshared.
    """
    for suffix in SIDECARS:
        try:
            os.chmod(path + suffix, SHARED_MODE)
        except OSError:
            pass


def connect(path, cap):
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript(SCHEMA)
    db.executescript(cap_trigger(cap))
    share(path)
    return db


class Intake:
    """Insert-only. Every outcome looks the same to the caller: None."""

    def __init__(self, path, cap):
        self._lock = threading.Lock()
        self._db = connect(path, cap)

    def offer(self, email, note="", now=None):
        now = int(now if now is not None else time.time())
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO intake (email, note, received_at) VALUES (?,?,?)",
                    (email, note, now),
                )
            except sqlite3.IntegrityError:
                pass

    def close(self):
        with self._lock:
            self._db.close()
