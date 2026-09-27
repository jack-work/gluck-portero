#!/usr/bin/env python3
"""The spent-nonce store, owned by the redeem process alone.

Mint holds no state. The only thing that must be remembered is which nonces
have already been used, and remembering it here means the public half never
reads the private half's data.
"""

import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS spent (
  nonce    TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  spent_at INTEGER NOT NULL
);
"""


class Spent:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(SCHEMA)

    def claim(self, nonce, username, now=None):
        """Spend a nonce. True on the first call, False on every later one.

        The uniqueness is the primary key's, not a read-then-write, so two
        simultaneous redemptions of one token cannot both win.
        """
        now = int(now if now is not None else time.time())
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO spent (nonce, username, spent_at) VALUES (?,?,?)",
                    (nonce, username, now),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def is_spent(self, nonce):
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM spent WHERE nonce = ?", (nonce,)
            ).fetchone()
        return row is not None

    def count(self):
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM spent").fetchone()[0]

    def close(self):
        with self._lock:
            self._db.close()
