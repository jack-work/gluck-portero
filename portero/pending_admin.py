#!/usr/bin/env python3
"""The reader and the state machine for the intake table. Mint only.

The public intake unit never imports this module. Every transition is a
conditional UPDATE, so two administrators racing on one row produce one winner
and no half-approved account.

A decided row carries a MAC over the fields that decide where a link goes. The
intake unit can write the table, so a row read back here is not trusted until
that MAC verifies.
"""

import threading
import time

from pending import connect

MAC_FIELDS = ("id", "email", "username", "nonce", "expires_at")


def mac_fields(row):
    return {k: row[k] for k in MAC_FIELDS}


class IntakeAdmin:
    def __init__(self, path, cap):
        self._lock = threading.Lock()
        self._db = connect(path, cap)
        self.cap = int(cap)

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
