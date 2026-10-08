#!/usr/bin/env python3
"""The spool: one file the public half can append to and cannot read.

Blindness is the kernel's, not the reviewer's. The writer opens O_WRONLY with
O_APPEND and never holds a readable descriptor, so no code path, present or
future, can read a submission back. A read() on that descriptor fails with
EBADF.

The file is pre-created root-owned by tmpfiles and is never created, renamed or
removed by either service, so no dynamic user ever owns it and a reboot that
reassigns uids changes nothing. Appends and reads never contend: the consumer
tracks a byte offset in its own StateDirectory and never writes here.
"""

import json
import os
import time

RECORD_MAX = 1024


class Spool:
    """Append-only, write-only. Its cap is a size, which is not a read."""

    def __init__(self, path, max_bytes):
        self.path = path
        self.max_bytes = int(max_bytes)
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND)

    def size(self):
        return os.fstat(self._fd).st_size

    def offer(self, email, note="", now=None):
        """Append one record, or silently decline. Returns nothing either way."""
        record = json.dumps(
            {"email": email, "note": note,
             "at": int(now if now is not None else time.time())},
            separators=(",", ":"), sort_keys=True,
        ).encode("utf-8") + b"\n"
        if len(record) > RECORD_MAX:
            return
        try:
            if self.size() + len(record) > self.max_bytes:
                return
            os.write(self._fd, record)
        except OSError:
            pass

    def close(self):
        os.close(self._fd)


def read_from(path, offset, limit=1 << 20):
    """Consumer side. Returns (records, new_offset), never past a partial line.

    A short append would otherwise be parsed as a whole record. Only data up to
    the last newline is consumed, so a torn tail waits for the rest instead of
    being dropped.
    """
    size = os.path.getsize(path)
    if offset > size:
        offset = 0
    if offset == size:
        return [], offset
    with open(path, "rb") as fh:
        fh.seek(offset)
        blob = fh.read(limit)
    cut = blob.rfind(b"\n")
    if cut < 0:
        return [], offset
    records = []
    for line in blob[:cut].split(b"\n"):
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row.get("email"), str):
            records.append(row)
    return records, offset + cut + 1
