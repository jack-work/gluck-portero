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

import errno
import json
import os
import time

# The largest record a legitimate submission can produce: intake admits an
# address of 254 characters and a note of 280, and UTF-8 spends at most four
# bytes on a character. The cap only has to refuse what intake would never send.
RECORD_MAX = 4096

WRITTEN = "written"
FULL = "full"
OVERSIZE = "oversize"
ERROR = "error"


class Spool:
    """Append-only, write-only. Its cap is a size, which is not a read."""

    def __init__(self, path, max_bytes, record_max=RECORD_MAX):
        self.path = path
        self.max_bytes = int(max_bytes)
        self.record_max = int(record_max)
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND)

    def size(self):
        return os.fstat(self._fd).st_size

    def offer(self, email, note="", now=None):
        """Append one record, or decline it. Returns (outcome, errno_name).

        errno_name is set only for ERROR: the kernel's name for the failure, or
        SHORT_WRITE when the write returned fewer bytes than the record, which
        would leave a torn line for the consumer.

        The outcome is for the operator's journal. It never reaches the caller,
        whose response is the same bytes whatever this returns, and it says
        nothing about the queue's contents: a duplicate is WRITTEN like any
        other record, because the spool does not deduplicate.
        """
        record = json.dumps(
            {"email": email, "note": note,
             "at": int(now if now is not None else time.time())},
            separators=(",", ":"), sort_keys=True, ensure_ascii=False,
        ).encode("utf-8") + b"\n"
        if len(record) > self.record_max:
            return OVERSIZE, None
        try:
            if self.size() + len(record) > self.max_bytes:
                return FULL, None
            if os.write(self._fd, record) != len(record):
                return ERROR, "SHORT_WRITE"
        except OSError as exc:
            return ERROR, errno.errorcode.get(exc.errno, "EUNKNOWN")
        return WRITTEN, None

    def close(self):
        os.close(self._fd)


def entries_from(path, offset, limit=1 << 20):
    """Consumer side. Returns (entries, new_offset), never past a partial line.

    Each entry is (row, start, end) in bytes, so a consumer that cannot accept
    a row yet can leave its offset at that row's start and take it next time.

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
    entries = []
    pos = offset
    for line in blob[:cut].split(b"\n"):
        begin = pos
        pos += len(line) + 1
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and isinstance(row.get("email"), str):
            entries.append((row, begin, pos))
    return entries, offset + cut + 1


def read_from(path, offset, limit=1 << 20):
    entries, end = entries_from(path, offset, limit)
    return [row for row, _, _ in entries], end
