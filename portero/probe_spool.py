#!/usr/bin/env python3
"""Attempts every operation on the spool that F1 showed intake could perform.

Test scaffolding only: it is run inside the real gluck-portero units by the VM
check, with ExecStart swapped by a drop-in so every other property is the
unit's own. Each attempt prints one line, OK or the errno name.
"""

import errno
import os
import sys

SPOOL = sys.argv[1]


def attempt(name, fn):
    try:
        detail = fn()
        print(f"PROBE {name} OK{(' ' + detail) if detail else ''}", flush=True)
    except OSError as exc:
        print(f"PROBE {name} {errno.errorcode.get(exc.errno, exc.errno)}", flush=True)


def read():
    fd = os.open(SPOOL, os.O_RDONLY)
    try:
        return f"bytes={len(os.read(fd, 4096))}"
    finally:
        os.close(fd)


def append():
    fd = os.open(SPOOL, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, b'{"email":"probe@example.com","note":"","at":1}\n')
    finally:
        os.close(fd)


def open_without_append():
    os.close(os.open(SPOOL, os.O_WRONLY))


def ftruncate():
    fd = os.open(SPOOL, os.O_WRONLY | os.O_APPEND)
    try:
        os.ftruncate(fd, 0)
    finally:
        os.close(fd)


def pwrite_at_zero():
    fd = os.open(SPOOL, os.O_WRONLY | os.O_APPEND)
    try:
        before = os.fstat(fd).st_size
        os.pwrite(fd, b"X", 0)
        return f"grew={os.fstat(fd).st_size > before}"
    finally:
        os.close(fd)


for step in sys.argv[2:]:
    {
        "read": lambda: attempt("read", read),
        "append": lambda: attempt("append", append),
        "open_without_append": lambda: attempt("open_without_append", open_without_append),
        "ftruncate": lambda: attempt("ftruncate", ftruncate),
        "pwrite_at_zero": lambda: attempt("pwrite_at_zero", pwrite_at_zero),
    }[step]()
