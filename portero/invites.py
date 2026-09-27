#!/usr/bin/env python3
"""Invite tokens: minted by one process, verified by another, shared state none.

The token carries its own claim and its own signature, so the public half never
reads the private half's database. Mint is stateless. Redeem owns one table of
spent nonces and nothing else.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

NONCE_BYTES = 32
MAX_TOKEN_LEN = 1024


class InvalidToken(Exception):
    """Every rejection raises this, with no detail that reaches a caller."""


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def load_key(path):
    """Read the signing key from a file, never from argv and never from a unit."""
    with open(path, "rb") as fh:
        key = fh.read().strip()
    if len(key) < 32:
        raise ValueError("invite signing key must be at least 32 bytes")
    return key


def mint(key, username, ttl_seconds, now=None):
    """Return (token, nonce, expires_at). The caller shows the token once."""
    if ttl_seconds <= 0:
        raise ValueError("ttl must be positive")
    now = int(now if now is not None else time.time())
    expires_at = now + int(ttl_seconds)
    nonce = secrets.token_hex(NONCE_BYTES // 2)
    payload = _b64e(
        json.dumps(
            {"u": username, "e": expires_at, "n": nonce},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    sig = _b64e(hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{sig}", nonce, expires_at


def verify(key, token, now=None):
    """Return {"username", "nonce", "expires_at"} or raise InvalidToken.

    Signature is checked before the payload is parsed, so a forged payload is
    never interpreted. Every failure raises the same exception with no detail.
    """
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN:
        raise InvalidToken()
    parts = token.split(".")
    if len(parts) != 2:
        raise InvalidToken()
    payload, sig = parts
    try:
        want = hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest()
        got = _b64d(sig)
    except Exception:
        raise InvalidToken()
    if not hmac.compare_digest(want, got):
        raise InvalidToken()
    try:
        claim = json.loads(_b64d(payload))
        username = claim["u"]
        expires_at = int(claim["e"])
        nonce = claim["n"]
    except Exception:
        raise InvalidToken()
    if not isinstance(username, str) or not isinstance(nonce, str):
        raise InvalidToken()
    now = int(now if now is not None else time.time())
    if now >= expires_at:
        raise InvalidToken()
    return {"username": username, "nonce": nonce, "expires_at": expires_at}


def new_signing_key():
    """For the operator to generate once, into sops. Never called by a service."""
    return base64.urlsafe_b64encode(os.urandom(48)).decode("ascii")
