import hashlib
import json
import re
import threading
import time
from collections import namedtuple

import jwt
import requests

BEARER_TOKEN = "^Bearer [A-Za-z0-9._~+/-]+=*$"
USERINFO_TTL = 60
USERINFO_TIMEOUT = 5
USERINFO_MAX_BODY = 64 << 10

Identity = namedtuple("Identity", "username groups subject client_id")


class Refused(Exception):
    pass


class Unavailable(Exception):
    pass


def bearer_token(authorization):
    if not re.fullmatch(BEARER_TOKEN, authorization or ""):
        return None
    return authorization[len("Bearer "):]


class BearerGate:
    def __init__(self, issuer, jwks_url, userinfo_url, client_ids,
                 ttl=USERINFO_TTL, timeout=USERINFO_TIMEOUT, now=time.time):
        self.issuer = issuer
        self.userinfo_url = userinfo_url
        self.client_ids = frozenset(c for c in client_ids if c)
        self.configured = bool(issuer and jwks_url and userinfo_url and self.client_ids)
        self.jwks = jwt.PyJWKClient(jwks_url, timeout=timeout) if self.configured else None
        self.ttl = ttl
        self.timeout = timeout
        self.now = now
        self._lock = threading.Lock()
        self._profiles = {}

    def verify(self, authorization):
        if not self.configured:
            raise Refused("bearer tokens are not accepted here")
        token = bearer_token(authorization)
        if token is None:
            raise Refused("Authorization is not a bearer token")
        claims = self._claims(token)
        client_id = claims.get("client_id")
        if client_id not in self.client_ids:
            raise Refused(f"token was issued to client {client_id!r}, not to this service")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise Refused("token carries no sub")
        username, groups = self._profile(subject, authorization)
        return Identity(username, groups, subject, client_id)

    def _claims(self, token):
        try:
            key = self.jwks.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as exc:
            raise Unavailable(f"jwks: {exc}") from None
        except (jwt.PyJWKClientError, jwt.InvalidTokenError) as exc:
            raise Refused(f"token key: {exc}") from None
        try:
            return jwt.decode(
                token, key.key, algorithms=["RS256"], issuer=self.issuer,
                options={"require": ["exp", "iss", "sub"], "verify_aud": False},
            )
        except jwt.InvalidTokenError as exc:
            raise Refused(f"token: {exc}") from None

    def _profile(self, subject, authorization):
        key = hashlib.sha256(authorization.encode()).digest()
        now = self.now()
        with self._lock:
            hit = self._profiles.get(key)
            if hit and now < hit[0]:
                return hit[1], hit[2]
            for k in [k for k, v in self._profiles.items() if now >= v[0]]:
                del self._profiles[k]
        username, groups = self._fetch(subject, authorization)
        with self._lock:
            self._profiles[key] = (now + self.ttl, username, groups)
        return username, groups

    def _fetch(self, subject, authorization):
        try:
            r = requests.get(
                self.userinfo_url,
                headers={"Authorization": authorization, "Accept": "application/json"},
                timeout=self.timeout, stream=True, allow_redirects=False,
            )
            body = r.raw.read(USERINFO_MAX_BODY + 1, decode_content=True)
        except requests.RequestException as exc:
            raise Unavailable(f"userinfo: {exc}") from None
        if r.status_code in (401, 403):
            raise Refused(f"userinfo refused the token: {r.status_code}")
        if r.status_code != 200:
            raise Unavailable(f"userinfo status {r.status_code}")
        if len(body) > USERINFO_MAX_BODY:
            raise Unavailable("userinfo body too large")
        try:
            claims = json.loads(body)
        except ValueError:
            raise Unavailable("userinfo is not JSON") from None
        if not isinstance(claims, dict):
            raise Unavailable("userinfo is not a JSON object")
        if claims.get("sub") != subject:
            raise Refused(f"userinfo answered for sub {claims.get('sub')!r}, token is {subject!r}")
        username = claims.get("preferred_username")
        groups = claims.get("groups", [])
        if not isinstance(username, str) or not username:
            raise Unavailable("userinfo carries no preferred_username")
        if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
            raise Unavailable("userinfo groups is not a list of strings")
        return username, groups
