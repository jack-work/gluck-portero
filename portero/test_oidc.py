#!/usr/bin/env python3
"""BearerGate against a real local identity provider: real RSA keys, real
JWTs, a real HTTP server for JWKS and userinfo. Nothing here stubs the
verification itself, so a pass means PyJWT and the gate agree with a token
the way Authelia mints it.

The properties:

  the parser admits exactly what Caddy's no-bearer matcher sends through
  a token is honoured only for this service's client_id
  groups come from userinfo, per token, cached 60 s, with a sub match
  every userinfo or JWKS failure refuses or is unavailable, never passes
"""

import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402

import oidc  # noqa: E402

ISSUER = "https://auth.example.test"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "k1"

# The same table as kelliher-web's tests/bearer_cases.txt, which checks
# Caddy's matcher: the backend must admit exactly what Caddy sends to it.
BEARER_CASES = [
    ("forward_auth", ""),
    ("forward_auth", "Basic YWRtaW46eA=="),
    ("forward_auth", "Bearer"),
    ("forward_auth", "Bearer "),
    ("forward_auth", "bearer abc"),
    ("forward_auth", "BEARER abc"),
    ("forward_auth", "Bearer  abc"),
    ("forward_auth", "Bearer abc def"),
    ("forward_auth", "Bearer abc,def"),
    ("forward_auth", "Bearer =abc"),
    ("forward_auth", "Bearer abc=x"),
    ("backend", "Bearer abc"),
    ("backend", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln-_~+/="),
    ("backend", "Bearer abc=="),
]

ESTATE_CLIENTS = ["keel", "keel-ci", "kfin", "kcal", "kcal-notify", "herald",
                  "rou2", "gluck-todo-cli", "gluck-calendar-cli", "gforms-cli",
                  "kmatrix", "netmon-pager", ""]


class IdP:
    def __init__(self):
        idp = self
        self.userinfo_hits = 0
        self.userinfo = lambda auth: (200, {"sub": "u-1", "preferred_username": "gluck",
                                            "groups": ["portero-admin"]})
        self.jwks_status = 200

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/jwks.json":
                    jwk = json.loads(RSAAlgorithm.to_jwk(KEY.public_key()))
                    jwk.update(kid=KID, alg="RS256", use="sig")
                    self.reply(idp.jwks_status, json.dumps({"keys": [jwk]}).encode())
                elif self.path == "/userinfo":
                    idp.userinfo_hits += 1
                    status, body = idp.userinfo(self.headers.get("Authorization"))
                    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                    self.reply(status, raw)
                else:
                    self.reply(404, b"{}")

            def reply(self, status, raw):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def token(key=KEY, kid=KID, alg="RS256", **over):
    claims = {"iss": ISSUER, "sub": "u-1", "client_id": "portero-cli",
              "exp": int(time.time()) + 600, "iat": int(time.time()), "scope": "openid groups"}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return "Bearer " + jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


class Base(unittest.TestCase):
    def setUp(self):
        self.idp = IdP()
        self.clock = [1000.0]
        self.gate = self.make()

    def make(self, **over):
        args = dict(issuer=ISSUER, jwks_url=self.idp.url + "/jwks.json",
                    userinfo_url=self.idp.url + "/userinfo", client_ids=["portero-cli"],
                    now=lambda: self.clock[0])
        args.update(over)
        return oidc.BearerGate(**args)

    def tearDown(self):
        self.idp.close()

    def refused(self, authorization):
        with self.assertRaises(oidc.Refused):
            self.gate.verify(authorization)


class Shape(Base):
    def test_the_parser_admits_exactly_what_caddy_sends_to_the_backend(self):
        for where, header in BEARER_CASES:
            with self.subTest(header=header):
                self.assertEqual(oidc.bearer_token(header) is not None, where == "backend")

    def test_a_trailing_newline_is_not_admitted(self):
        self.assertIsNone(oidc.bearer_token("Bearer abc\n"))

    def test_a_shape_caddy_refuses_is_refused_before_any_network(self):
        self.idp.close()
        for where, header in BEARER_CASES:
            if where == "forward_auth":
                with self.subTest(header=header):
                    self.refused(header)


class Token(Base):
    def test_a_valid_token_yields_userinfo_identity(self):
        who = self.gate.verify(token())
        self.assertEqual(who, oidc.Identity("gluck", ["portero-admin"], "u-1", "portero-cli"))

    def test_garbage_is_refused(self):
        self.refused("Bearer x")

    def test_every_other_estate_client_is_refused(self):
        for client in ESTATE_CLIENTS:
            with self.subTest(client=client):
                self.refused(token(client_id=client))
        self.refused(token(client_id=None))
        self.assertEqual(self.idp.userinfo_hits, 0, "a foreign token must not reach userinfo")

    def test_wrong_issuer_expired_and_foreign_key_are_refused(self):
        self.refused(token(iss="https://evil.test"))
        self.refused(token(exp=int(time.time()) - 60))
        self.refused(token(key=OTHER_KEY))
        self.refused(token(kid="nope"))

    def test_hs256_signed_with_the_public_key_is_refused(self):
        from cryptography.hazmat.primitives import serialization
        pem = KEY.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        claims = {"iss": ISSUER, "sub": "u-1", "client_id": "portero-cli", "exp": int(time.time()) + 600}
        import base64
        import hashlib
        import hmac
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
        head = b64(json.dumps({"alg": "HS256", "kid": KID}).encode())
        body = b64(json.dumps(claims).encode())
        sig = b64(hmac.new(pem, head + b"." + body, hashlib.sha256).digest())
        self.refused("Bearer " + (head + b"." + body + b"." + sig).decode())

    def test_no_sub_is_refused(self):
        self.refused(token(sub=None))

    def test_an_unconfigured_gate_refuses_everything(self):
        gate = self.make(client_ids=[])
        with self.assertRaises(oidc.Refused):
            gate.verify(token())


class Userinfo(Base):
    def test_a_revoked_token_is_refused(self):
        for status in (401, 403):
            with self.subTest(status=status):
                self.idp.userinfo = lambda a, s=status: (s, {"error": "invalid_token"})
                self.clock[0] += 120
                self.refused(token())

    def test_a_sub_mismatch_is_refused(self):
        self.idp.userinfo = lambda a: (200, {"sub": "u-2", "preferred_username": "x", "groups": ["portero-admin"]})
        self.refused(token())

    def test_failures_are_unavailable_never_a_pass(self):
        cases = {
            "500": (500, {}),
            "not json": (200, b"<html>login</html>"),
            "not an object": (200, ["portero-admin"]),
            "groups not a list": (200, {"sub": "u-1", "preferred_username": "g", "groups": "portero-admin"}),
            "no username": (200, {"sub": "u-1", "groups": ["portero-admin"]}),
            "oversize": (200, {"sub": "u-1", "preferred_username": "g", "groups": ["x" * 70000]}),
        }
        for name, answer in cases.items():
            with self.subTest(name):
                self.idp.userinfo = lambda a, r=answer: r
                self.clock[0] += 120
                with self.assertRaises(oidc.Unavailable):
                    self.gate.verify(token())

    def test_an_unreachable_userinfo_is_unavailable(self):
        gate = self.make(userinfo_url="http://127.0.0.1:1/userinfo")
        with self.assertRaises(oidc.Unavailable):
            gate.verify(token())

    def test_an_unreachable_jwks_is_unavailable(self):
        gate = self.make(jwks_url="http://127.0.0.1:1/jwks.json")
        with self.assertRaises(oidc.Unavailable):
            gate.verify(token())


class Cache(Base):
    def test_groups_are_cached_sixty_seconds_per_token(self):
        t = token()
        self.gate.verify(t)
        self.gate.verify(t)
        self.assertEqual(self.idp.userinfo_hits, 1)
        self.clock[0] += 59
        self.gate.verify(t)
        self.assertEqual(self.idp.userinfo_hits, 1)
        self.clock[0] += 2
        self.gate.verify(t)
        self.assertEqual(self.idp.userinfo_hits, 2)

    def test_removal_from_the_group_lands_within_the_ttl(self):
        t = token()
        self.assertIn("portero-admin", self.gate.verify(t).groups)
        self.idp.userinfo = lambda a: (200, {"sub": "u-1", "preferred_username": "gluck", "groups": []})
        self.clock[0] += 61
        self.assertEqual(self.gate.verify(t).groups, [])

    def test_another_token_is_another_lookup(self):
        self.gate.verify(token(iat=1))
        self.gate.verify(token(iat=2))
        self.assertEqual(self.idp.userinfo_hits, 2)

    def test_a_failure_is_not_cached(self):
        t = token()
        self.idp.userinfo = lambda a: (500, {})
        with self.assertRaises(oidc.Unavailable):
            self.gate.verify(t)
        self.idp.userinfo = lambda a: (200, {"sub": "u-1", "preferred_username": "gluck", "groups": ["portero-admin"]})
        self.assertEqual(self.gate.verify(t).username, "gluck")


if __name__ == "__main__":
    unittest.main(verbosity=2)
