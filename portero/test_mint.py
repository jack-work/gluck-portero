#!/usr/bin/env python3
"""Mint endpoint tests.

This half holds lldap_admin, so the properties under test are about what it
REFUSES: callers without the group, and any group outside the allowlist.
"""

import json
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CREDS = tempfile.mkdtemp()
KEY = b"k" * 48
with open(os.path.join(_CREDS, "invite_key"), "wb") as fh:
    fh.write(KEY)
with open(os.path.join(_CREDS, "admin_password"), "w") as fh:
    fh.write("admin-password")

os.environ["CREDENTIALS_DIRECTORY"] = _CREDS
os.environ["PORTERO_GRANTABLE_GROUPS"] = "site-share-access,site-cal-access"

sys.path.insert(0, _HERE)
import invites  # noqa: E402
import mint as M  # noqa: E402

REAL_GQL = M.gql  # captured before any test replaces it

GROUPS = [
    {"id": 1, "displayName": "lldap_admin"},
    {"id": 13, "displayName": "files-admin"},
    {"id": 20, "displayName": "site-share-access"},
]


class Base(unittest.TestCase):
    def setUp(self):
        M.app.config["TESTING"] = True
        self.c = M.app.test_client()
        self.created = []
        self.added = []
        self.existing = set()

        M.lldap_token = lambda: "fake-token"

        def fake_gql(token, query, variables=None):
            variables = variables or {}
            if "createUser" in query:
                self.created.append(variables["u"])
                return {"createUser": {"id": variables["u"]["id"]}}
            if "addUserToGroup" in query:
                self.added.append((variables["u"], variables["g"]))
                return {"addUserToGroup": {"ok": True}}
            if "deleteUser" in query:
                return {"deleteUser": {"ok": True}}
            if "groups" in query:
                return {"groups": GROUPS}
            if "user(" in query:
                uid = variables.get("id")
                return {"user": {"id": uid} if uid in self.existing else None}
            raise AssertionError(f"unexpected query {query}")

        M.gql = fake_gql

    def post(self, body, user="admin", groups="portero-admin"):
        headers = {}
        if user is not None:
            headers["Remote-User"] = user
        if groups is not None:
            headers["Remote-Groups"] = groups
        return self.c.post("/invites", json=body, headers=headers)

    def good(self, **over):
        body = {"username": "dad", "email": "dad@example.com"}
        body.update(over)
        return body


class Authorization(Base):
    def test_unauthenticated_is_401(self):
        r = self.post(self.good(), user=None)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.created, [])

    def test_wrong_group_is_403(self):
        r = self.post(self.good(), groups="files-admin")
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.created, [])

    def test_no_groups_is_403(self):
        r = self.post(self.good(), groups="")
        self.assertEqual(r.status_code, 403)


class Allowlist(Base):
    def test_lldap_admin_is_refused(self):
        # The escalation this allowlist exists to stop.
        r = self.post(self.good(site_access_groups=["lldap_admin"]))
        self.assertEqual(r.status_code, 400)
        self.assertIn(b"not grantable", r.data)
        self.assertEqual(self.created, [], "nothing must be created on refusal")
        self.assertEqual(self.added, [])

    def test_capability_group_is_refused(self):
        r = self.post(self.good(site_access_groups=["files-admin"]))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.created, [])

    def test_allowlisted_group_is_granted(self):
        r = self.post(self.good(site_access_groups=["site-share-access"]))
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.added, [("dad", 20)])

    def test_group_on_allowlist_but_absent_from_directory_is_refused(self):
        # site-cal-access is allowlisted in env but not in GROUPS. Unknown group
        # names never match an Authelia rule, so a silent miss must not happen.
        r = self.post(self.good(site_access_groups=["site-cal-access"]))
        self.assertEqual(r.status_code, 400)
        self.assertIn(b"does not exist in the directory", r.data)
        self.assertEqual(self.created, [], "must refuse BEFORE creating the user")

    def test_case_sensitivity_is_respected(self):
        r = self.post(self.good(site_access_groups=["Site-Share-Access"]))
        self.assertEqual(r.status_code, 400)


class Creation(Base):
    def test_account_is_created_with_no_password_field(self):
        r = self.post(self.good())
        self.assertEqual(r.status_code, 201)
        self.assertEqual(len(self.created), 1)
        self.assertNotIn("password", json.dumps(self.created[0]).lower())

    def test_no_groups_by_default(self):
        self.post(self.good())
        self.assertEqual(self.added, [])

    def test_response_carries_a_verifiable_token(self):
        r = self.post(self.good())
        url = r.get_json()["url"]
        token = url.rsplit("/i/", 1)[1]
        claim = invites.verify(KEY, token)
        self.assertEqual(claim["username"], "dad")

    def test_duplicate_user_is_409(self):
        self.existing.add("dad")
        r = self.post(self.good())
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.created, [])

    def test_bad_username_and_email(self):
        for body in (
            self.good(username="A"),
            self.good(username="1abc"),
            self.good(username="x"),
            self.good(username="admin; drop"),
            self.good(email="nope"),
            self.good(email=""),
        ):
            self.assertEqual(self.post(body).status_code, 400)
        self.assertEqual(self.created, [])

    def test_ttl_bounds(self):
        self.assertEqual(self.post(self.good(ttl_seconds=5)).status_code, 400)
        self.assertEqual(
            self.post(self.good(ttl_seconds=10 ** 9)).status_code, 400
        )
        self.assertEqual(self.post(self.good(ttl_seconds=3600)).status_code, 201)

    def test_graphql_error_with_http_200_is_not_success(self):
        # lldap returns HTTP 200 with an "errors" key on failure. Treating that
        # as success is the defect in lldap-bootstrap, where a failed mutation
        # reads as a successful one. This must not repeat it.
        import requests as _rq

        class Resp:
            status_code = 200

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"errors": [{"message": "boom"}], "data": None}

        real_post = _rq.post
        _rq.post = lambda url, **kw: Resp()
        try:
            with self.assertRaises(RuntimeError):
                REAL_GQL("t", "mutation{createUser{id}}")
        finally:
            _rq.post = real_post

    def test_graphql_success_body_is_accepted(self):
        # Negative control for the test above: the same transport shape without
        # an "errors" key must NOT raise, or the check is just rejecting everything.
        import requests as _rq

        class Resp:
            status_code = 200

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return {"data": {"createUser": {"id": "dad"}}}

        real_post = _rq.post
        _rq.post = lambda url, **kw: Resp()
        try:
            self.assertEqual(
                REAL_GQL("t", "mutation{createUser{id}}"),
                {"createUser": {"id": "dad"}},
            )
        finally:
            _rq.post = real_post


if __name__ == "__main__":
    unittest.main(verbosity=2)
