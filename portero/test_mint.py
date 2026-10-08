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
os.environ["PORTERO_GRANTABLE_GROUPS"] = "site-files-access,site-cal-access"
os.environ["PORTERO_INTAKE_DB"] = os.path.join(tempfile.mkdtemp(), "intake.db")
os.environ["PORTERO_INTAKE_CAP"] = "8"

sys.path.insert(0, _HERE)
import invites  # noqa: E402
import mailer  # noqa: E402
import mint as M  # noqa: E402
import pending  # noqa: E402

REAL_GQL = M.gql  # captured before any test replaces it

GROUPS = [
    {"id": 1, "displayName": "lldap_admin"},
    {"id": 13, "displayName": "files-admin"},
    {"id": 20, "displayName": "site-files-access"},
]


class Base(unittest.TestCase):
    def setUp(self):
        M.app.config["TESTING"] = True
        self.c = M.app.test_client()
        self.created = []
        self.added = []
        self.existing = set()

        M.lldap_token = lambda: "fake-token"

        def fake_gql(token, query, variables=None, tolerate=()):
            variables = variables or {}
            if "createUser" in query:
                self.created.append(variables["u"])
                self.existing.add(variables["u"]["id"])
                return {"createUser": {"id": variables["u"]["id"]}}
            if "addUserToGroup" in query:
                self.added.append((variables["u"], variables["g"]))
                return {"addUserToGroup": {"ok": True}}
            if "deleteUser" in query:
                self.existing.discard(variables.get("id"))
                return {"deleteUser": {"ok": True}}
            if "groups" in query:
                return {"groups": GROUPS}
            if "user(" in query:
                uid = variables.get("id")
                if uid in self.existing:
                    return {"user": {"id": uid}}
                # lldap answers an ABSENT user with a GraphQL error, not a null
                # field, and REAL_GQL turns a tolerated error into None. The
                # first version of this mock returned {"user": None}, which
                # agreed with my assumption instead of with lldap, so the suite
                # was green while production 500'd on every mint.
                if tolerate and any("Entity not found" in t for t in tolerate):
                    return None
                raise RuntimeError("graphql error: Entity not found")
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
        r = self.post(self.good(site_access_groups=["site-files-access"]))
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
        # an "errors" key must NOT raise, or the check rejects everything.
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

    def test_absent_user_reports_false_against_lldaps_real_error_shape(self):
        # The production 500. lldap answers a missing user with a GraphQL ERROR,
        # so user_exists must tolerate that one message and return False.
        # Exercised through REAL_GQL, not the mock, so the mock cannot be the
        # only witness to lldap's behaviour.
        import requests as _rq

        class Resp:
            status_code = 200
            @staticmethod
            def raise_for_status(): return None
            @staticmethod
            def json():
                return {"data": None, "errors": [
                    {"message": "Entity not found: `dad`", "path": ["user"]}]}

        real_post, real_gql = _rq.post, M.gql
        _rq.post = lambda url, **kw: Resp()
        M.gql = REAL_GQL
        try:
            self.assertFalse(M.user_exists("t", "dad"))
        finally:
            _rq.post, M.gql = real_post, real_gql

    def test_other_graphql_errors_still_raise_from_user_exists(self):
        # Tolerance must be narrow: only "Entity not found".
        import requests as _rq

        class Resp:
            status_code = 200
            @staticmethod
            def raise_for_status(): return None
            @staticmethod
            def json():
                return {"data": None, "errors": [{"message": "Unauthorized"}]}

        real_post, real_gql = _rq.post, M.gql
        _rq.post = lambda url, **kw: Resp()
        M.gql = REAL_GQL
        try:
            with self.assertRaises(RuntimeError):
                M.user_exists("t", "dad")
        finally:
            _rq.post, M.gql = real_post, real_gql


class IntakeBase(Base):
    """The authenticated side of the intake pipeline."""

    def setUp(self):
        super().setUp()
        self.admin = M.intake()
        self.admin._db.execute("DELETE FROM intake")
        self.writer = pending.Intake(M.INTAKE_DB, M.INTAKE_CAP)
        self.mailed = []

        def fake_send(to, url, expires_at):
            self.mailed.append((to, url, expires_at))

        self.real_send = mailer.send_invite
        mailer.send_invite = fake_send

    def tearDown(self):
        mailer.send_invite = self.real_send
        self.writer.close()

    def row(self, email="dad@example.com"):
        self.writer.offer(email)
        return self.admin.listing(state="pending")[-1]["id"]

    def call(self, path, body=None, user="admin", groups="portero-admin"):
        headers = {}
        if user is not None:
            headers["Remote-User"] = user
        if groups is not None:
            headers["Remote-Groups"] = groups
        return self.c.post(path, json=body or {}, headers=headers)

    def listing(self, user="admin", groups="portero-admin", query=""):
        headers = {}
        if user is not None:
            headers["Remote-User"] = user
        if groups is not None:
            headers["Remote-Groups"] = groups
        return self.c.get(f"/intake{query}", headers=headers)


class IntakeAuthorization(IntakeBase):
    def test_every_intake_route_refuses_an_unauthenticated_caller(self):
        rid = self.row()
        self.assertEqual(self.listing(user=None).status_code, 401)
        for path in (f"/intake/{rid}/approve", f"/intake/{rid}/send",
                     f"/intake/{rid}/reject"):
            self.assertEqual(self.call(path, user=None).status_code, 401)
        self.assertEqual(self.created, [])

    def test_every_intake_route_refuses_the_wrong_group(self):
        rid = self.row()
        self.assertEqual(self.listing(groups="files-admin").status_code, 403)
        for path in (f"/intake/{rid}/approve", f"/intake/{rid}/send",
                     f"/intake/{rid}/reject"):
            self.assertEqual(self.call(path, groups="files-admin").status_code, 403)
        self.assertEqual(self.created, [])
        self.assertEqual(self.mailed, [])


class IntakeListing(IntakeBase):
    def test_pending_rows_are_listed_with_their_capacity(self):
        self.row("one@example.com")
        self.row("two@example.com")
        body = self.listing().get_json()
        self.assertEqual([r["email"] for r in body["rows"]],
                         ["one@example.com", "two@example.com"])
        self.assertEqual(body["pending_capacity"], M.INTAKE_CAP)
        self.assertEqual(body["counts"], {"pending": 2})

    def test_the_listing_never_carries_the_claim_material(self):
        rid = self.row()
        self.call(f"/intake/{rid}/approve", {"username": "dad"})
        blob = self.listing(query="?state=all").get_data(as_text=True)
        row = self.admin.get(rid)
        self.assertNotIn(row["nonce"], blob)
        self.assertNotIn(row["mac"], blob)


class IntakeApproval(IntakeBase):
    def test_approve_creates_the_account_and_mails_the_link(self):
        rid = self.row("dad@example.com")
        r = self.call(f"/intake/{rid}/approve",
                      {"username": "dad", "site_access_groups": ["site-files-access"]})
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.get_json()["mailed"])
        self.assertEqual(len(self.created), 1)
        self.assertEqual(self.added, [("dad", 20)])
        self.assertEqual(len(self.mailed), 1)
        to, url, _ = self.mailed[0]
        self.assertEqual(to, "dad@example.com")
        claim = invites.verify(KEY, url.rsplit("/i/", 1)[1])
        self.assertEqual(claim["username"], "dad")

    def test_the_address_comes_from_the_row_not_the_request(self):
        rid = self.row("dad@example.com")
        self.call(f"/intake/{rid}/approve",
                  {"username": "dad", "email": "attacker@example.com"})
        self.assertEqual(self.mailed[0][0], "dad@example.com")
        self.assertEqual(self.created[0]["email"], "dad@example.com")

    def test_the_allowlist_still_applies_to_an_approval(self):
        rid = self.row()
        r = self.call(f"/intake/{rid}/approve",
                      {"username": "dad", "site_access_groups": ["lldap_admin"]})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.created, [])
        self.assertEqual(self.mailed, [])
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_an_existing_user_leaves_the_row_pending(self):
        self.existing.add("dad")
        rid = self.row()
        r = self.call(f"/intake/{rid}/approve", {"username": "dad"})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.admin.get(rid)["state"], "pending",
                         "a failed approval must be retryable")
        self.assertEqual(self.mailed, [])

    def test_a_directory_failure_releases_the_row(self):
        rid = self.row()
        M.gql = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lldap is down"))
        with self.assertRaises(RuntimeError):
            self.call(f"/intake/{rid}/approve", {"username": "dad"})
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_a_row_is_approved_once(self):
        rid = self.row()
        first = self.call(f"/intake/{rid}/approve", {"username": "dad"})
        second = self.call(f"/intake/{rid}/approve", {"username": "dad2"})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 409)
        self.assertEqual(len(self.created), 1)

    def test_mail_failure_is_a_502_that_keeps_the_account(self):
        rid = self.row()

        def boom(to, url, expires_at):
            raise mailer.MailFailed("smtp refused mail to x: SMTPDataError")

        mailer.send_invite = boom
        r = self.call(f"/intake/{rid}/approve", {"username": "dad"})
        self.assertEqual(r.status_code, 502)
        self.assertFalse(r.get_json()["mailed"])
        self.assertEqual(len(self.created), 1)
        self.assertEqual(self.admin.get(rid)["state"], "approved")
        self.assertIsNone(self.admin.get(rid)["sent_at"])

    def test_rejecting_frees_the_cap_and_blocks_approval(self):
        rid = self.row()
        self.assertEqual(self.call(f"/intake/{rid}/reject").status_code, 200)
        self.assertEqual(self.call(f"/intake/{rid}/approve",
                                   {"username": "dad"}).status_code, 409)
        self.assertEqual(self.created, [])


class SendById(IntakeBase):
    def approved(self, email="dad@example.com", username="dad"):
        rid = self.row(email)
        self.call(f"/intake/{rid}/approve", {"username": username})
        self.mailed.clear()
        return rid

    def test_send_resends_the_same_link(self):
        rid = self.approved()
        before = self.admin.get(rid)["nonce"]
        r = self.call(f"/intake/{rid}/send")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(self.mailed), 1)
        token = self.mailed[0][1].rsplit("/i/", 1)[1]
        self.assertEqual(invites.verify(KEY, token)["nonce"], before,
                         "a resend must not create a second live link")

    def test_send_counts_up(self):
        rid = self.approved()
        self.call(f"/intake/{rid}/send")
        self.call(f"/intake/{rid}/send")
        self.assertEqual(self.admin.get(rid)["send_count"], 3)

    def test_send_refuses_a_pending_row(self):
        rid = self.row()
        self.assertEqual(self.call(f"/intake/{rid}/send").status_code, 409)
        self.assertEqual(self.mailed, [])

    def test_send_refuses_an_unknown_row(self):
        self.assertEqual(self.call("/intake/99999/send").status_code, 404)

    def test_send_refuses_a_revoked_account(self):
        rid = self.approved()
        self.existing.discard("dad")
        self.assertEqual(self.call(f"/intake/{rid}/send").status_code, 409)
        self.assertEqual(self.mailed, [])

    def test_send_refuses_a_row_whose_recipient_was_rewritten(self):
        # The intake unit can write this table. Repointing an approved row at
        # an attacker's address must not get a working link mailed to it.
        rid = self.approved()
        self.admin._db.execute("UPDATE intake SET email='evil@example.com' "
                               "WHERE id=?", (rid,))
        r = self.call(f"/intake/{rid}/send")
        self.assertEqual(r.status_code, 409)
        self.assertIn(b"not authentic", r.data)
        self.assertEqual(self.mailed, [])

    def test_send_refuses_a_row_whose_username_was_rewritten(self):
        rid = self.approved()
        self.existing.add("admin")
        self.admin._db.execute("UPDATE intake SET username='admin' WHERE id=?",
                               (rid,))
        r = self.call(f"/intake/{rid}/send")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.mailed, [])

    def test_send_refuses_a_row_forged_wholesale(self):
        self.existing.add("admin")
        self.admin._db.execute(
            "INSERT INTO intake (email, received_at, state, username, nonce, "
            "expires_at, mac) VALUES (?,?,?,?,?,?,?)",
            ("evil@example.com", 0, "approved", "admin", "b" * 32,
             2_000_000_000, "forged"),
        )
        rid = self.admin.listing(state="approved")[-1]["id"]
        self.assertEqual(self.call(f"/intake/{rid}/send").status_code, 409)
        self.assertEqual(self.mailed, [])

    def test_an_expired_claim_is_re_minted(self):
        rid = self.approved()
        self.admin._db.execute("UPDATE intake SET expires_at=1 WHERE id=?", (rid,))
        row = self.admin.get(rid)
        self.admin.record_claim_material(
            rid, row["nonce"], 1,
            invites.decision_mac(KEY, {"id": rid, "email": row["email"],
                                       "username": "dad", "nonce": row["nonce"],
                                       "expires_at": 1}))
        r = self.call(f"/intake/{rid}/send")
        self.assertEqual(r.status_code, 200)
        token = self.mailed[0][1].rsplit("/i/", 1)[1]
        self.assertEqual(invites.verify(KEY, token)["username"], "dad")
        self.assertNotEqual(self.admin.get(rid)["nonce"], row["nonce"])


class MintLogging(IntakeBase):
    def test_the_link_never_reaches_a_log(self):
        rid = self.row()
        with self.assertLogs("portero-mint", level="INFO") as cap:
            self.call(f"/intake/{rid}/approve", {"username": "dad"})
            self.call(f"/intake/{rid}/send")
        blob = "\n".join(cap.output)
        url = self.mailed[0][1]
        token = url.rsplit("/i/", 1)[1]
        self.assertNotIn(url, blob)
        self.assertNotIn(token, blob)
        self.assertNotIn(token.split(".")[0], blob)
        self.assertIn("dad", blob)

    def test_a_mail_failure_logs_no_link(self):
        rid = self.row()
        self.call(f"/intake/{rid}/approve", {"username": "dad"})
        url = self.mailed[0][1]

        def boom(to, url_, expires_at):
            raise mailer.MailFailed(f"smtp refused mail to {to}: SMTPDataError")

        mailer.send_invite = boom
        with self.assertLogs("portero-mint", level="INFO") as cap:
            self.call(f"/intake/{rid}/send")
        blob = "\n".join(cap.output)
        self.assertNotIn(url, blob)
        self.assertNotIn(url.rsplit("/i/", 1)[1], blob)
        self.assertIn("smtp refused", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
