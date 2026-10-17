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
_MINT_STATE = tempfile.mkdtemp()
_MINT_SPOOL = os.path.join(_MINT_STATE, "spool.jsonl")
open(_MINT_SPOOL, "wb").close()
os.environ["PORTERO_INTAKE_DB"] = os.path.join(_MINT_STATE, "intake.db")
os.environ["PORTERO_INTAKE_SPOOL"] = _MINT_SPOOL
os.environ["PORTERO_INTAKE_OFFSET"] = os.path.join(_MINT_STATE, "spool.offset")
os.environ["PORTERO_INTAKE_CAP"] = "8"

sys.path.insert(0, _HERE)
import invites  # noqa: E402
import mailer  # noqa: E402
import oidc  # noqa: E402
import mint as M  # noqa: E402
import spool  # noqa: E402

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
        self.taken_emails = set()

        M.lldap_token = lambda: "fake-token"

        def fake_gql(token, query, variables=None, tolerate=()):
            variables = variables or {}
            if "createUser" in query:
                if variables["u"].get("email") in self.taken_emails:
                    # lldap's own words, read off spain on 2026-10-07 after an
                    # approval for an address that already had an account.
                    raise RuntimeError(
                        "graphql error: [{'message': 'Database error: `Execution "
                        "Error: error returned from database: (code: 2067) UNIQUE "
                        "constraint failed: users.lowercase_email`'}]"
                    )
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
        open(_MINT_SPOOL, "wb").close()
        with open(self.admin.offset_path, "w", encoding="utf-8") as fh:
            fh.write("0")
        self.writer = spool.Spool(_MINT_SPOOL, 1 << 20)
        self.mailed = []

        def fake_send(to, url, expires_at):
            self.mailed.append((to, url, expires_at))

        self.real_send = mailer.send_invite
        mailer.send_invite = fake_send

    def tearDown(self):
        mailer.send_invite = self.real_send
        self.writer.close()

    def row(self, email="dad@example.com"):
        """A row as one really arrives: appended by the public half, ingested."""
        self.writer.offer(email)
        self.admin.ingest()
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
    def test_the_listing_ingests_so_the_queue_is_never_stale(self):
        # The operator reads one endpoint and sees submissions that arrived a
        # second ago, with no timer in between.
        self.writer.offer("justnow@example.com")
        body = self.listing().get_json()
        self.assertEqual(body["ingested_now"], 1)
        self.assertIn("justnow@example.com", [r["email"] for r in body["rows"]])

    def test_the_listing_reports_the_spool_against_its_ceiling(self):
        # A full spool silently drops signups, so it has to be visible on the
        # authenticated side. It cannot be visible on the public side.
        self.row("one@example.com")
        body = self.listing().get_json()
        self.assertGreater(body["spool_bytes"], 0)
        self.assertEqual(body["spool_consumed"], body["spool_bytes"])
        self.assertGreater(body["spool_max"], body["spool_bytes"])

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


class DuplicateEmail(IntakeBase):
    """An address that already belongs to an account is a 409, never a 500.

    lldap enforces uniqueness on lowercase_email with a database constraint, so
    the constraint is the arbiter and this maps its one error to a status. A
    pre-check followed by an insert would be the read-then-write pattern that
    has bitten this estate three times.
    """

    def test_mint_answers_409_not_500(self):
        self.taken_emails.add("dad@example.com")
        r = self.post(self.good(email="dad@example.com"))
        self.assertEqual(r.status_code, 409)
        self.assertIn(b"already belongs", r.data)
        self.assertEqual(self.created, [])

    def test_approve_answers_409_and_RELEASES_the_row(self):
        # The property worth protecting: a refused approval leaves the row
        # retryable rather than stranded in approved with no account.
        rid = self.row("dad@example.com")
        self.taken_emails.add("dad@example.com")
        r = self.call(f"/intake/{rid}/approve", {"username": "dad"})
        self.assertEqual(r.status_code, 409)
        row = self.admin.get(rid)
        self.assertEqual(row["state"], "pending")
        self.assertIsNone(row["username"])
        self.assertIsNone(row["decided_by"])
        self.assertEqual(self.mailed, [], "nothing may be mailed on a refusal")

    def test_a_released_row_can_be_approved_afterwards(self):
        rid = self.row("dad@example.com")
        self.taken_emails.add("dad@example.com")
        self.call(f"/intake/{rid}/approve", {"username": "dad"})
        self.taken_emails.clear()
        again = self.call(f"/intake/{rid}/approve", {"username": "dad"})
        self.assertEqual(again.status_code, 201)
        self.assertEqual(self.admin.get(rid)["state"], "approved")
        self.assertEqual(len(self.mailed), 1)

    def test_any_other_graphql_error_still_raises(self):
        # The tolerance is one constraint, not "errors from createUser".
        rid = self.row("dad@example.com")
        real = M.gql

        def angry(token, query, variables=None, tolerate=()):
            if "createUser" in query:
                raise RuntimeError("graphql error: [{'message': 'Unauthorized'}]")
            return real(token, query, variables, tolerate)

        M.gql = angry
        with self.assertRaises(RuntimeError):
            self.call(f"/intake/{rid}/approve", {"username": "dad"})
        self.assertEqual(self.admin.get(rid)["state"], "pending",
                         "a crash must still release the row")


class IngestJournal(IntakeBase):
    """One line per ingest attempt, in a form netmon parses. Pinned verbatim:
    a failure must never read as an empty spool, in the log or the listing."""

    def setUp(self):
        super().setUp()
        import io
        import logging
        import journal
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setFormatter(journal.JournalFormatter())
        M.log.addHandler(self.handler)
        M.log.setLevel(logging.INFO)

    def tearDown(self):
        M.log.removeHandler(self.handler)
        os.chmod(_MINT_SPOOL, 0o644)
        super().tearDown()

    def ingest_lines(self):
        return [l for l in self.stream.getvalue().splitlines() if " mint ingest " in l]

    def size(self):
        return os.path.getsize(_MINT_SPOOL)

    def test_ok(self):
        self.writer.offer("dad@example.com")
        body = self.listing().get_json()
        self.assertEqual(self.ingest_lines(), [
            f"<6>INFO mint ingest outcome=ok landed=1 offset={self.size()} spool_bytes={self.size()}"])
        self.assertEqual((body["ingest"], body["ingest_errno"], body["ingested_now"]), ("ok", None, 1))

    def test_held(self):
        for i in range(M.INTAKE_CAP):
            self.row(f"user{i}@example.com")
        held_at = self.size()
        self.writer.offer("waiting@example.com")
        body = self.listing().get_json()
        self.assertEqual(self.ingest_lines()[-1],
                         f"<4>WARNING mint ingest outcome=held landed=0 offset={held_at} spool_bytes={self.size()}")
        self.assertEqual(body["ingest"], "held")

    def test_an_unreadable_spool_is_an_error_not_an_empty_queue(self):
        self.assertNotEqual(os.geteuid(), 0, "root reads a mode-000 file; run this unprivileged")
        self.row("before@example.com")
        consumed = self.size()
        self.writer.offer("stalled@example.com")
        os.chmod(_MINT_SPOOL, 0)
        resp = self.listing()
        body = resp.get_json()
        self.assertEqual(self.ingest_lines()[-1],
                         f"<3>ERROR mint ingest outcome=error offset={consumed} spool_bytes={self.size()} errno=EACCES")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual((body["ingest"], body["ingest_errno"], body["ingested_now"]),
                         ("error", "EACCES", None))
        self.assertEqual([r["email"] for r in body["rows"]], ["before@example.com"])
        self.assertGreater(body["spool_bytes"], body["spool_consumed"])

    def test_a_missing_spool_reports_minus_one_bytes(self):
        os.unlink(_MINT_SPOOL)
        try:
            body = self.listing().get_json()
        finally:
            open(_MINT_SPOOL, "wb").close()
        self.assertEqual(self.ingest_lines()[-1],
                         "<3>ERROR mint ingest outcome=error offset=0 spool_bytes=-1 errno=ENOENT")
        self.assertEqual(body["spool_bytes"], -1)

    def test_a_tick_lands_a_signup_with_nobody_looking(self):
        self.writer.offer("unwatched@example.com")
        got = M.ingest_tick()
        self.assertEqual((got.outcome, got.landed), ("ok", 1))
        self.assertIn("unwatched@example.com", [r["email"] for r in self.admin.listing()])
        self.assertEqual(self.ingest_lines(), [
            f"<6>INFO mint ingest outcome=ok landed=1 offset={self.size()} spool_bytes={self.size()}"])

    def test_a_quiet_tick_still_logs_so_silence_means_a_dead_clock(self):
        self.assertEqual(M.ingest_tick().outcome, "ok")
        self.assertEqual(self.ingest_lines(), [
            f"<6>INFO mint ingest outcome=ok landed=0 offset={self.size()} spool_bytes={self.size()}"])

    def test_a_failing_tick_logs_the_error(self):
        self.assertNotEqual(os.geteuid(), 0, "root reads a mode-000 file; run this unprivileged")
        self.writer.offer("stalled@example.com")
        os.chmod(_MINT_SPOOL, 0)
        M.ingest_tick()
        self.assertEqual(self.ingest_lines(),
                         [f"<3>ERROR mint ingest outcome=error offset=0 spool_bytes={self.size()} errno=EACCES"])

    def test_the_timer_ticks_until_stopped(self):
        import threading
        stop = threading.Event()
        worker = threading.Thread(target=M.ingest_every, args=(0.01, stop))
        worker.start()
        self.writer.offer("ticked@example.com")
        for _ in range(200):
            if "ticked@example.com" in [r["email"] for r in self.admin.listing()]:
                break
            stop.wait(0.01)
        stop.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertIn("ticked@example.com", [r["email"] for r in self.admin.listing()])

    def test_ingests_are_serialised(self):
        # Two ingests racing would both rewrite spool.offset.new; the lock is
        # what prevents a torn offset, so prove ingest waits on it.
        import threading
        self.admin._ingest_lock.acquire()
        worker = threading.Thread(target=self.admin.ingest)
        worker.start()
        worker.join(0.2)
        blocked = worker.is_alive()
        self.admin._ingest_lock.release()
        worker.join(2)
        self.assertTrue(blocked, "ingest ran without its lock")
        self.assertFalse(worker.is_alive())

    def test_a_corrupt_offset_reports_minus_one(self):
        with open(M.INTAKE_OFFSET, "w", encoding="utf-8") as fh:
            fh.write("garbage")
        body = self.listing().get_json()
        self.assertEqual(self.ingest_lines()[-1],
                         f"<3>ERROR mint ingest outcome=error offset=-1 spool_bytes={self.size()} errno=BAD_OFFSET")
        self.assertEqual(body["spool_consumed"], -1)


class Retire(SendById):
    """An approved row whose account is gone can be retired. Retiring is
    bookkeeping, never revocation: while the account exists it is refused."""

    def test_retire_refuses_an_unauthenticated_caller_and_the_wrong_group(self):
        rid = self.approved()
        self.existing.discard("dad")
        self.assertEqual(self.call(f"/intake/{rid}/retire", user=None).status_code, 401)
        self.assertEqual(self.call(f"/intake/{rid}/retire", groups="files-admin").status_code, 403)
        self.assertEqual(self.admin.get(rid)["state"], "approved")

    def test_retire_refuses_while_the_account_exists(self):
        rid = self.approved()
        r = self.call(f"/intake/{rid}/retire")
        self.assertEqual(r.status_code, 409)
        self.assertIn("DELETE /invites/dad", r.get_json()["error"])
        self.assertEqual(self.admin.get(rid)["state"], "approved")
        self.assertIn("dad", self.existing)

    def test_retire_after_revocation_makes_the_row_inert(self):
        rid = self.approved()
        self.assertEqual(self.c.delete("/invites/dad", headers={
            "Remote-User": "admin", "Remote-Groups": "portero-admin"}).status_code, 200)
        r = self.call(f"/intake/{rid}/retire")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"retired": rid, "username": "dad"})
        row = self.admin.get(rid)
        self.assertEqual(row["state"], "retired")
        self.assertIsNone(row["nonce"])
        self.assertEqual(self.call(f"/intake/{rid}/send").status_code, 409)
        self.assertEqual(self.mailed, [])
        self.assertEqual(self.admin.counts().get("approved"), None)
        self.assertEqual(self.admin.counts()["retired"], 1)

    def test_retire_refuses_a_pending_row_and_an_unknown_one(self):
        rid = self.row("pending@example.com")
        self.assertEqual(self.call(f"/intake/{rid}/retire").status_code, 409)
        self.assertEqual(self.admin.get(rid)["state"], "pending")
        self.assertEqual(self.call("/intake/99999/retire").status_code, 404)

    def test_retire_happens_once(self):
        rid = self.approved()
        self.existing.discard("dad")
        self.assertEqual(self.call(f"/intake/{rid}/retire").status_code, 200)
        self.assertEqual(self.call(f"/intake/{rid}/retire").status_code, 409)

    def test_retire_is_logged_with_who_and_which_account(self):
        rid = self.approved()
        self.existing.discard("dad")
        with self.assertLogs("portero-mint", level="INFO") as cap:
            self.call(f"/intake/{rid}/retire")
        self.assertIn(f"INFO:portero-mint:intake row {rid} retired by admin, account dad gone", cap.output)


class TolerateOnlyAPureAbsence(SendById):
    """gql tolerates "Entity not found" only when it is the WHOLE answer:
    every error is that one, and data carries nothing. A real error riding
    alongside it must raise, or retire would close a live account's row."""

    NOT_FOUND = {"message": "Entity not found: `dad`", "path": ["user"]}
    DB_ERROR = {"message": "Database error: connection reset", "path": ["user"]}

    def lldap_answers(self, body):
        import requests as _rq

        class Resp:
            status_code = 200

            @staticmethod
            def raise_for_status():
                return None

            @staticmethod
            def json():
                return body

        real_post, real_gql = _rq.post, M.gql
        _rq.post = lambda url, **kw: Resp()
        M.gql = REAL_GQL
        self.addCleanup(setattr, _rq, "post", real_post)
        self.addCleanup(setattr, M, "gql", real_gql)

    def test_absence_plus_a_database_error_raises(self):
        self.lldap_answers({"data": None, "errors": [self.NOT_FOUND, self.DB_ERROR]})
        with self.assertRaises(RuntimeError):
            M.user_exists("t", "dad")

    def test_absence_with_a_user_in_data_raises(self):
        self.lldap_answers({"data": {"user": {"id": "dad"}}, "errors": [self.NOT_FOUND]})
        with self.assertRaises(RuntimeError):
            M.user_exists("t", "dad")

    def test_retire_fails_closed_on_the_mixed_answer(self):
        rid = self.approved()
        self.lldap_answers({"data": None, "errors": [self.NOT_FOUND, self.DB_ERROR]})
        with self.assertRaises(RuntimeError):
            self.call(f"/intake/{rid}/retire")
        self.assertEqual(self.admin.get(rid)["state"], "approved")

    def test_control_retire_proceeds_on_a_pure_absence(self):
        rid = self.approved()
        self.lldap_answers({"data": None, "errors": [self.NOT_FOUND]})
        self.assertEqual(self.call(f"/intake/{rid}/retire").status_code, 200)
        self.assertEqual(self.admin.get(rid)["state"], "retired")


class Bearer(IntakeBase):
    """Identity comes from the Authorization header whenever one is present,
    and a failing token is refused: never a fall back to Remote-*, never
    anonymous. Caddy strips Remote-* on the bearer branch; these tests send
    forged Remote-* anyway, so mint is not relying on that."""

    FORGED = {"Remote-User": "admin", "Remote-Groups": "portero-admin"}

    class StandIn:
        def __init__(self, outcome):
            self.outcome = outcome

        def verify(self, authorization):
            if isinstance(self.outcome, Exception):
                raise self.outcome
            return self.outcome

    def gate(self, outcome):
        real = M.GATE
        M.GATE = self.StandIn(outcome)
        self.addCleanup(setattr, M, "GATE", real)

    def reject(self, rid, authorization, extra=None):
        headers = dict(self.FORGED, Authorization=authorization)
        headers.update(extra or {})
        return self.c.post(f"/intake/{rid}/reject", headers=headers)

    def test_garbage_bearer_with_forged_identity_is_401_and_reaches_no_handler(self):
        rid = self.row()
        r = self.reject(rid, "Bearer x")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_any_authorization_header_disables_remote_headers(self):
        rid = self.row()
        for value in ("Basic YWRtaW46eA==", "", "Bearer", "bearer abc"):
            with self.subTest(value=value):
                self.assertEqual(self.reject(rid, value).status_code, 401)
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_a_refused_token_is_401_even_with_forged_identity(self):
        self.gate(oidc.Refused("token was issued to client 'keel'"))
        rid = self.row()
        self.assertEqual(self.reject(rid, "Bearer abc").status_code, 401)
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_an_unavailable_identity_provider_is_503(self):
        self.gate(oidc.Unavailable("userinfo status 500"))
        rid = self.row()
        self.assertEqual(self.reject(rid, "Bearer abc").status_code, 503)
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_a_valid_token_from_a_non_operator_is_403(self):
        self.gate(oidc.Identity("mallory", ["files-user"], "u-9", "portero-cli"))
        rid = self.row()
        self.assertEqual(self.reject(rid, "Bearer abc").status_code, 403)
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_a_valid_operator_token_acts_as_its_own_user_not_the_forged_one(self):
        self.gate(oidc.Identity("gluck", ["portero-admin"], "u-1", "portero-cli"))
        rid = self.row()
        self.assertEqual(self.reject(rid, "Bearer abc").status_code, 200)
        self.assertEqual(self.admin.get(rid)["decided_by"], "gluck")

    def test_a_bearer_post_needs_no_json_content_type(self):
        self.gate(oidc.Identity("gluck", ["portero-admin"], "u-1", "portero-cli"))
        rid = self.row()
        r = self.c.post(f"/intake/{rid}/reject", headers={"Authorization": "Bearer abc"})
        self.assertEqual(r.status_code, 200)

    def test_whoami_says_how_the_caller_was_identified(self):
        self.gate(oidc.Identity("gluck", ["portero-admin"], "u-1", "portero-cli"))
        body = self.c.get("/invites/whoami", headers={"Authorization": "Bearer abc"}).get_json()
        self.assertEqual(body, {"user": "gluck", "groups": ["portero-admin"], "via": "bearer"})
        body = self.c.get("/invites/whoami", headers=self.FORGED).get_json()
        self.assertEqual(body["via"], "session")

    def test_the_shipped_gate_refuses_every_bearer_when_unconfigured(self):
        self.assertFalse(M.GATE.configured)
        rid = self.row()
        self.assertEqual(self.reject(rid, "Bearer abc").status_code, 401)


class CrossSite(IntakeBase):
    """A session POST must be application/json, which a cross-site form
    cannot send without a preflight, and must not carry a foreign Origin."""

    SESSION = {"Remote-User": "admin", "Remote-Groups": "portero-admin"}

    def test_a_form_post_is_refused_and_does_nothing(self):
        rid = self.row()
        for ctype in ("application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain", None):
            with self.subTest(ctype=ctype):
                headers = dict(self.SESSION)
                if ctype:
                    headers["Content-Type"] = ctype
                r = self.c.post(f"/intake/{rid}/reject", headers=headers, data="x=1")
                self.assertEqual(r.status_code, 415)
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_a_foreign_origin_is_refused(self):
        rid = self.row()
        r = self.c.post(f"/intake/{rid}/reject", json={}, headers=dict(self.SESSION, Origin="https://files.kelliher.info"))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.admin.get(rid)["state"], "pending")

    def test_same_origin_json_is_accepted(self):
        rid = self.row()
        r = self.c.post(f"/intake/{rid}/reject", json={}, headers=dict(self.SESSION, Origin=M.ORIGIN))
        self.assertEqual(r.status_code, 200)

    def test_json_without_origin_is_accepted(self):
        rid = self.row()
        self.assertEqual(self.c.post(f"/intake/{rid}/reject", json={}, headers=self.SESSION).status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
