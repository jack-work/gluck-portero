#!/usr/bin/env python3

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CREDS = tempfile.mkdtemp()
with open(os.path.join(_CREDS, "invite_key"), "wb") as fh:
    fh.write(b"k" * 48)
with open(os.path.join(_CREDS, "admin_password"), "w") as fh:
    fh.write("admin-password")
_STATE = tempfile.mkdtemp()
_SPOOL = os.path.join(_STATE, "spool.jsonl")
open(_SPOOL, "wb").close()
os.environ.update({
    "CREDENTIALS_DIRECTORY": _CREDS,
    "PORTERO_GRANTABLE_GROUPS": "friends,site-bootystats-access",
    "PORTERO_INTAKE_DB": os.path.join(_STATE, "intake.db"),
    "PORTERO_INTAKE_SPOOL": _SPOOL,
    "PORTERO_INTAKE_OFFSET": os.path.join(_STATE, "spool.offset"),
    "PORTERO_UMBRAL": "1",
    "PORTERO_UMBRAL_DB": os.path.join(_STATE, "umbral.db"),
})

sys.path.insert(0, _HERE)
import mailer  # noqa: E402
import mint as M  # noqa: E402
import umbral as U  # noqa: E402


def record(**over):
    r = {"v": 1, "provider": "google", "subject": "1234", "email": "new@example.com",
         "hd": "", "name": "Nora", "note": "", "at": "2026-11-12T23:00:00Z"}
    r.update(over)
    return (json.dumps(r) + "\n").encode()


class Parse(unittest.TestCase):
    def test_good(self):
        r = U.parse(record(hd="example.com", note="hi")[:-1])
        self.assertEqual(r["subject"], "1234")
        self.assertEqual(r["hd"], "example.com")
        self.assertEqual(r["received_at"], 1794524400)

    def test_refused(self):
        cases = {
            "version": dict(v=2),
            "provider": dict(provider="facebook"),
            "google subject": dict(subject="a b"),
            "github subject not numeric": dict(provider="github", subject="amy"),
            "github subject zero": dict(provider="github", subject="0"),
            "email": dict(email="nobody"),
            "hd": dict(hd="Example.COM/"),
            "no name": dict(name=""),
            "long name": dict(name="n" * 101),
            "long note": dict(note="n" * 501),
            "time": dict(at="yesterday"),
            "subject not a string": dict(subject=1234),
        }
        for name, over in cases.items():
            with self.subTest(name):
                self.assertIsNone(U.parse(record(**over)[:-1]))
        self.assertIsNone(U.parse(b"not json"))
        self.assertIsNone(U.parse(b"[]"))
        self.assertIsNone(U.parse(b"x" * (U.RECORD_MAX + 1)))


class Layout(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "spool")
        with open(self.path, "wb") as fh:
            fh.write(record())
        os.chmod(self.path, 0o660)
        self.gid = os.getgid()
        self.good_acl = U.expected_acl(4242)

    def check(self, **over):
        kw = dict(owner=os.getuid(), flags_of=lambda fd: True, acl_of=lambda p: self.good_acl)
        kw.update(over)
        fd = U.open_checked(self.path, self.gid, 4242, **kw)
        os.close(fd)

    def test_U10_good_layout_reads(self):
        self.check()

    def test_U10_each_difference_refuses(self):
        cases = {
            "owner": dict(owner=os.getuid() + 1),
            "not append-only": dict(flags_of=lambda fd: False),
            "flags unreadable": dict(flags_of=lambda fd: (_ for _ in ()).throw(OSError(95, "x"))),
            "acl writer can read": dict(acl_of=lambda p: (self.good_acl - {(U.ACL_GROUP, 2, 4242)}) | {(U.ACL_GROUP, 6, 4242)}),
            "acl extra user": dict(acl_of=lambda p: self.good_acl | {(U.ACL_USER, 2, 1000)}),
            "acl other may read": dict(acl_of=lambda p: (self.good_acl - {(U.ACL_OTHER, 0, None)}) | {(U.ACL_OTHER, 4, None)}),
            "no acl": dict(acl_of=lambda p: (_ for _ in ()).throw(OSError(61, "x"))),
        }
        for name, over in cases.items():
            with self.subTest(name):
                with self.assertRaises(U.LayoutWrong):
                    self.check(**over)

    def test_U10_mode_group_type_links(self):
        os.chmod(self.path, 0o664)
        with self.assertRaises(U.LayoutWrong):
            self.check()
        os.chmod(self.path, 0o660)
        with self.assertRaises(U.LayoutWrong):
            fd = U.open_checked(self.path, self.gid + 1, 4242, owner=os.getuid(), flags_of=lambda fd: True, acl_of=lambda p: self.good_acl)
            os.close(fd)
        os.link(self.path, self.path + ".2")
        with self.assertRaises(U.LayoutWrong):
            self.check()
        os.unlink(self.path + ".2")
        link = os.path.join(self.dir, "sym")
        os.symlink(self.path, link)
        with self.assertRaises(OSError):
            U.open_checked(link, self.gid, 4242, owner=os.getuid(), flags_of=lambda fd: True, acl_of=lambda p: self.good_acl)

    def test_acl_parse(self):
        import struct
        raw = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, p, i) for t, p, i in [
            (U.ACL_USER_OBJ, 6, 0xFFFFFFFF), (U.ACL_GROUP_OBJ, 4, 0xFFFFFFFF), (U.ACL_GROUP, 2, 4242),
            (U.ACL_MASK, 6, 0xFFFFFFFF), (U.ACL_OTHER, 0, 0xFFFFFFFF)])
        real = os.getxattr
        os.getxattr = lambda *a, **k: raw
        try:
            self.assertEqual(U.acl_entries("x"), U.expected_acl(4242))
        finally:
            os.getxattr = real


class Ingest(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "spool")
        self.store = U.Store(os.path.join(tempfile.mkdtemp(), "u.db"), cap=3)

    def write(self, data):
        with open(self.path, "ab") as fh:
            fh.write(data)

    def ingest(self):
        fd = os.open(self.path, os.O_RDONLY)
        try:
            return self.store.ingest(fd)
        finally:
            os.close(fd)

    def test_lines_offsets_and_cap(self):
        self.write(record(subject="1") + b"garbage\n" + record(subject="2") + b'{"v":1,"provider"')
        landed, skipped, off = self.ingest()
        self.assertEqual((landed, skipped), (2, 1))
        self.assertEqual(self.ingest()[0], 0)
        self.write(b':"x"}\n' + record(subject="3") + record(subject="4") + record(subject="5"))
        landed, skipped, off = self.ingest()
        self.assertEqual((landed, skipped), (1, 1))
        self.assertEqual(len(self.store.listing("pending")), 3)
        self.store.reject(self.store.listing("pending")[0]["id"], "gluck")
        self.assertEqual(self.ingest()[0], 1)
        self.assertEqual(self.ingest()[0], 0)

    def test_offset_past_end_refuses(self):
        self.write(record())
        self.ingest()
        open(self.path, "wb").close()
        with self.assertRaises(U.LayoutWrong):
            self.ingest()

    def test_reingest_after_lost_offset_is_idempotent(self):
        self.write(record(subject="1"))
        self.ingest()
        self.store._db.execute("DELETE FROM meta")
        self.assertEqual(self.ingest()[0], 0)


class FakeDir:
    def __init__(self):
        self.users = {
            "gluck": {"id": "gluck", "email": "Gluck@example.com", "links": {}},
            "amy": {"id": "amy", "email": "amy@example.com", "links": {"google": "111"}},
        }
        self.writes = []
        self.extra_holder = None

    def user(self, uid):
        u = self.users.get(uid)
        return None if u is None else {"id": u["id"], "email": u["email"], "links": dict(u["links"])}

    def holders(self, provider, subject):
        out = [u["id"] for u in self.users.values() if u["links"].get(provider) == subject]
        if self.extra_holder and out:
            out.append(self.extra_holder)
        return out

    def set_link(self, uid, provider, subject):
        self.writes.append(("set", uid, provider, subject))
        self.users[uid]["links"][provider] = subject

    def clear_link(self, uid, provider):
        self.writes.append(("clear", uid, provider))
        del self.users[uid]["links"][provider]


class FakeNotifier:
    def __init__(self):
        self.said = []

    def tell(self, text):
        self.said.append(text)
        return "herald"


class Link(unittest.TestCase):
    def setUp(self):
        self.dir = FakeDir()
        self.store = U.Store(os.path.join(tempfile.mkdtemp(), "u.db"))
        self.note = FakeNotifier()
        self.linker = U.Linker(self.dir, self.store, self.note)

    def test_link_writes_records_and_notifies(self):
        self.assertEqual(self.linker.link("gluck", "google", "888", "gluck@EXAMPLE.com", "umbral"), "gluck")
        self.assertEqual(self.dir.writes, [("set", "gluck", "google", "888")])
        ev = self.store.events()[0]
        self.assertEqual((ev["action"], ev["uid"], ev["provider"], ev["subject"], ev["notified"]),
                         ("link", "gluck", "google", "888", "herald"))
        self.assertEqual(len(self.note.said), 1)
        text = self.note.said[0]
        for want in ("gluck", "Google", "888"):
            self.assertIn(want, text)
        self.assertNotIn("@", text)

    def test_refusals_write_nothing(self):
        cases = [
            ("unknown provider", ("gluck", "facebook", "1", "gluck@example.com"), 400),
            ("bad subject", ("gluck", "google", "a b", "gluck@example.com"), 400),
            ("github subject not numeric", ("gluck", "github", "x", "gluck@example.com"), 400),
            ("empty uid", ("", "google", "1", "gluck@example.com"), 400),
            ("no account", ("nobody", "google", "1", "gluck@example.com"), 404),
            ("email differs", ("gluck", "google", "1", "other@example.com"), 403),
            ("provider already linked", ("amy", "google", "2", "amy@example.com"), 409),
            ("subject held elsewhere", ("gluck", "google", "111", "gluck@example.com"), 409),
        ]
        for name, args, status in cases:
            with self.subTest(name):
                with self.assertRaises(U.Refused) as cm:
                    self.linker.link(*args, by="umbral")
                self.assertEqual(cm.exception.status, status)
        self.assertEqual(self.dir.writes, [])
        self.assertEqual(self.note.said, [])

    def test_post_write_check(self):
        self.dir.extra_holder = "ghost"
        with self.assertRaises(U.Refused):
            self.linker.link("gluck", "google", "888", "gluck@example.com", "umbral")

    def test_unlink(self):
        self.assertEqual(self.linker.unlink("amy", "google", "gluck"), "111")
        self.assertEqual(self.dir.writes, [("clear", "amy", "google")])
        with self.assertRaises(U.Refused):
            self.linker.unlink("amy", "google", "gluck")


class FakeHTTP:
    def __init__(self, fail_token=False, fail_say=False):
        self.calls = []
        self.fail_token = fail_token
        self.fail_say = fail_say

    def post(self, url, data=None, json=None, auth=None, headers=None, timeout=None):
        self.calls.append({"url": url, "data": data, "json": json, "auth": auth, "headers": headers})
        fail = self.fail_token if url.endswith("/token") else self.fail_say

        class R:
            def raise_for_status(self):
                if fail:
                    raise RuntimeError("http 500")

            def json(self):
                return {"access_token": "tok-123"}
        return R()


class Notify(unittest.TestCase):
    def notifier(self, http, mail=None):
        secret = os.path.join(tempfile.mkdtemp(), "s")
        with open(secret, "w") as fh:
            fh.write("sekrit\n")
        return U.Notifier("https://auth.example/api/oidc/token", "portero-notify", secret,
                          "https://herald.example/", "gluck", mail=mail, http=http)

    def test_herald(self):
        http = FakeHTTP()
        mailed = []
        self.assertEqual(self.notifier(http, mailed.append).tell("hello"), "herald")
        tok, say = http.calls
        self.assertEqual(tok["data"], {"grant_type": "client_credentials"})
        self.assertEqual(tok["auth"], ("portero-notify", "sekrit"))
        self.assertEqual(say["url"], "https://herald.example/v1/say")
        self.assertEqual(say["json"], {"to": "gluck", "text": "hello"})
        self.assertEqual(say["headers"], {"Authorization": "Bearer tok-123"})
        self.assertEqual(mailed, [])

    def test_mail_fallback(self):
        for http in (FakeHTTP(fail_token=True), FakeHTTP(fail_say=True)):
            mailed = []
            self.assertEqual(self.notifier(http, mailed.append).tell("hello"), "mail")
            self.assertEqual(mailed, ["hello"])

    def test_both_fail(self):
        def boom(text):
            raise RuntimeError("smtp")
        self.assertEqual(self.notifier(FakeHTTP(fail_say=True), boom).tell("x"), "failed")

    def test_unconfigured_herald_mails(self):
        mailed = []
        self.assertEqual(U.Notifier(mail=mailed.append).tell("x"), "mail")


class LinkSocket(unittest.TestCase):
    def serve(self, allowed):
        path = os.path.join(tempfile.mkdtemp(), "link.sock")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        sock.listen(8)
        self.linker = U.Linker(FakeDir(), U.Store(os.path.join(tempfile.mkdtemp(), "u.db")), FakeNotifier())
        server = U.LinkServer(sock, self.linker, "umbral", resolve=lambda name: allowed if name == "umbral" else None)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return path

    def call(self, path, method="POST", target="/link", body=None, ctype="application/json"):
        import http.client
        conn = U._UnixHTTPConnection(path, timeout=5)
        try:
            data = json.dumps(body).encode() if body is not None else b""
            conn.request(method, target, body=data, headers={"Content-Type": ctype})
            r = conn.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        except (ConnectionError, http.client.RemoteDisconnected):
            return None, None
        finally:
            conn.close()

    GOOD = {"uid": "gluck", "provider": "google", "subject": "888", "email": "gluck@example.com"}

    def test_umbral_peer_links(self):
        path = self.serve(os.getuid())
        self.assertEqual(self.call(path, body=self.GOOD), (200, {"linked": "gluck"}))

    def test_N3_other_peer_refused(self):
        path = self.serve(os.getuid() + 1)
        self.assertEqual(self.call(path, body=self.GOOD), (None, None))
        self.assertEqual(self.linker.dir.writes, [])

    def test_N3_unresolvable_peer_refused(self):
        path = self.serve(None)
        self.assertEqual(self.call(path, body=self.GOOD), (None, None))

    def test_shape(self):
        path = self.serve(os.getuid())
        self.assertEqual(self.call(path, body=dict(self.GOOD, groups=["lldap_admin"]))[0], 400)
        self.assertEqual(self.call(path, body={k: v for k, v in self.GOOD.items() if k != "email"})[0], 400)
        self.assertEqual(self.call(path, body=["x"])[0], 400)
        self.assertEqual(self.call(path, target="/unlink", body=self.GOOD)[0], 404)
        self.assertEqual(self.call(path, method="GET")[0], 405)
        self.assertEqual(self.call(path, body=self.GOOD, ctype="text/plain")[0], 415)
        self.assertEqual(self.call(path, body=dict(self.GOOD, email="x@y.z"))[0], 403)
        self.assertEqual(self.linker.dir.writes, [])


GROUPS = [{"id": 1, "displayName": "lldap_admin"}, {"id": 30, "displayName": "friends"},
          {"id": 31, "displayName": "site-bootystats-access"}]


class Routes(unittest.TestCase):
    def setUp(self):
        M.app.config["TESTING"] = True
        self.c = M.app.test_client()
        self.users = {"old": {"id": "old", "email": "taken@example.com", "attrs": {}}}
        self.created, self.added = [], []
        M.lldap_token = lambda: "t"

        def gql(token, query, variables=None, tolerate=()):
            v = variables or {}
            if "createUser" in query:
                u = v["u"]
                if any(x["email"].lower() == u["email"].lower() for x in self.users.values()):
                    raise RuntimeError("UNIQUE constraint failed: users.lowercase_email")
                self.created.append(u)
                self.users[u["id"]] = {"id": u["id"], "email": u["email"],
                                       "attrs": {a["name"]: a["value"] for a in u.get("attributes", [])}}
                return {"createUser": {"id": u["id"]}}
            if "addUserToGroup" in query:
                self.added.append((v["u"], v["g"]))
                return {"addUserToGroup": {"ok": True}}
            if "users(filters" in query:
                f = v["f"]["eq"]
                if f["field"] == "email":
                    return {"users": [{"id": x["id"]} for x in self.users.values() if x["email"].lower() == f["value"].lower()]}
                return {"users": [{"id": x["id"]} for x in self.users.values() if x["attrs"].get(f["field"]) == [f["value"]]]}
            if "user(userId" in query:
                if v["id"] not in self.users:
                    if tolerate:
                        return None
                    raise RuntimeError("Entity not found")
                return {"user": {"id": v["id"]}}
            if "groups" in query:
                return {"groups": GROUPS}
            raise AssertionError(query)
        M.gql = gql
        M._umbral = None
        self.parts = M.umbral_parts()
        self.cleared = []
        self.parts["sessions"].clear_pending = lambda p, s: self.cleared.append((p, s)) or True
        M.umbral_ingest = lambda: "ok"
        self.welcomed = []
        mailer.send_welcome = lambda to, label: self.welcomed.append((to, label))
        self.parts["store"]._db.execute("DELETE FROM requests")

    def add(self, **over):
        row = U.parse(record(**over)[:-1])
        self.parts["store"]._db.execute(
            "INSERT INTO requests (provider, subject, email, hd, name, note, received_at) "
            "VALUES (:provider, :subject, :email, :hd, :name, :note, :received_at)", row)
        return self.parts["store"].listing("pending")[-1]["id"]

    def as_admin(self):
        return {"Remote-User": "gluck", "Remote-Groups": "portero-admin"}

    def test_forbidden_without_group(self):
        rid = self.add()
        for method, path in [("get", "/umbral/requests"), ("post", f"/umbral/requests/{rid}/approve"),
                             ("post", f"/umbral/requests/{rid}/reject"), ("get", "/umbral/sessions"),
                             ("post", "/umbral/accounts/amy/unlink"), ("get", "/umbral/events")]:
            r = getattr(self.c, method)(path, headers={"Remote-User": "kion", "Remote-Groups": "site-x-access"},
                                        json={})
            self.assertEqual(r.status_code, 403, path)

    def test_listing_shows_subject_hd_warning_and_claims(self):
        self.add(subject="9", email="TAKEN@example.com", hd="example.com")
        rows = self.c.get("/umbral/requests", headers=self.as_admin()).get_json()["rows"]
        self.assertEqual(rows[0]["subject"], "9")
        self.assertEqual(rows[0]["claims_existing"], ["old"])
        self.assertIn("administrator can sign in as this person", rows[0]["workspace_warning"])

    def test_approve(self):
        rid = self.add(subject="777", email="nora@example.com")
        r = self.c.post(f"/umbral/requests/{rid}/approve", headers=self.as_admin(),
                        json={"username": "nora", "site_access_groups": ["friends", "site-bootystats-access"]})
        self.assertEqual(r.status_code, 201, r.get_json())
        u = self.created[0]
        self.assertNotIn("password", json.dumps(u).lower())
        self.assertEqual(u["attributes"], [{"name": "umbral-google-sub", "value": ["777"]}])
        self.assertEqual(u["email"], "nora@example.com")
        self.assertEqual(sorted(g for _, g in self.added), [30, 31])
        self.assertEqual(self.cleared, [("google", "777")])
        self.assertEqual(self.welcomed, [("nora@example.com", "Google")])
        self.assertEqual(self.parts["store"].get(rid)["state"], "approved")

    def test_approve_refusals_release_the_row(self):
        cases = [
            ("group outside the allowlist", dict(subject="1"), {"username": "nora", "site_access_groups": ["lldap_admin"]}, 400),
            ("email taken", dict(subject="2", email="taken@example.com"), {"username": "nora2"}, 409),
            ("username taken", dict(subject="3"), {"username": "old"}, 409),
        ]
        for name, row, body, status in cases:
            with self.subTest(name):
                rid = self.add(**row)
                r = self.c.post(f"/umbral/requests/{rid}/approve", headers=self.as_admin(), json=body)
                self.assertEqual(r.status_code, status, r.get_json())
                self.assertEqual(self.parts["store"].get(rid)["state"], "pending")
        self.assertEqual(self.welcomed, [])

    def test_approve_subject_already_linked(self):
        self.users["old"]["attrs"]["umbral-google-sub"] = ["5"]
        rid = self.add(subject="5")
        r = self.c.post(f"/umbral/requests/{rid}/approve", headers=self.as_admin(), json={"username": "nora"})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.created, [])

    def test_reject(self):
        rid = self.add(subject="6")
        self.assertEqual(self.c.post(f"/umbral/requests/{rid}/reject", headers=self.as_admin(), json={}).status_code, 200)
        self.assertEqual(self.cleared, [("google", "6")])
        self.assertEqual(self.c.post(f"/umbral/requests/{rid}/reject", headers=self.as_admin(), json={}).status_code, 409)


if __name__ == "__main__":
    unittest.main(verbosity=1)
