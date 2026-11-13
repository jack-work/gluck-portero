#!/usr/bin/env python3

import calendar
import errno
import fcntl
import http.client
import http.server
import json
import logging
import os
import pwd
import re
import socket
import socketserver
import sqlite3
import stat
import struct
import threading
import time
import urllib.parse

import requests

log = logging.getLogger("portero-umbral")

PROVIDERS = {"google": "umbral-google-sub", "github": "umbral-github-id"}
LABELS = {"google": "Google", "github": "GitHub"}
SUBJECT_RE = {
    "google": re.compile(r"^[A-Za-z0-9_-]{1,255}$"),
    "github": re.compile(r"^[1-9][0-9]{0,19}$"),
}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HD_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
NAME_MAX = 100
NOTE_MAX = 500
RECORD_MAX = 4096

FS_IOC_GETFLAGS = 0x80086601
FS_APPEND_FL = 0x00000020

ACL_XATTR = "system.posix_acl_access"
ACL_USER_OBJ, ACL_USER, ACL_GROUP_OBJ, ACL_GROUP, ACL_MASK, ACL_OTHER = 1, 2, 4, 8, 0x10, 0x20


class LayoutWrong(Exception):
    pass


def append_only(fd):
    buf = fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("l", 0))
    return bool(struct.unpack("l", buf)[0] & FS_APPEND_FL)


def acl_entries(fd):
    raw = os.getxattr(fd, ACL_XATTR)
    version, = struct.unpack_from("<I", raw, 0)
    if version != 2 or (len(raw) - 4) % 8:
        raise LayoutWrong("acl format")
    out = set()
    for off in range(4, len(raw), 8):
        tag, perm, ident = struct.unpack_from("<HHI", raw, off)
        if tag not in (ACL_USER, ACL_GROUP):
            ident = None
        out.add((tag, perm, ident))
    return out


def expected_acl(writer_gid):
    return {
        (ACL_USER_OBJ, 6, None),
        (ACL_GROUP_OBJ, 4, None),
        (ACL_GROUP, 2, writer_gid),
        (ACL_MASK, 6, None),
        (ACL_OTHER, 0, None),
    }


def open_checked(path, reader_gid, writer_gid, owner=0, flags_of=append_only, acl_of=acl_entries):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        wrong = []
        if not stat.S_ISREG(st.st_mode):
            wrong.append("type")
        if st.st_uid != owner:
            wrong.append(f"owner={st.st_uid}")
        if st.st_gid != reader_gid:
            wrong.append(f"group={st.st_gid}")
        if stat.S_IMODE(st.st_mode) != 0o660:
            wrong.append(f"mode={stat.S_IMODE(st.st_mode):o}")
        if st.st_nlink != 1:
            wrong.append(f"links={st.st_nlink}")
        try:
            if not flags_of(fd):
                wrong.append("append_only=no")
        except OSError as exc:
            wrong.append(f"flags={errno.errorcode.get(exc.errno, exc.errno)}")
        try:
            if acl_of(fd) != expected_acl(writer_gid):
                wrong.append("acl")
        except OSError as exc:
            wrong.append(f"acl={errno.errorcode.get(exc.errno, exc.errno)}")
        if wrong:
            raise LayoutWrong(" ".join(wrong))
        return fd
    except BaseException:
        os.close(fd)
        raise


def parse(line):
    if len(line) > RECORD_MAX:
        return None
    try:
        row = json.loads(line)
    except ValueError:
        return None
    if not isinstance(row, dict) or row.get("v") != 1:
        return None
    provider = row.get("provider")
    if provider not in PROVIDERS:
        return None
    fields = {k: row.get(k, "") for k in ("subject", "email", "hd", "name", "note", "at")}
    if not all(isinstance(v, str) for v in fields.values()):
        return None
    if not SUBJECT_RE[provider].fullmatch(fields["subject"]):
        return None
    if not EMAIL_RE.fullmatch(fields["email"]) or len(fields["email"]) > 254:
        return None
    if fields["hd"] and not HD_RE.fullmatch(fields["hd"]):
        return None
    if not fields["name"] or len(fields["name"]) > NAME_MAX or len(fields["note"]) > NOTE_MAX:
        return None
    try:
        at = calendar.timegm(time.strptime(fields["at"], "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None
    return {"provider": provider, "subject": fields["subject"], "email": fields["email"],
            "hd": fields["hd"], "name": fields["name"], "note": fields["note"], "received_at": at}


SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  provider    TEXT NOT NULL,
  subject     TEXT NOT NULL,
  email       TEXT NOT NULL,
  hd          TEXT NOT NULL DEFAULT '',
  name        TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT '',
  received_at INTEGER NOT NULL,
  state       TEXT NOT NULL DEFAULT 'pending',
  username    TEXT,
  decided_by  TEXT,
  decided_at  INTEGER,
  UNIQUE (provider, subject, received_at)
);
CREATE INDEX IF NOT EXISTS requests_state ON requests(state, id);
CREATE TABLE IF NOT EXISTS events (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  at       INTEGER NOT NULL,
  action   TEXT NOT NULL,
  uid      TEXT NOT NULL,
  provider TEXT NOT NULL,
  subject  TEXT NOT NULL,
  by       TEXT NOT NULL,
  notified TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
"""


class Store:
    def __init__(self, path, cap=200):
        self._lock = threading.Lock()
        self.cap = int(cap)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(SCHEMA)

    def _rows(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def offset(self):
        rows = self._rows("SELECT value FROM meta WHERE key='offset'")
        return rows[0]["value"] if rows else 0

    def ingest(self, fd, limit=1 << 20):
        start = self.offset()
        size = os.fstat(fd).st_size
        if start > size:
            raise LayoutWrong(f"offset {start} past end {size}")
        blob = os.pread(fd, limit, start)
        cut = blob.rfind(b"\n")
        if cut < 0:
            return 0, 0, start
        landed = skipped = 0
        end = start
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                pending = self._db.execute("SELECT COUNT(*) FROM requests WHERE state='pending'").fetchone()[0]
                pos = start
                for line in blob[:cut].split(b"\n"):
                    line_end = pos + len(line) + 1
                    row = parse(line) if line else None
                    if line and row is None:
                        skipped += 1
                    elif row is not None:
                        if pending >= self.cap:
                            break
                        cur = self._db.execute(
                            "INSERT OR IGNORE INTO requests (provider, subject, email, hd, name, note, received_at) "
                            "VALUES (:provider, :subject, :email, :hd, :name, :note, :received_at)", row)
                        landed += cur.rowcount
                        pending += cur.rowcount
                    pos = end = line_end
                self._db.execute("INSERT INTO meta (key, value) VALUES ('offset', ?) "
                                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (end,))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return landed, skipped, end

    def get(self, row_id):
        rows = self._rows("SELECT * FROM requests WHERE id=?", (int(row_id),))
        return rows[0] if rows else None

    def listing(self, state=None, limit=500):
        if state is None:
            return self._rows("SELECT * FROM requests ORDER BY id DESC LIMIT ?", (int(limit),))
        return self._rows("SELECT * FROM requests WHERE state=? ORDER BY id LIMIT ?", (state, int(limit)))

    def claim(self, row_id, username, by):
        with self._lock:
            cur = self._db.execute(
                "UPDATE requests SET state='approved', username=?, decided_by=?, decided_at=? "
                "WHERE id=? AND state='pending'", (username, by, int(time.time()), int(row_id)))
            return cur.rowcount == 1

    def release(self, row_id):
        with self._lock:
            cur = self._db.execute(
                "UPDATE requests SET state='pending', username=NULL, decided_by=NULL, decided_at=NULL "
                "WHERE id=? AND state='approved'", (int(row_id),))
            return cur.rowcount == 1

    def reject(self, row_id, by):
        with self._lock:
            cur = self._db.execute(
                "UPDATE requests SET state='rejected', decided_by=?, decided_at=? WHERE id=? AND state='pending'",
                (by, int(time.time()), int(row_id)))
            return cur.rowcount == 1

    def record(self, action, uid, provider, subject, by):
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO events (at, action, uid, provider, subject, by) VALUES (?,?,?,?,?,?)",
                (int(time.time()), action, uid, provider, subject, by))
            return cur.lastrowid

    def notified(self, event_id, how):
        with self._lock:
            self._db.execute("UPDATE events SET notified=? WHERE id=?", (how, int(event_id)))

    def events(self, limit=200):
        return self._rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (int(limit),))


class Directory:

    def __init__(self, gql):
        self.gql = gql

    def ensure_attributes(self):
        data = self.gql("query{schema{userSchema{attributes{name attributeType isList isVisible isEditable}}}}")
        have = {a["name"]: a for a in data["schema"]["userSchema"]["attributes"]}
        for name in PROVIDERS.values():
            a = have.get(name)
            if a is None:
                self.gql("mutation($n:String!){addUserAttribute(name:$n,attributeType:STRING,isList:false,"
                         "isVisible:false,isEditable:false){ok}}", {"n": name})
                log.info("created lldap attribute %s admin-only", name)
                continue
            if a["attributeType"] != "STRING" or a["isList"] or a["isVisible"] or a["isEditable"]:
                raise RuntimeError(f"lldap attribute {name} is not admin-only STRING: {a}")

    def holders(self, provider, subject):
        data = self.gql("query($f:RequestFilter!){users(filters:$f){id}}",
                        {"f": {"eq": {"field": PROVIDERS[provider], "value": subject}}})
        return [u["id"] for u in data["users"]]

    def by_email(self, email):
        data = self.gql("query($f:RequestFilter!){users(filters:$f){id}}",
                        {"f": {"eq": {"field": "email", "value": email}}})
        return [u["id"] for u in data["users"]]

    def user(self, uid):
        data = self.gql("query($id:String!){user(userId:$id){id email attributes{name value}}}",
                        {"id": uid}, tolerate=("Entity not found",))
        if not data or not data.get("user"):
            return None
        u = data["user"]
        attrs = {a["name"]: a["value"] for a in u["attributes"]}
        return {"id": u["id"], "email": u["email"],
                "links": {p: (attrs.get(a) or [""])[0] for p, a in PROVIDERS.items() if attrs.get(a)}}

    def set_link(self, uid, provider, subject):
        self.gql("mutation($u:UpdateUserInput!){updateUser(user:$u){ok}}",
                 {"u": {"id": uid, "insertAttributes": [{"name": PROVIDERS[provider], "value": [subject]}]}})

    def clear_link(self, uid, provider):
        self.gql("mutation($u:UpdateUserInput!){updateUser(user:$u){ok}}",
                 {"u": {"id": uid, "removeAttributes": [PROVIDERS[provider]]}})


class Refused(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class Linker:

    def __init__(self, directory, store, notifier):
        self.dir = directory
        self.store = store
        self.notifier = notifier
        self._lock = threading.Lock()

    def link(self, uid, provider, subject, email, by):
        if provider not in PROVIDERS or not isinstance(subject, str) or not SUBJECT_RE[provider].fullmatch(subject):
            raise Refused(400, "bad provider or subject")
        if not isinstance(uid, str) or not uid or not isinstance(email, str):
            raise Refused(400, "bad uid or email")
        with self._lock:
            user = self.dir.user(uid)
            if user is None:
                raise Refused(404, "no such account")
            if user["email"].lower() != email.lower():
                raise Refused(403, "verified email is not the account's mail")
            if user["links"].get(provider):
                raise Refused(409, "account already linked for this provider")
            if self.dir.holders(provider, subject):
                raise Refused(409, "subject already linked")
            self.dir.set_link(user["id"], provider, subject)
            after = self.dir.holders(provider, subject)
            if after != [user["id"]]:
                log.error("link of %s %s to %r left holders %r", provider, subject, user["id"], after)
                raise Refused(409, "subject on more than one account")
        event = self.store.record("link", user["id"], provider, subject, by)
        log.info("umbral link written uid=%s provider=%s subject=%s", user["id"], provider, subject)
        self.store.notified(event, self.notifier.tell(
            f"Linked {LABELS[provider]} to {user['id']} (subject {subject}) at login.kelliher.info."))
        return user["id"]

    def unlink(self, uid, provider, by):
        if provider not in PROVIDERS:
            raise Refused(400, "bad provider")
        with self._lock:
            user = self.dir.user(uid)
            if user is None:
                raise Refused(404, "no such account")
            subject = user["links"].get(provider)
            if not subject:
                raise Refused(409, "not linked")
            self.dir.clear_link(user["id"], provider)
        self.store.record("unlink", user["id"], provider, subject, by)
        log.info("umbral link removed uid=%s provider=%s subject=%s by=%r", user["id"], provider, subject, by)
        return subject


class Notifier:

    def __init__(self, token_url="", client_id="", secret_file="", herald_url="", to="gluck",
                 mail=None, http=None):
        self.token_url = token_url
        self.client_id = client_id
        self.secret_file = secret_file
        self.herald_url = herald_url.rstrip("/")
        self.to = to
        self.mail = mail
        self.http = http or requests.Session()

    def _herald(self, text):
        with open(self.secret_file, "r", encoding="utf-8") as fh:
            secret = fh.read().strip()
        r = self.http.post(self.token_url, data={"grant_type": "client_credentials"},
                           auth=(urllib.parse.quote(self.client_id, safe=""), urllib.parse.quote(secret, safe="")),
                           timeout=10)
        r.raise_for_status()
        token = r.json()["access_token"]
        r = self.http.post(f"{self.herald_url}/v1/say", json={"to": self.to, "text": text},
                           headers={"Authorization": f"Bearer {token}"}, timeout=10)
        r.raise_for_status()

    def tell(self, text):
        if self.token_url and self.client_id and self.secret_file and self.herald_url:
            try:
                self._herald(text)
                return "herald"
            except Exception as exc:
                log.error("herald notification failed: %s", type(exc).__name__)
        if self.mail is not None:
            try:
                self.mail(text)
                return "mail"
            except Exception as exc:
                log.error("mail notification failed: %s", type(exc).__name__)
        return "failed"


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=10):
        super().__init__("umbral", timeout=timeout)
        self.path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path)
        self.sock = s


class Sessions:

    def __init__(self, path):
        self.path = path

    def _call(self, method, target):
        conn = _UnixHTTPConnection(self.path)
        try:
            conn.request(method, target)
            resp = conn.getresponse()
            body = resp.read(1 << 20)
            return resp.status, body
        finally:
            conn.close()

    def listing(self, uid=""):
        target = "/sessions" + (f"?uid={urllib.parse.quote(uid, safe='')}" if uid else "")
        status, body = self._call("GET", target)
        if status != 200:
            raise RuntimeError(f"umbral admin answered {status}")
        return json.loads(body)

    def kill(self, handle):
        status, _ = self._call("DELETE", f"/sessions/{urllib.parse.quote(handle, safe='')}")
        return status == 204

    def kill_uid(self, uid):
        status, body = self._call("DELETE", f"/sessions?uid={urllib.parse.quote(uid, safe='')}")
        if status != 200:
            raise RuntimeError(f"umbral admin answered {status}")
        return json.loads(body).get("deleted", 0)

    def clear_pending(self, provider, subject):
        status, _ = self._call("DELETE", f"/pending/{urllib.parse.quote(provider, safe='')}/{urllib.parse.quote(subject, safe='')}")
        return status in (204, 404)


def peer_uid(sock):
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", raw)
    return uid


def lookup_uid(name):
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


class LinkServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):

    daemon_threads = True

    def __init__(self, sock, linker, peer_name, resolve=lookup_uid, peer_of=peer_uid):
        socketserver.UnixStreamServer.__init__(self, "", _LinkHandler, bind_and_activate=False)
        self.socket.close()
        self.socket = sock
        self.linker = linker
        self.peer_name = peer_name
        self.resolve = resolve
        self.peer_of = peer_of

    def verify_request(self, request, client_address):
        try:
            got = self.peer_of(request)
        except OSError:
            got = None
        want = self.resolve(self.peer_name)
        if want is None or got != want:
            log.warning("umbral link socket refused peer uid=%s", got)
            return False
        return True


class _LinkHandler(http.server.BaseHTTPRequestHandler):
    server_version = "portero-link"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _answer(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._answer(400, {"error": "length"})
        if not 0 < length <= 4096:
            return self._answer(413, {"error": "size"})
        raw = self.rfile.read(length)
        if self.path != "/link":
            return self._answer(404, {"error": "not found"})
        if self.headers.get_content_type() != "application/json":
            return self._answer(415, {"error": "json only"})
        try:
            body = json.loads(raw)
        except ValueError:
            return self._answer(400, {"error": "bad json"})
        if not isinstance(body, dict) or set(body) != {"uid", "provider", "subject", "email"}:
            return self._answer(400, {"error": "want exactly uid, provider, subject, email"})
        try:
            uid = self.server.linker.link(body["uid"], body["provider"], body["subject"], body["email"], by="umbral")
        except Refused as exc:
            log.info("umbral link refused: %s", exc.reason)
            return self._answer(exc.status, {"error": exc.reason})
        except Exception:
            log.exception("umbral link failed")
            return self._answer(502, {"error": "link failed"})
        return self._answer(200, {"linked": uid})

    def do_GET(self):
        self._answer(405, {"error": "POST /link only"})

    do_PUT = do_DELETE = do_PATCH = do_GET
