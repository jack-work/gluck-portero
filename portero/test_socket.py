#!/usr/bin/env python3
"""mint over an inherited unix socket, against the shipped tree.

  trust      Remote-User on the socket is believed: the positive control
  underscore Remote_User and remote_user are not believed
  no tcp     PORT is set but nothing listens on it
  refuse     PORTERO_LISTEN=socket with no inherited socket exits nonzero
"""
import http.client
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

SRC = os.environ["PORTERO_SRC"]
ACTIVATE = os.environ["SOCKET_ACTIVATE"]
TMP = tempfile.mkdtemp()
SOCK = os.path.join(TMP, "mint.sock")
PORT = 29101


def env():
    creds = os.path.join(TMP, "creds")
    os.makedirs(creds, exist_ok=True)
    with open(os.path.join(creds, "invite_key"), "wb") as fh:
        fh.write(b"k" * 48)
    with open(os.path.join(creds, "admin_password"), "w") as fh:
        fh.write("fixture")
    return {
        **os.environ,
        "CREDENTIALS_DIRECTORY": creds,
        "PORTERO_LISTEN": "socket",
        "PORT": str(PORT),
        "PORTERO_INTAKE_DB": os.path.join(TMP, "intake.db"),
        "PORTERO_INTAKE_SPOOL": os.path.join(TMP, "spool.jsonl"),
        "PYTHONPATH": SRC,
    }


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect(SOCK)


def whoami(headers):
    c = UnixConnection("mint")
    c.putrequest("GET", "/invites/whoami")
    for k, v in headers:
        c.putheader(k, v)
    c.endheaders()
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body


class Socket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        e = env()
        forward = [f"--setenv={k}" for k in ("CREDENTIALS_DIRECTORY", "PORTERO_LISTEN", "PORT",
                                              "PORTERO_INTAKE_DB", "PORTERO_INTAKE_SPOOL", "PYTHONPATH")]
        cls.proc = subprocess.Popen(
            [ACTIVATE, "-l", SOCK, *forward, sys.executable, os.path.join(SRC, "mint.py")],
            env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(SOCK):
                break
            time.sleep(0.05)
        for _ in range(100):
            try:
                whoami([])
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("mint never answered on the socket")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=10)

    def test_positive_control_hyphen_is_believed(self):
        status, body = whoami([("Remote-User", "forged-admin")])
        self.assertEqual(status, 200)
        self.assertIn(b"forged-admin", body)

    def test_underscore_forms_are_not_believed(self):
        for name in ("Remote_User", "remote_user"):
            status, body = whoami([(name, "forged-admin")])
            self.assertEqual(status, 401, name)
            self.assertIn(b"unauthenticated", body, name)
            self.assertNotIn(b"forged-admin", body, name)

    def test_no_tcp_listener(self):
        s = socket.socket()
        s.settimeout(1)
        with self.assertRaises(OSError):
            s.connect(("127.0.0.1", PORT))
        s.close()


class Refuse(unittest.TestCase):
    def test_no_inherited_socket_means_no_start(self):
        r = subprocess.run([sys.executable, os.path.join(SRC, "mint.py")], env=env(),
                           capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing to fall back to TCP", r.stderr + r.stdout)
        s = socket.socket()
        s.settimeout(1)
        with self.assertRaises(OSError):
            s.connect(("127.0.0.1", PORT))
        s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
