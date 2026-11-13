#!/usr/bin/env python3

import os
import subprocess
import sys
import unittest

import requests

sys.path.insert(0, os.environ.get("SRC", os.path.dirname(os.path.abspath(__file__))))
import mint as M  # noqa: E402
import umbral as U  # noqa: E402

URL = os.environ["PORTERO_LLDAP_URL"]


def login(user, password):
    r = requests.post(f"{URL}/auth/simple/login", json={"username": user, "password": password}, timeout=10)
    r.raise_for_status()
    return r.json()["token"]


def as_user(token, query, variables=None):
    r = requests.post(f"{URL}/api/graphql", headers={"Authorization": f"Bearer {token}"},
                      json={"query": query, "variables": variables or {}}, timeout=10)
    r.raise_for_status()
    return r.json()


def set_password(user, password):
    subprocess.run([os.environ["UMBRAL_TEST_SET_PASSWORD"], "--base-url", URL, "--admin-username", "admin",
                    "--admin-password", M.ADMIN_PASSWORD, "--username", user, "--password", password],
                   check=True, capture_output=True)


def admin(query, variables=None, tolerate=()):
    return M.gql(M.lldap_token(), query, variables, tolerate)


def attrs():
    data = admin("query{schema{userSchema{attributes{name attributeType isList isVisible isEditable}}}}")
    return {a["name"]: a for a in data["schema"]["userSchema"]["attributes"]}


class RealLLDAP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admin("mutation{addUserAttribute(name:\"umbral-github-id\",attributeType:STRING,isList:false,"
              "isVisible:false,isEditable:true){ok}}")
        cls.dir = U.Directory(M.umbral_gql)
        with cls.assertRaises(cls, RuntimeError):
            cls.dir.ensure_attributes()
        print("MEASURED ensure_attributes refuses a user-editable umbral-github-id")
        admin("mutation{deleteUserAttribute(name:\"umbral-github-id\"){ok}}")
        cls.dir.ensure_attributes()
        cls.dir.ensure_attributes()
        admin("mutation{createGroup(name:\"friends\"){id}}")
        admin("mutation($u:CreateUserInput!){createUser(user:$u){id}}",
              {"u": {"id": "gluck", "email": "Gluck@example.com", "displayName": "Gluck"}})
        set_password("gluck", "gluck-password-1")

    def test_U6_attributes_admin_only(self):
        a = attrs()
        for name in ("umbral-google-sub", "umbral-github-id"):
            self.assertEqual((a[name]["attributeType"], a[name]["isList"], a[name]["isVisible"], a[name]["isEditable"]),
                             ("STRING", False, False, False))

    def test_U6_own_write_refused(self):
        tok = login("gluck", "gluck-password-1")
        got = as_user(tok, "mutation($u:UpdateUserInput!){updateUser(user:$u){ok}}",
                      {"u": {"id": "gluck", "insertAttributes": [{"name": "umbral-google-sub", "value": ["999"]}]}})
        self.assertIn("not editable by regular users", str(got.get("errors")))
        self.assertEqual(self.dir.holders("google", "999"), [])
        print("MEASURED a user's own insert of umbral-google-sub:", got["errors"][0]["message"])

    def test_link_and_post_check_on_real_directory(self):
        note = []

        class N:
            def tell(self, text):
                note.append(text)
                return "test"
        store = U.Store(os.path.join(os.environ["STATE_DIRECTORY"], "link.db"))
        linker = U.Linker(self.dir, store, N())
        self.assertEqual(linker.link("gluck", "github", "4242", "gluck@EXAMPLE.com", "umbral"), "gluck")
        self.assertEqual(self.dir.holders("github", "4242"), ["gluck"])
        self.assertEqual(self.dir.user("gluck")["links"], {"github": "4242"})
        with self.assertRaises(U.Refused) as cm:
            linker.link("gluck", "github", "5", "gluck@example.com", "umbral")
        self.assertEqual(cm.exception.status, 409)
        admin("mutation($u:CreateUserInput!){createUser(user:$u){id}}", {"u": {"id": "other", "email": "o@example.com"}})
        with self.assertRaises(U.Refused) as cm:
            linker.link("other", "github", "4242", "o@example.com", "umbral")
        self.assertEqual(cm.exception.status, 409)
        self.assertEqual(len(note), 1)
        tok = login("gluck", "gluck-password-1")
        got = as_user(tok, "mutation($u:UpdateUserInput!){updateUser(user:$u){ok}}",
                      {"u": {"id": "gluck", "removeAttributes": ["umbral-github-id"]}})
        print("MEASURED a user's own removeAttributes of umbral-github-id:", got,
              "holders after:", self.dir.holders("github", "4242"))

    def test_approval_creates_credential_less_linked_account(self):
        parts = M.umbral_parts()
        row = {"provider": "google", "subject": "777", "email": "nora@example.com"}
        payload, status = M.provision_linked(parts, "nora", row, "Nora", ["friends"])
        self.assertEqual(status, 201, payload)
        self.assertEqual(self.dir.holders("google", "777"), ["nora"])
        r = requests.post(f"{URL}/auth/simple/login", json={"username": "nora", "password": ""}, timeout=10)
        self.assertNotEqual(r.status_code, 200)
        payload, status = M.provision_linked(parts, "nora2", row, "Nora", [])
        self.assertEqual(status, 409)
        payload, status = M.provision_linked(parts, "nora3", dict(row, subject="778", email="NORA@example.com"), "", [])
        self.assertEqual(status, 409)
        self.assertIn("already belongs to an account", payload["error"])
        self.assertEqual(parts["dir"].by_email("NORA@EXAMPLE.COM"), ["nora"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
