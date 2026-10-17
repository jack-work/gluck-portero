"""The intake pages wear zanni with no request to anyone: the faces are inline
data: woff2, Figaro's head is an inline data: PNG, and the one script is
zanni's heft and parla, each admitted by its hash as the style block is, so
neither inline style nor any other script can run. The reader's light/dark choice from the
zanni-scheme cookie is rendered onto <html> only when it is exactly "light"
or "dark". Runs against the packaged source (PORTERO_SRC), because that is
where zanni.css, heft and parla are copied in."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.environ["PORTERO_SRC"])
_TMP = tempfile.mkdtemp()
os.environ["PORTERO_INTAKE_SPOOL"] = os.path.join(_TMP, "spool.jsonl")
open(os.environ["PORTERO_INTAKE_SPOOL"], "wb").close()
os.environ["PORTERO_RESPONSE_FLOOR"] = "0.01"

import intake as I  # noqa: E402
import look  # noqa: E402


class Look(unittest.TestCase):
    def setUp(self):
        self.c = I.app.test_client()

    def get(self, cookie):
        if cookie is None:
            self.c.delete_cookie("zanni-scheme")
        else:
            self.c.set_cookie("zanni-scheme", cookie)
        r = self.c.get("/intake")
        return r, r.get_data(as_text=True)

    def test_the_faces_ship_inline(self):
        r, body = self.get(None)
        self.assertEqual(r.status_code, 200)
        self.assertIn("src: url(data:font/woff2;base64,", body)
        self.assertIn("'EB Garamond'", body)
        self.assertIn("'VT323'", body)
        self.assertNotIn("googleapis", body)
        self.assertNotIn("gstatic", body)

    def test_the_csp_names_exactly_the_style_and_scripts_it_serves(self):
        import base64, hashlib, re
        r, body = self.get(None)
        csp = r.headers["Content-Security-Policy"]
        style = body.split("<style>", 1)[1].split("</style>", 1)[0]
        scripts = re.findall(r"<script>(.*?)</script>", body, re.S)
        self.assertEqual(len(scripts), 2)
        h = lambda t: "'sha256-" + base64.b64encode(hashlib.sha256(t.encode()).digest()).decode() + "'"
        self.assertEqual(csp, "default-src 'none'; "
                              f"style-src {h(style)}; img-src data:; script-src {h(scripts[0])} {h(scripts[1])}; "
                              "font-src data:; form-action 'self'")
        self.assertNotIn("unsafe", csp)

    def test_the_only_scripts_are_zannis_heft_and_parla(self):
        _, body = self.get("dark")
        self.assertEqual(body.lower().count("<script"), 2)
        for name in ("heft.js", "parla.js"):
            with open(os.path.join(os.environ["PORTERO_SRC"], name), encoding="utf-8") as f:
                self.assertIn(f"<script>{f.read()}</script>", body)

    def test_figaro_is_inline_and_draggable(self):
        import re
        _, body = self.get(None)
        srcs = re.findall(r'(?:src|href)="([^"]*)"', body)
        self.assertEqual(len(srcs), 1)
        self.assertTrue(srcs[0].startswith("data:image/png;base64,"), srcs[0][:40])
        self.assertIn('class="parla-head heft"', body)
        self.assertIn("data-parla", body)
        self.assertNotIn("style=", body)
        self.assertNotIn("http", body.split("<style>", 1)[0] + body.split("</style>", 1)[1])

    def test_the_answer_wears_it_too(self):
        r = self.c.post("/intake", data={"email": "x@example.com"})
        self.assertEqual(r.headers["Content-Security-Policy"], self.get(None)[0].headers["Content-Security-Policy"])
        self.assertIn('class="parla-bubble"', r.get_data(as_text=True))

    def test_follows_the_os_without_a_cookie(self):
        r, body = self.get(None)
        self.assertNotIn("data-scheme", body.split("<meta", 1)[0])
        self.assertIn("color-scheme:light dark", body)
        self.assertIn("Cookie", r.headers.get("Vary", ""))

    def test_pins_light_and_dark(self):
        for s in ("light", "dark"):
            _, body = self.get(s)
            self.assertTrue(body.startswith(f'<!doctype html><html lang=en data-scheme="{s}">'), body[:80])

    def test_ignores_anything_else(self):
        for bad in ("system", "", '"><script>x</script>', "Dark"):
            _, body = self.get(bad)
            self.assertNotIn("data-scheme=", body.split("<meta", 1)[0])
            self.assertNotIn("<script>x", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
