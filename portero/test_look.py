"""The invite pages wear zanni with no request to anyone: the faces are inline
data: woff2 (font-src data: is the only widening of the CSP), there is still
no script, and the reader's light/dark choice from the zanni-scheme cookie is
rendered onto <html> only when it is exactly "light" or "dark". Runs against
the packaged source (PORTERO_SRC), because that is where zanni.css is built."""
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

    def test_the_csp_widens_only_for_inline_fonts(self):
        r, _ = self.get(None)
        self.assertEqual(r.headers["Content-Security-Policy"],
                         "default-src 'none'; style-src 'unsafe-inline'; font-src data:; form-action 'self'")

    def test_there_is_still_no_script(self):
        _, body = self.get("dark")
        self.assertNotIn("<script", body.lower())

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
