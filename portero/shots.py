"""Screenshots of the intake pages as a browser renders them, light and dark,
at phone and desktop widths, against the packaged source. Fails if the page
asks anything of another origin, if the browser refuses anything under the
CSP (which would mean the hashes drifted from what is served), if the faces
do not load, or if Figaro cannot be picked up and does not settle back."""
import os
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import expect, sync_playwright

OUT = sys.argv[1]
PORT = 9179
U = f"http://127.0.0.1:{PORT}"

server = subprocess.Popen([sys.executable, os.path.join(os.environ["PORTERO_SRC"], "intake.py")],
                          env=dict(os.environ, PORT=str(PORT)))
try:
    for _ in range(100):
        try:
            urllib.request.urlopen(U + "/healthz")
            break
        except OSError:
            time.sleep(0.1)

    foreign, refused, faces = [], [], {}
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        for width, height, name in ((390, 844, "phone"), (1280, 860, "desktop")):
            for scheme in ("light", "dark"):
                ctx = b.new_context(viewport={"width": width, "height": height}, color_scheme=scheme)
                pg = ctx.new_page()
                pg.on("request", lambda r: foreign.append(r.url) if not r.url.startswith((U + "/", "data:")) else None)
                pg.on("console", lambda m: refused.append(m.text) if "Content Security Policy" in m.text or "Refused" in m.text else None)

                pg.goto(U + "/intake")
                expect(pg.locator(".parla-bubble")).to_be_visible()
                pg.evaluate("document.fonts.ready")
                faces[f"{name}-{scheme}"] = pg.evaluate(
                    "[...document.fonts].filter(f => f.status === 'loaded').map(f => f.family.replace(/[\"']/g, ''))")
                pg.screenshot(path=f"{OUT}/intake-{name}-{scheme}.png", full_page=True)

                head = pg.locator(".parla-head")
                box = head.bounding_box()
                cx, cy = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
                pg.mouse.move(cx, cy)
                pg.mouse.down()
                pg.mouse.move(cx + 60, cy + 40, steps=6)
                pg.mouse.move(cx + 140, cy + 90, steps=6)
                held = head.evaluate("e => [e.classList.contains('held'), e.style.translate]")
                assert held[0] and held[1] == "140px 90px", f"Figaro was not picked up: {held}"
                pg.screenshot(path=f"{OUT}/intake-{name}-{scheme}-held.png", full_page=True)
                pg.mouse.up()
                pg.wait_for_timeout(900)
                back = head.bounding_box()
                assert abs(back["x"] - box["x"]) < 1 and abs(back["y"] - box["y"]) < 1, (box, back)

                pg.goto(U + "/terms")
                expect(pg.get_by_text("I am not liable")).to_be_visible()
                pg.screenshot(path=f"{OUT}/terms-{name}-{scheme}.png", full_page=True)
                pg.goto(U + "/intake")
                pg.fill("#e", "figaro@example.com")
                pg.click("button[type=submit]")
                expect(pg.get_by_text("Thank you. If an invitation is sent")).to_be_visible()
                pg.screenshot(path=f"{OUT}/answer-{name}-{scheme}.png", full_page=True)
                ctx.close()
        b.close()
finally:
    server.terminate()

print("faces", faces)
assert not foreign, f"the page reached off its origin: {foreign}"
assert not refused, f"the browser refused something under the CSP: {refused}"
for shot, loaded in faces.items():
    assert {"Jacquard 24", "EB Garamond", "VT323"} <= set(loaded), (shot, loaded)
print("ok")
