import base64
import hashlib
import os

from flask import request

SCHEMES = {"light", "dark"}

CSP = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; form-action 'self'"

_HERE = os.path.dirname(os.path.abspath(__file__))


def _shipped(name, mode="r"):
    path = os.path.join(_HERE, name)
    if not os.path.exists(path):
        return "" if mode == "r" else b""
    with open(path, mode, **({"encoding": "utf-8"} if mode == "r" else {})) as f:
        return f.read()


ZANNI = _shipped("zanni.css")
HEFT_CSS = _shipped("heft.css")
HEFT_JS = _shipped("heft.js")
PARLA_CSS = _shipped("parla.css")
PARLA_JS = _shipped("parla.js")
FIGARO_HEAD = "data:image/png;base64," + base64.b64encode(_shipped("figaro-head.png", "rb")).decode()
SCRIPTS = [js for js in (HEFT_JS, PARLA_JS) if js]

STYLE = """
:root{color-scheme:light dark}
body{font:18px/1.55 var(--fontpack-prose,Georgia,serif);max-width:27rem;margin:5rem auto;padding:0 1.2rem}
h1{font:400 2.1rem/1.1 var(--fontpack-display,Georgia,serif);letter-spacing:.02em;margin:0 0 .6rem}
p{color:var(--z-muted)} strong{color:var(--z-ink)}
label{display:block;margin:1.4rem 0 .35rem;font:18px/1.1 var(--fontpack-mono,monospace);letter-spacing:.04em}
input{width:100%;box-sizing:border-box;padding:.6rem;font:inherit;color:var(--z-ink);background:light-dark(#fbf6f0,#140a0b);border:1px solid var(--z-line);border-radius:4px}
input:focus{outline:1px solid var(--z-focus);border-color:var(--z-focus)}
button{margin-top:1.4rem;padding:.6rem 1.1rem;font:19px/1.1 var(--fontpack-mono,monospace);letter-spacing:.04em;border:0;border-radius:4px;background:var(--z-accent);color:var(--z-on-accent);cursor:pointer}
a{color:var(--z-accent)}
.err{color:var(--z-fail);font-weight:600}
"""


def scheme_attr():
    scheme = request.cookies.get("zanni-scheme")
    return f' data-scheme="{scheme}"' if scheme in SCHEMES else ""


def document(title, body):
    return (
        f"<!doctype html><html lang=en{scheme_attr()}><meta charset=utf-8>\n"
        '<meta name=viewport content="width=device-width,initial-scale=1">\n'
        "<meta name=referrer content=no-referrer>\n"
        f"<title>{title}</title>\n"
        f"<style>{ZANNI}{STYLE}</style>\n"
        f'<body class="gesso">\n<h1>{title}</h1>\n{body}\n'
    )


PAGE_STYLE = """
.aside{font-size:.85rem}
@media (min-width:640px){body{max-width:31rem}}
"""

STAGE_STYLE = ZANNI + STYLE + PAGE_STYLE + HEFT_CSS + PARLA_CSS


def _sha256(text):
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


STAGE_CSP = "; ".join(
    ["default-src 'none'", f"style-src {_sha256(STAGE_STYLE)}", "img-src data:"]
    + (["script-src " + " ".join(_sha256(js) for js in SCRIPTS)] if SCRIPTS else [])
    + ["font-src data:", "form-action 'self'"]
)


def figaro(says):
    return (
        '<div class="parla" data-parla>'
        f'<img class="parla-head heft" src="{FIGARO_HEAD}" alt="Figaro" draggable="false">'
        f'<p class="parla-bubble">{says}</p></div>'
    )


def stage(title, body):
    scripts = "".join(f"<script>{js}</script>\n" for js in SCRIPTS)
    return (
        f"<!doctype html><html lang=en{scheme_attr()}><meta charset=utf-8>\n"
        '<meta name=viewport content="width=device-width,initial-scale=1">\n'
        "<meta name=referrer content=no-referrer>\n"
        f"<title>{title}</title>\n"
        f"<style>{STAGE_STYLE}</style>\n"
        f'<body class="gesso">\n<h1>{title}</h1>\n{body}\n{scripts}'
    )
