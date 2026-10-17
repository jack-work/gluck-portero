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
FIGARO_HEAD = "data:image/png;base64," + base64.b64encode(_shipped("figaro-head.png", "rb")).decode()

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


FIGARO_STYLE = """
.figaro{display:flex;align-items:flex-start;gap:1.2rem;margin:.4rem 0 1.4rem}
.figaro-head{flex:none;width:104px;height:104px;box-sizing:border-box;image-rendering:pixelated;border:3px solid light-dark(#a2762a,#d9a94e);background:#e7d4c4}
.bubble{position:relative;flex:1;margin:.2rem 0 0;padding:.75rem 1rem;font:19px/1.45 var(--fontpack-prose,Georgia,serif);color:var(--z-ink);background:var(--z-ground-2);border:2px solid var(--z-ink);border-radius:14px}
.bubble::before,.bubble::after{content:"";position:absolute;border-style:solid;border-color:transparent}
.bubble::before{left:-16px;top:56px;border-width:8px 16px 8px 0;border-right-color:var(--z-ink)}
.bubble::after{left:-12px;top:58px;border-width:6px 13px 6px 0;border-right-color:var(--z-ground-2)}
.aside{font-size:.85rem}
@media (min-width:640px){body{max-width:31rem}.figaro-head{width:130px;height:130px}.bubble::before{top:71px}.bubble::after{top:73px}}
"""

STAGE_STYLE = ZANNI + STYLE + FIGARO_STYLE + HEFT_CSS


def _sha256(text):
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


STAGE_CSP = "; ".join(
    ["default-src 'none'", f"style-src {_sha256(STAGE_STYLE)}", "img-src data:"]
    + ([f"script-src {_sha256(HEFT_JS)}"] if HEFT_JS else [])
    + ["font-src data:", "form-action 'self'"]
)


def figaro(says):
    return (
        '<div class="figaro">'
        f'<img class="figaro-head heft" src="{FIGARO_HEAD}" alt="Figaro" draggable="false">'
        f'<p class="bubble">{says}</p></div>'
    )


def stage(title, body):
    script = f"<script>{HEFT_JS}</script>\n" if HEFT_JS else ""
    return (
        f"<!doctype html><html lang=en{scheme_attr()}><meta charset=utf-8>\n"
        '<meta name=viewport content="width=device-width,initial-scale=1">\n'
        "<meta name=referrer content=no-referrer>\n"
        f"<title>{title}</title>\n"
        f"<style>{STAGE_STYLE}</style>\n"
        f'<body class="gesso">\n<h1>{title}</h1>\n{body}\n{script}'
    )
