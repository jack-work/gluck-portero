import os

from flask import request

SCHEMES = {"light", "dark"}

CSP = "default-src 'none'; style-src 'unsafe-inline'; font-src data:; form-action 'self'"

_ZANNI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zanni.css")
ZANNI = open(_ZANNI, encoding="utf-8").read() if os.path.exists(_ZANNI) else ""

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
