#!/usr/bin/env python3
"""A real SMTP server that keeps what it is given. Test scaffolding only.

Not an SMTP mock: the mint half speaks the protocol to this over a socket, so
what is asserted is the message that actually left the process. It never ships;
porteroSrc copies named runtime modules and this is not one of them.
"""

import base64
import os
import socket
import sys
import threading

GREETING = b"220 sink ESMTP\r\n"


def handle(conn, outdir, counter):
    conn.sendall(GREETING)
    data = b""
    envelope = {"from": "", "to": []}
    body = None

    def line():
        nonlocal data
        while b"\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            data += chunk
        one, data = data.split(b"\r\n", 1)
        return one

    while True:
        raw = line()
        if raw is None:
            break
        cmd = raw.decode("utf-8", "replace")
        up = cmd.upper()
        if up.startswith("EHLO") or up.startswith("HELO"):
            conn.sendall(b"250-sink\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n")
        elif up.startswith("AUTH LOGIN"):
            conn.sendall(b"334 " + base64.b64encode(b"Username:") + b"\r\n")
            line()
            conn.sendall(b"334 " + base64.b64encode(b"Password:") + b"\r\n")
            line()
            conn.sendall(b"235 ok\r\n")
        elif up.startswith("AUTH PLAIN"):
            if len(up.split()) == 2:
                conn.sendall(b"334 \r\n")
                line()
            conn.sendall(b"235 ok\r\n")
        elif up.startswith("MAIL FROM"):
            envelope["from"] = cmd.split(":", 1)[1].strip()
            conn.sendall(b"250 ok\r\n")
        elif up.startswith("RCPT TO"):
            envelope["to"].append(cmd.split(":", 1)[1].strip())
            conn.sendall(b"250 ok\r\n")
        elif up.startswith("DATA"):
            conn.sendall(b"354 go ahead\r\n")
            lines = []
            while True:
                one = line()
                if one is None or one == b".":
                    break
                lines.append(one)
            body = b"\r\n".join(lines)
            with counter["lock"]:
                counter["n"] += 1
                n = counter["n"]
            with open(os.path.join(outdir, f"msg-{n}.txt"), "wb") as fh:
                fh.write(f"ENVELOPE-FROM {envelope['from']}\n".encode())
                fh.write(f"ENVELOPE-TO {' '.join(envelope['to'])}\n".encode())
                fh.write(b"---\n")
                fh.write(body or b"")
            conn.sendall(b"250 queued\r\n")
        elif up.startswith("RSET"):
            envelope = {"from": "", "to": []}
            conn.sendall(b"250 ok\r\n")
        elif up.startswith("NOOP"):
            conn.sendall(b"250 ok\r\n")
        elif up.startswith("QUIT"):
            conn.sendall(b"221 bye\r\n")
            break
        else:
            conn.sendall(b"502 not implemented\r\n")
    conn.close()


def main():
    port = int(sys.argv[1])
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    counter = {"n": 0, "lock": threading.Lock()}
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(f"sink listening on {port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn, outdir, counter),
                         daemon=True).start()


if __name__ == "__main__":
    main()
