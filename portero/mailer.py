#!/usr/bin/env python3
"""Outbound mail for the mint half, through Amazon SES over SMTP.

The invite link is a bearer capability in a URL. It is passed to send_invite and
it is never returned, never put in an exception message, and never logged: a
failure is reported as a reason string that names the recipient and the SMTP
fault and nothing else.
"""

import os
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

HOST = os.environ.get("PORTERO_SMTP_HOST", "email-smtp.us-east-1.amazonaws.com")
PORT = int(os.environ.get("PORTERO_SMTP_PORT", "587"))
USER = os.environ.get("PORTERO_SMTP_USER", "")
SENDER = os.environ.get("PORTERO_SMTP_SENDER", "kelliher.info <auth@kelliher.info>")
STARTTLS = os.environ.get("PORTERO_SMTP_STARTTLS", "1") != "0"
TIMEOUT = float(os.environ.get("PORTERO_SMTP_TIMEOUT", "20"))
SUBJECT = os.environ.get("PORTERO_SMTP_SUBJECT", "Your kelliher.info invitation")

BODY = """Hello,

An account has been created for you on kelliher.info. Open this link to choose
your password:

  {url}

The link works once and stops working on {expires}. After you sign in you will
be asked to set up two-factor authentication; the iOS Passwords app or any
authenticator app will do.

Do not forward this message. Anyone holding the link can claim the account.

If you were not expecting this, ignore it and the invitation expires on its own.
"""


class MailFailed(Exception):
    """Carries a reason safe to log: no URL, no token, no password."""


def password():
    base = os.environ.get("CREDENTIALS_DIRECTORY")
    if not base:
        raise MailFailed("no CREDENTIALS_DIRECTORY")
    path = os.path.join(base, "smtp_password")
    if not os.path.exists(path):
        raise MailFailed("no smtp_password credential")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def configured():
    return bool(USER) and bool(HOST)


def _message(to, url, expires_at):
    msg = EmailMessage()
    msg["From"] = SENDER
    msg["To"] = to
    msg["Subject"] = SUBJECT
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="kelliher.info")
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(
        BODY.format(
            url=url,
            expires=time.strftime("%d %B %Y at %H:%M %Z", time.localtime(expires_at)),
        )
    )
    return msg


def send_invite(to, url, expires_at):
    if not configured():
        raise MailFailed("smtp is not configured on this unit")
    msg = _message(to, url, expires_at)
    try:
        with smtplib.SMTP(HOST, PORT, timeout=TIMEOUT) as smtp:
            smtp.ehlo()
            if STARTTLS:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            if USER:
                smtp.login(USER, password())
            smtp.send_message(msg)
    except MailFailed:
        raise
    except smtplib.SMTPException as exc:
        raise MailFailed(f"smtp refused mail to {to}: {type(exc).__name__}")
    except OSError as exc:
        raise MailFailed(f"smtp unreachable for {to}: {type(exc).__name__}")
