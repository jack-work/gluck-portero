---
name: THREAT-MODEL
description: Why a public unauthenticated endpoint that touches the directory is acceptable here, what it can and cannot do, and the two operational traps that arrive with the first guest account. Read before changing any route, credential or group in gluck-portero.
---

# Threat model

This service exists because Authelia has no self-registration, lldap has no
invite system, and Authelia's notifier writes to a file on spain so no
email-driven flow works for a real second human.

It contains **the most dangerous shape on this estate**: a public,
unauthenticated endpoint that can change the directory. Everything below is
about keeping that shape small.

## The one-sentence claim

The public endpoint can set a password on an account that already exists, has no
password, and was named in a token this estate signed. It can do nothing else.

## Why there is no temporary password

`createUser` in lldap succeeds with **no password field**, and the resulting
account returns 401 for an empty password and for a guessed one. Verified
against a real lldap on a scratch instance.

So mint creates an account that is **real and unusable**. There is no temporary
credential at any point, which removes an entire class of failure: nothing for an
agent to see, nothing to put in an email, nothing to leak into a transcript,
nothing to expire. The invitee's own POST is the first and only password the
account ever has.

This is stronger than "zero permissions by default". It is **zero credential by
default**, and it makes the ordering a property rather than a rule someone keeps.

## The split, and why it is two processes

| | mint | redeem |
|---|---|---|
| hostname | `portero.<domain>` | `invite.<domain>` |
| auth | Authelia, plus `portero-admin` checked against `Remote-Groups` | **none.** The token is the only authorization |
| directory identity | `lldap_admin` | **`lldap_password_manager` only** |
| can create a user | yes | **no** |
| can change a group | yes, allowlist only | **no** |
| state | none | spent nonces only |

**Two units, not one process serving two hostnames.** If a single process
registered both route sets, the only thing between the public internet and user
creation would be a `Host` header. That is authorization by routing, and it is
the same class as the September 5 bearer bypass, where a security property
depended on something upstream behaving and it did not. Two units means the
public process has no mint route to reach.

A Nix assertion refuses a configuration where the two halves share a credential
file, because that is the mistake that would quietly undo the split.

## Mint holds no invite state

The token carries its own claim and its own HMAC signature. Mint signs, redeem
verifies, and neither reads the other's storage.

| consequence | |
|---|---|
| no shared writable state | the public half cannot read or corrupt a private database |
| mint is stateless | a mint compromise yields no history of outstanding invites |
| revocation | **delete the account.** A token naming a user that does not exist cannot be redeemed, because setting its password fails |
| key rotation | invalidates every outstanding invite at once, which is the intended blast radius |

## What the token is, and what it is not

```
base64url(json{u,e,n}) . base64url(hmac_sha256(key, payload))
```

- 32 bytes of OS entropy in the nonce, so guessing is not a threat.
- The signature is checked **before** the payload is parsed, so a forged payload
  is never interpreted. A payload naming `admin` with a bad signature does not
  reach the JSON parser.
- Expiry is inside the signed claim, so it cannot be extended by editing the URL.
- Single use is enforced by a **primary key**, not by a read-then-write.

It **is** a bearer capability in a URL until it expires or is used. URLs leak
through `Referer`, browser history and access logs. So: `Referrer-Policy:
no-referrer` on every response, the token never written to a log, and a short
default lifetime.

## The oracle problem

Invalid, expired and already-used tokens return **one** response: the same
status, the same bytes, and no username anywhere in it. Otherwise the endpoint
tells an anonymous caller which accounts exist.

Timing is part of that response. A constant-time signature compare is undone by
an early return that reveals whether the token was well-formed, so every
response is held to a fixed floor before it is sent.

Tested, including the case where all three refusal paths are compared
byte-for-byte.

## Ordering inside a redemption

The nonce is spent **before** the password is set. If setting the password then
fails, the link is burnt and a new invite is needed.

The other order leaves a window in which one link sets a password twice. Burning
a link on a server error is the cheaper failure: the remedy is one more invite.

A **typo** does not burn the link. Short passwords and mismatched confirmations
are rejected before the nonce is touched.

## Two traps that arrive with the first guest

### Authelia caches groups in the session

Sessions live in valkey and survive restarts, deliberately, since 2026-09-11.
Authelia refreshes profiles on an interval, normally five minutes, and keeps the
old details if an LDAP refresh fails. **Granting a group does not immediately
reach a live session, and restarting Authelia no longer clears it.**

So the estate's own logout fix created a trap for group changes. The remedy here
is ordering: **grant site access at mint time**, which is safe precisely because
the account has no credential yet. The invitee's first session is then created
*after* the grant and is born holding the group.

If a guest's first click 403s and then works a few minutes later, this is the
cause and not this service.

### Rolling spain back is a security rollback once a guest exists

Until zero-by-default lands, one unrestricted Authelia rule covers every gated
hostname. After it lands, rolling back to an earlier generation **restores that
rule** and hands every existing account all gated hostnames.

So once a guest account exists, magic rollback is no longer a free safety net for
anyone deploying spain.

**Before any rollback past the enforcement change, delete or disable the guest.**
`DELETE /invites/<username>` on the mint half is that tool. The next person to
hit a bad deploy will reach for rollback without knowing it reopens nine doors,
which is why it is written here and in the deploy notes rather than remembered.

## What this service deliberately does not do

| | why |
|---|---|
| send email | Authelia's notifier writes to a file on spain. The operator sends the link himself, so no mail credential exists to steal. |
| set up 2FA | Authelia owns TOTP secrets. Enrolment needs an elevated session and a one-time code from the notifier, which is a file on spain. Until SMTP exists, that code is relayed by hand by the operator. A one-time code is not a password. |
| grant capability groups | `grantableGroups` is an allowlist of site-access groups. This half holds `lldap_admin`, so without an allowlist a request could ask for `lldap_admin`. Capability groups belong to the app that defines them. |
| reset a password | there is no authenticated user model here, and a reset endpoint on a public hostname is a different threat model. With no SMTP there is no self-service reset at all; that is recorded debt. |

## Residual risk, stated plainly

| risk | mitigation | residual |
|---|---|---|
| signing key disclosure | sops, `LoadCredential`, per-unit tmpfs at 0400, never argv, never a unit literal, never the Nix store | holder can mint tokens for accounts that already exist with no password. Cannot create accounts. Rotate the key to invalidate everything |
| `lldap_password_manager` credential disclosure | same delivery | holder can change passwords of directory users. Serious, and the reason this is not `lldap_admin` |
| invite link forwarded or intercepted | single use, short expiry, no-referrer, never logged | whoever opens it first sets the password. The operator must send it over a channel he trusts |
| denial of service on the public endpoint | whole-endpoint rate budget, `MemoryMax`, `CPUQuota` | a flood costs a few hundred refusals per minute. Per-IP limits were rejected as evadable by rotation |
| guest reaches other hostnames | **not solved here.** Requires zero-by-default | this is the gating dependency. No invite is minted before `site-share-access` exists |

The last row is the important one. This service is safe to deploy with no invites
outstanding, and it must not mint one until the access gate exists.
