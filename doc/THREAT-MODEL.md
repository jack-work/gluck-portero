---
name: THREAT-MODEL
description: Why a public unauthenticated endpoint that touches the directory is acceptable here, what it can and cannot do, and the two operational traps that arrive with the first guest account. Read before changing any route, credential or group in gluck-portero.
---

# Threat model

This service exists because Authelia has no self-registration and lldap has no
invite system. It predates SES on this estate, which is why the operator carried
links by hand at first; mail arrived on 2026-10-07 and the shape did not change,
because who may decide was never a mail problem.

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

| | mint | redeem | intake |
|---|---|---|---|
| hostname | `portero.<domain>` | `invite.<domain>` | `invite.<domain>/intake` |
| auth | Authelia, plus `portero-admin` checked against `Remote-Groups` | **none.** The token is the only authorization | **none** |
| credentials held | invite key, `lldap_admin`, SES SMTP password | invite key, `lldap_password_manager` | **none at all** |
| directory identity | `lldap_admin` | **`lldap_password_manager` only** | **none.** It cannot reach lldap |
| can create a user | yes | **no** | **no** |
| can change a group | yes, allowlist only | **no** | **no** |
| can send mail | yes | **no** | **no** |
| state | the intake table, read and write | spent nonces only | the intake table, **INSERT only** |

The intake unit is the only process here that starts with no credentials
directory. It is checked rather than asserted: the packaging check imports its
entrypoint with `CREDENTIALS_DIRECTORY` unset, and the pipeline test runs the
real unit the same way. mint and redeem both refuse to start under that
condition.

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

## The rate limit, and what a mail scanner does to it

The first version was one whole-endpoint budget: 20 requests per 60 seconds,
counting every method. The reasoning was that per-IP limits are evaded by
rotation and this endpoint sees a handful of requests in its life.

Both halves of that were wrong in the same direction. A link mailed to a real
person is fetched by whatever scans his mail before he ever clicks it, and those
fetches are GETs on the one URL that matters. Twenty of them, from one scanner
or from a preview pane that retries, closed the endpoint for a minute including
the invitee's POST. With 20 users the arrival of invites is correlated, so the
denial is most likely exactly when it hurts.

| budget | key | default | spent by |
|---|---|---|---|
| flood ceiling, GET | whole endpoint | 600 / 60s | every GET, valid or not |
| flood ceiling, POST | whole endpoint | 120 / 60s | every POST, valid or not |
| per invite, GET | the nonce | 60 / 300s | a signature-valid GET |
| per invite, POST | the nonce | 10 / 300s | a signature-valid POST |

Three properties hold it together.

**A GET costs nothing but a page.** It verifies a signature, checks the spent
table and renders a form. It does not touch the directory and it does not spend
the nonce, so a flood of them cannot consume an invite. Only the POST does.

**A per-invite key is only created for a token this estate signed.** Keying a
budget on attacker-supplied input is an allocation primitive, so the signature
check comes first and an invalid token is charged to the flood ceiling alone.
The per-key store is bounded by `max_keys` with least-recently-used eviction on
top of that.

**The flood ceiling is still unevadable.** It is global and not per-IP, so
rotating addresses buys nothing. It is now large enough that honest traffic
cannot reach it: a scanner on one link spends 1 of 600.

The metric for this must be stated carefully. "Fewer 429s" is a number that can
improve for bad reasons. The property tested is the one that matters: after 300
GETs on a link, the POST that redeems it still returns 200 and the account can
log in afterwards.

## The intake table, and writing where you cannot read

Intake exists because inviting 20 people one at a time by hand does not scale,
and because an unauthenticated endpoint that *decides* anything is a much worse
shape than one that records.

So the public unit records. One route, one INSERT, no statement in its module
that reads a row back, and no route that returns stored data. Deciding happens
on the authenticated half.

| property | how |
|---|---|
| one response | accepted, duplicate, malformed, flooded and full all render the same bytes with the same status after the same floor |
| never auto-sends | the unit holds no mail credential and does not import the mailer. The packaging check refuses a build where it does |
| bounded | a sqlite trigger refuses an INSERT past `intakeCap` pending rows, so the cap holds for a caller that ignores exceptions |
| no enumeration | there is no read path to enumerate with. A duplicate is swallowed, so the endpoint is not an oracle for which addresses are already known |
| no address in a log | the journal records that an offer was written or dropped, never what was in it |

The cap is a denial-of-service trade, stated plainly: an attacker can fill 200
pending rows with junk and real requests are then dropped silently. The
alternative, dropping the cap, is an attacker filling the disk of the machine
that routes the house. The mint listing reports `pending_capacity` and the
counts beside it so a full table is visible to the operator, and rejecting junk
frees the slots.

### The trust boundary the table crosses

mint reads a table the public unit can write. That is a new edge, and the naive
version of it is an escalation: write a row with `state = approved`, `username =
admin` and an attacker's address, then wait for an operator to click send.

So a decided row carries an HMAC over `(id, email, username, nonce,
expires_at)` under the invite signing key, which only the authenticated halves
hold. `POST /intake/<id>/send` verifies it before mailing anything and refuses a
row that fails, whether it was edited or forged whole.

The row stores the **nonce**, not the token. mint re-signs the nonce to rebuild
the one live link, so a resend cannot create a second valid link for one
account, and the stored material is useless to anyone who does not hold the
signing key.

## Mail, now that SES exists

Production SES access was granted on 2026-10-07, so the earlier "this service
deliberately does not send email" is no longer true. What replaces it:

| | |
|---|---|
| who can send | the **mint** half only, which is behind Authelia and `portero-admin` |
| the credential | the SES SMTP password, `LoadCredential` as a file, read per send, never in argv, never in a unit, never logged |
| what reaches a log | the recipient address and the username. Never the link, never the token, never the password |
| a failure | reported as the exception class and the recipient, because an SMTP error string is not a safe place to assume nothing echoed back |
| send by id | `POST /intake/<id>/send` puts the id in the request line, not the token, so no proxy access log can hold a live credential even if URI redaction is removed later |

The last row is the one to keep. Caddy logged 13 live invite tokens out of
`request>uri` before URI redaction landed, because a path segment is a secret
that no proxy can recognise. An API whose identifiers are row ids cannot leak
that way.

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
| send mail from a public unit | only the authenticated half holds the SMTP credential, and it sends on an explicit decision. Nothing an anonymous caller does can cause an email. |
| set up 2FA | Authelia owns TOTP secrets. Enrolment needs an elevated session and a one-time code from the notifier, which is a file on spain. Until SMTP exists, that code is relayed by hand by the operator. A one-time code is not a password. |
| grant capability groups | `grantableGroups` is an allowlist of site-access groups. This half holds `lldap_admin`, so without an allowlist a request could ask for `lldap_admin`. Capability groups belong to the app that defines them. |
| reset a password | there is no authenticated user model here, and a reset endpoint on a public hostname is a different threat model. Authelia owns reset now that SES exists; this service must not grow a second path to a password. |

## Residual risk, stated plainly

| risk | mitigation | residual |
|---|---|---|
| signing key disclosure | sops, `LoadCredential`, per-unit tmpfs at 0400, never argv, never a unit literal, never the Nix store | holder can mint tokens for accounts that already exist with no password. Cannot create accounts. Rotate the key to invalidate everything |
| `lldap_password_manager` credential disclosure | same delivery | holder can change passwords of directory users. Serious, and the reason this is not `lldap_admin` |
| invite link forwarded or intercepted | single use, short expiry, no-referrer, never logged | whoever opens it first sets the password. The operator must send it over a channel he trusts |
| denial of service on the public endpoints | global flood ceilings per method, a per-invite budget, `MemoryMax`, `CPUQuota` | a flood costs refusals. It can no longer consume a real invitee's attempt, because a GET spends neither the POST budget nor the nonce |
| intake filled with junk | `intakeCap`, one response so the attacker learns nothing, counts visible to the operator | real signups are dropped silently while the table is full. Rejecting junk frees the slots |
| the intake table is writable by a public unit | decision MAC over the fields that decide where a link goes, verified before any send | a holder can add noise to the operator's queue and nothing else. It cannot cause a link to be mailed anywhere |
| SES SMTP credential disclosure | sops, `LoadCredential` as a file, held by the authenticated half only | holder can send mail as `auth@kelliher.info`. Rotate in SES. It grants nothing in the directory |
| guest reaches other hostnames | **not solved here.** Requires zero-by-default | this is the gating dependency. No invite is minted before `site-files-access` exists |

The last row is the important one. This service is safe to deploy with no invites
outstanding, and it must not mint one until the access gate exists.

## State outside the closure, and what a rollback does not undo

A Nix rollback restores configuration, not data. Three things here live outside
it, and each needs its revocation written down rather than assumed:

| artifact | what a rollback does | the revocation |
|---|---|---|
| `/var/lib/gluck-portero-intake/intake.db` | nothing. The rows and the addresses in them survive | `rm -rf /var/lib/gluck-portero-intake`. The unit recreates an empty table |
| a spent nonce | nothing. The INSERT already happened, so a redeemed link stays dead | none needed, and none wanted |
| an account created by an approval, with its group | nothing. The user and the grant remain | `DELETE /invites/<username>` on the mint half, which deletes the account |

So rolling spain back past this change removes the intake endpoint while leaving
its table on disk. That is the harmless direction. The direction that matters is
the account: an approval is a one-way door until somebody deletes the user.
