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
| state | the intake table, in its **own StateDirectory**; reads the spool | spent nonces only | appends to one append-only spool it has no read permission on |

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

## The spool, and writing where you cannot read

Intake exists because inviting 20 people one at a time by hand does not scale,
and because an unauthenticated endpoint that *decides* anything is a much worse
shape than one that records.

So the public unit records, into one file it can only append to. The first version of
this was a sqlite table shared with mint through a group, and two things were
wrong with it. The public half could read the table back, and only code review
said it did not. And sqlite's files were owned by whichever dynamic uid created
them, which `systemd.exec` names as the hazard of writing outside a
StateDirectory: "care must be taken so that UID/GID recycling does not create
security issues involving files created by the service." DynamicUser uids are
allocated per boot and reused, so a reboot could have handed an unrelated
service ownership of the queue.

| property | how, and who enforces it |
|---|---|
| cannot read back | the file's permissions. The spool is `root:portero-spool-reader`, owning group `r--`, which only mint holds, and an ACL entry gives `portero-intake` `-w-` and nothing more. Measured inside the real intake unit: `open(O_RDONLY)` is **EACCES** |
| cannot truncate or overwrite | `chattr +a` from a tmpfiles `h` line. Inside the real unit: a write open without `O_APPEND` is **EPERM**, `ftruncate` is **EPERM**, and `pwrite` at offset zero appends instead of overwriting |
| no ownership drift | the file is pre-created root-owned by tmpfiles, and neither service may create, rename or unlink it. `ReadWritePaths` names the **file**, so the public half cannot make or destroy anything in that directory |
| the table is safe across a reboot | it lives in mint's own StateDirectory, which systemd re-chowns recursively at every start. That is the documented protection, applied rather than reimplemented |
| one response | accepted, duplicate, malformed, flooded and full render the same bytes with the same status after the same floor |
| never auto-sends | the unit holds no mail credential and does not import the mailer. The packaging check refuses a build where it does |
| bounded | the writer refuses past `intakeSpoolMax` by calling `fstat` on **its own descriptor**, which is a size and not a read, so the cap needs no read permission |
| no address in a log | the journal records that an offer was written or dropped, never what was in it |

### The claim that was false, and why it looked tested

The first version of this section said the public half could not read the
spool and that the kernel enforced it, citing `EBADF` from intake's
`O_WRONLY|O_APPEND` descriptor. El Inspector showed otherwise in a VM on
spain's pin: intake's group owned a `0660` file, so the process could open a
**second** descriptor and read every record, `ftruncate` the file to nothing,
and `pwrite` over the first record.

`EBADF` proved that one **descriptor** could not read. Whether the **process**
can read is a question about its permissions on the file, and no check asked
it: the probe tried creating and renaming files beside the spool, which the
read-only directory blocks, and never a second `open`. A check that answers a
narrower question than the claim it is cited for is the failure, and it is now
covered by `checks.sandbox`, which first restores the old layout and requires
the probe to succeed in reading before it is trusted to report a refusal.

### Why nothing truncates the spool

The consumer reads to a byte offset stored beside its own table and never writes
to the spool at all. A truncate from the consumer would destroy any record
appended between the read and the truncate, and that is a lost signup the
submitter cannot detect, because he received the same indistinguishable 202 as
everyone else. Losing a signup is worse than the ownership drift this design
exists to fix.

Every automated rotation considered had the same defect in a different place: a
rename orphans the writer's `O_APPEND` descriptor, which keeps appending to an
unlinked inode, and the rows vanish. So there is no rotation. The cap is 1 MiB,
which a caller forcing 2157-byte records fills with 486 submissions, about four
minutes at the flood ceiling. `GET /intake` reports `spool_bytes` against
`spool_max`, and reclaiming it is `systemctl start gluck-portero-intake-reset`
as root: one run that stops both units, empties the spool, removes mint's offset
and starts both again. Emptying the spool without removing the offset is the
half-reset this unit exists to prevent, because mint would skip whatever is
appended until the file grew past the old offset.

### A full table is a queue

The table's cap of 200 pending rows is enforced by a trigger, and ingestion
**stops** at the first record it refuses, leaving the offset on that record. The
signup waits in the spool and lands, in order, when the operator frees a slot.
The first version swallowed that refusal together with duplicates and advanced
past it, which consumed and lost a real signup that nobody could see go; a test
that expected the next submission to land after a reject was passing only
because the one before it had been lost.

Ingestion is **at-least-once**, and the table's `UNIQUE(email)` makes it
exactly-once: a crash between the INSERT and the offset write re-reads the
records and the duplicates are refused by the constraint. The same move as
letting lldap's own constraint arbitrate a duplicate address: the database holds
the invariant and the code stops trying to.

Only data up to the last complete newline is consumed, so a torn append waits
for its remainder instead of being half-parsed. A single small append to a
regular file will not tear in practice, and "in practice" is not a guarantee
worth taking under a public endpoint.

### The cap must be indistinguishable too

Refusing a full spool is an `fstat` and no write, which is a strictly **cheaper**
path than an accepted append. So byte-equality is not enough: the response floor
is measured in the tests rather than trusted because it appears in the source.
Accepted, duplicate, malformed, flooded and full are identical in bytes and none
is measurably faster.

### The decision MAC, and the boundary it used to cross

When mint read a table the public unit could write, the naive version was an
escalation: write a row with `state = approved`, `username = admin` and an
attacker's address, then wait for an operator to click send. A decided row
therefore carries an HMAC over `(id, email, username, nonce, expires_at)` under
the invite signing key, verified by `POST /intake/<id>/send` before anything is
mailed.

**That boundary no longer exists.** The table is mint's alone and the public half
cannot open it. The MAC is kept because it costs nothing and still catches
corruption of mint's own state, and because a future author who re-shares the
table would otherwise reintroduce the hole silently. It is no longer a defence
against the public unit, and this file should not claim it is.

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
| the spool filled with junk | `intakeSpoolMax`, one response so the attacker learns nothing, `spool_bytes` visible to the operator | real signups are declined silently once it is full, about four minutes of sustained abuse at the flood ceiling, and recovery needs root. Worse than the old table, which the operator could clear through the API. Spool fullness is not yet alerted on anywhere |
| the spool is appendable by a public unit | write-only through an ACL entry, append-only through `chattr +a`, the directory is not writable, and the table is unreachable from that unit | a holder can add noise to the operator's queue, including a partial line that spoils the next record. It cannot read, truncate, overwrite or remove the queue, cannot decide anything, and cannot cause a link to be mailed |
| SES SMTP credential disclosure | sops, `LoadCredential` as a file, held by the authenticated half only | holder can send mail as `auth@kelliher.info`. Rotate in SES. It grants nothing in the directory |
| guest reaches other hostnames | **not solved here.** Requires zero-by-default | this is the gating dependency. No invite is minted before `site-files-access` exists |

The last row is the important one. This service is safe to deploy with no invites
outstanding, and it must not mint one until the access gate exists.

## State outside the closure, and what a rollback does not undo

A Nix rollback restores configuration, not data. Three things here live outside
it, and each needs its revocation written down rather than assumed:

| artifact | what a rollback does | the revocation |
|---|---|---|
| `/var/lib/gluck-portero-intake/spool.jsonl` | nothing. The addresses appended to it survive | `systemctl start gluck-portero-intake-reset`. tmpfiles recreates it root-owned if removed |
| the spool's ACL entry and `chattr +a` | the previous release's tmpfiles rules reset owner, group and mode, but no rule removes an ACL or `+a`, so both stay. Signups keep flowing: measured in `checks.sandbox`, old mint reads and old intake appends. Only the old reset fails, safely, because `+a` refuses its truncate | the block below, run as root |
| mint's `intake.db`, in its StateDirectory | nothing. Rows and decisions survive | `rm` it with mint stopped. The offset file beside it must go in the same breath |
| a spent nonce | nothing. The INSERT already happened, so a redeemed link stays dead | none needed, and none wanted |
| an account created by an approval, with its group | nothing. The user and the grant remain | `DELETE /invites/<username>` on the mint half, which deletes the account |

The revocation for the spool's attributes after a rollback, copied verbatim
from the command `checks.sandbox` runs:

```sh
systemctl stop gluck-portero-intake.service gluck-portero-mint.service && chattr -a /var/lib/gluck-portero-intake/spool.jsonl && setfacl -b /var/lib/gluck-portero-intake/spool.jsonl && chmod 0660 /var/lib/gluck-portero-intake/spool.jsonl && systemctl start gluck-portero-mint.service gluck-portero-intake.service
```

The `chmod` is not optional. `setfacl -b` keeps the base group entry, `r--`,
so without it the mode falls to `0640` and the old intake loses its only write
grant. The rig runs the block without it first and measures `EACCES`.

So rolling spain back past this change removes the intake endpoint while leaving
its table on disk. That is the harmless direction. The direction that matters is
the account: an approval is a one-way door until somebody deletes the user.
