# gluck-portero

Invite links for guest accounts on spain. The doorkeeper: it lets someone in
without ever holding their key.

Three halves, deliberately three processes:

| | |
|---|---|
| `portero.kelliher.info` | **Mint.** Behind Authelia, needs `portero-admin`. Creates the account, returns one link, and mails it through SES. |
| `invite.kelliher.info` | **Redeem.** Public, unauthenticated. The invitee chooses his own password. |
| `invite.kelliher.info/intake` | **Intake.** Public, unauthenticated, holds no credential at all, and appends an address to a spool it **cannot read, truncate or overwrite**: its group has write and nothing else through an ACL entry, and the file is `chattr +a`. |

Read [`doc/THREAT-MODEL.md`](./doc/THREAT-MODEL.md) before changing any route,
credential or group. It contains the only public unauthenticated endpoint on this
estate that touches the directory.

## The property that makes it safe

`createUser` in lldap succeeds with **no password**, and such an account rejects
every login. So mint creates an account that is real and unusable.

**There is no temporary password anywhere in this system.** Nothing for an agent
to see, nothing to put in an email, nothing to leak into a transcript, nothing to
expire. The invitee's own POST is the first password the account ever has.

That is zero *credential* by default, which is stronger than zero permissions by
default, and it makes the ordering a property rather than a rule someone keeps.

## Using it

Mint an invite. Send the link yourself.

```bash
curl -sS https://portero.kelliher.info/invites \
  -H 'Content-Type: application/json' \
  -d '{"username":"dad","email":"dad@example.com",
       "site_access_groups":["site-files-access"],"ttl_seconds":259200}'
```

The response carries the URL once. It is not stored and cannot be re-read.

Three ways in, all to the same JSON endpoints on the gated hostname:

| way | identity |
|---|---|
| the `portero` CLI | an OIDC access token from Authelia's `portero-cli` client, held by hush |
| the dashboard, `https://portero.kelliher.info/admin` | an Authelia browser session |
| `curl` with a session | the same; every session POST must be `application/json` |

mint takes identity from the token whenever an `Authorization` header is
present and from Remote-* otherwise, never both. A token is honoured only for
the `portero-cli` client, and its groups are read from Authelia's userinfo per
request (cached 60 s), so removing someone from `portero-admin` takes effect
within a minute even though Authelia does not re-check a refresh. Any failure
is a refusal: 401 for a bad token, 503 when Authelia cannot be asked. The
Caddy side is kelliher-web's `trustsRemoteHeadersOrBearer` site mode.

```bash
nix profile install github:jack-work/gluck-portero#portero
portero login                 # device flow; hush keeps and refreshes the token
portero intake                # pending signups; --all for every state, --json for JSON
```

## Inviting at scale: the intake pipeline

Someone asks for an account at `invite.kelliher.info/intake`. Nothing is sent,
nothing is created, and the page says the same thing whatever happened.

```bash
portero intake                                             # list pending
portero approve 7 dad --sites site-files-access --name Dad  # account + invite mail
portero send 7                                             # mail it again
portero reject 7                                           # or refuse
portero retire 7                                           # close a row whose account is gone
```

Deleting an account is the dashboard's "Delete account", or
`DELETE /invites/<username>`.

`retire` closes an approved row whose account is gone and clears its link
material, so nothing can mail from it again. It refuses while the account
exists: revocation is `DELETE /invites/<username>`, never a row edit.

`approve` creates the credential-less account, grants site access, mints one
link and mails it. `send` mails **the same link again**, rebuilt by re-signing
the stored nonce, so a resend never creates a second live link for one account.

The identifier in every one of those URLs is a row id. The token appears in no
request line, so no proxy access log can hold a live credential, which is the
failure that put 13 invite tokens into journald before URI redaction landed.

Revoke by deleting the account. A token naming a user that does not exist cannot
be redeemed.

```bash
curl -sS -X DELETE https://portero.kelliher.info/invites/dad
```

Grant site access with `site_access_groups` at mint time, not afterwards. Why:
session, refreshes profiles on a five minute interval, and sessions survive
restarts because they live in valkey. So granting a group **after** someone has a
session may not reach them until the next refresh.

Granting at mint time is safe because the account has no credential yet, and the
invitee's first session is created after the grant, so it is born holding the
group.

If a guest's first click 403s and then works a few minutes later, that is this,
not a bug here.

## What the invitee sees

1. Opens the link. One page, one form: choose a password, twice.
2. Sets it. The link stops working.
3. Signs in at `auth.kelliher.info` and is asked to enrol 2FA.

Step 3 no longer needs the operator for mail: SES production access was granted
on 2026-10-07, so Authelia's notifier reaches the invitee directly. Enrolment is
TOTP in the iOS Passwords app for a non-technical user.

## Two things that will bite

**Do not mint an invite before `site-files-access` exists.** Until
zero-permissions-by-default lands, one unrestricted Authelia rule covers every
gated hostname, so a new account reaches all of them. The service is safe to
deploy with no invites outstanding; it is the first *invite* that is gated on
that work, not the deploy.

**Once a guest exists, rolling spain back is a security rollback.** It restores
the unrestricted rule and hands that account every gated hostname. Delete the
guest before any rollback past the enforcement change.

## Ports and state

| | |
|---|---|
| mint | `127.0.0.1:9101`, reads and writes the intake table |
| redeem | `127.0.0.1:9102`, one sqlite table of spent nonces |
| intake | `127.0.0.1:9103`, one append to the spool and nothing else |

The queue is two files in two places, deliberately. The **spool** lives at
`/var/lib/gluck-portero-intake/spool.jsonl`, created and held root-owned by the
`gluck-portero-spool-layout` oneshot
and reachable through the `portero-intake` group; the public half can append to
that file and can neither read it nor create, rename or unlink anything beside
it. The **table** lives in mint's own StateDirectory, which systemd re-chowns at
every start, so a reboot that reassigns dynamic uids cannot leave it owned by a
stranger.

Nothing truncates the spool. mint consumes it by byte offset, because a truncate
from the consumer would destroy any record appended between the read and the
truncate, and that is a lost signup the submitter cannot detect.

Two caps, and they fail differently:

| cap | when it is hit | recovery |
|---|---|---|
| 200 pending rows in mint's table | ingestion **stops at the refused record** and leaves it in the spool, so it lands in order once a row is approved or rejected | the operator, through the authenticated API |
| 1 MiB of spool | intake declines every submission, with the same bytes and timing as an accepted one | root: `systemctl start gluck-portero-intake-reset` |

A caller can force 2157-byte records, so 486 hostile submissions fill the
spool, about four minutes at intake's flood ceiling. `GET /intake` reports
`spool_bytes` against `spool_max`; nothing else on the estate shows it yet.

The reset unit stops both units, empties the spool, removes mint's offset and
starts both again, from a trap so they come back even if the reset fails. Do not
empty the spool by hand: without the offset removed in the same run, mint skips
whatever is appended until the file grows past the old offset.

The group is **not** named after the unit: systemd allocates a `DynamicUser`
named after the unit and refuses to start if a static user or group already
holds that name, which is a `217/USER` exit with "User or group with specified
name already exists".

Both files are **state outside the closure**: a rollback removes neither, and the
revocations are in `doc/THREAT-MODEL.md`.

All three loopback; only Caddy reaches them. Intake is served under `/intake` on
the redeem hostname rather than a name of its own, so there is no DNS record to
add and no new public hostname to gate. Both carry `MemoryMax` and `CPUQuota`,
because spain is the house router on a single unbacked NVMe.

## Secrets

Three files, all sops, all delivered by `LoadCredential` into a per-unit tmpfs at
mode 0400. Never argv, never `Environment=`, never the Nix store.

| credential | held by | must be |
|---|---|---|
| `inviteKeyFile` | mint and redeem | at least 32 bytes. Rotating it invalidates every outstanding invite |
| `adminPasswordFile` | mint | an `lldap_admin` |
| `redeemPasswordFile` | redeem | `lldap_password_manager` and **not** `lldap_admin` |
| `smtpPasswordFile` | mint | the SES SMTP password. Optional: null means no invite mail is sent |

The intake unit appears in no row of that table. It is given no credentials
directory, and the packaging check proves its entrypoint imports with none.

Generate the signing key without it ever reaching a terminal:

```bash
head -c 48 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' \
  | sops --set '["portero-invite-key"] ...'   # or: sops edit and paste
```

A Nix assertion refuses a configuration where mint and redeem share a credential
file, because that is the mistake that quietly undoes the split.

## Tests

`nix flake check` runs eight suites, three whole-system tests, the reset and
packaging checks: 13 checks. `sandbox` is a VM test and needs KVM.

| suite | what it pins |
|---|---|
| `invites` | a token we did not sign is never interpreted; tampering, signature swaps, expiry, unsigned payloads; re-signing a nonce rebuilds exactly one token |
| `spent` | single use comes from a primary key, not a read-then-write |
| `budget` | a key spends only its own allowance; the window slides; memory is bounded when the key space is not |
| `spool` | the writer opens append-only; an append landing between a read and the offset advance is not lost; a torn line is neither dropped nor half-parsed; every outcome is reported |
| `pending` | the cap is a schema trigger, not application politeness; approval has one winner; ingestion is exactly-once through `UNIQUE(email)` |
| `redeem` | invalid, expired and used are byte-identical; the link works once; a typo does not burn it; a GET flood spends neither the POST budget nor the nonce; the token never reaches a log |
| `mint` | `lldap_admin` cannot be granted; a caller without the group gets 403; a GraphQL error carrying HTTP 200 is not success; a rewritten intake row is never mailed |
| `intake` | accepted, duplicate, malformed, flooded and full render identical bytes **and none is measurably faster**; no route returns a row; the address reaches no log |
| `integration` | the original loop against a real lldap: zero credential, single use |
| `pipeline` | intake to mail to redemption against a real lldap **and a real SMTP server**, with the intake unit started with no credentials directory |
| `reset` | the shipped reset script's order: stop, lift append-only, truncate, restore it, remove the offset, start; on failure, restore it before the units return, and if it cannot be restored only mint returns; its last line is the netmon contract |
| `sandbox` | a NixOS VM importing this module. Restores spain's old layout and requires the probe to read the spool; migrates the way activation does; probes **inside the real intake and mint units**; runs the real reset with the real `chattr`; drives a signup to mint; emulates a rollback and runs the revocation from the threat model; rolls forward; reboots and probes again |
| `packaging` | all three entrypoints import out of the derivation the units execute, the shipped intake opens its spool append-only, and neither public half imports the mailer or sqlite |

`./negative-controls.sh` is the suite that tests the tests: it breaks nine
properties one at a time and requires the named check to fail. One case is the
divergence that matters, dropping a module from the shipped tree, where
`packaging` must fail **while the unit suites stay green**.

Every security property has a **negative control**: the check is broken
deliberately and the suite must fail. Two of those controls found real problems.
One test of atomicity passed against a deliberately broken read-then-write
implementation, because threads under the GIL would not interleave; it was
replaced with a deterministic version that makes the read lie.
