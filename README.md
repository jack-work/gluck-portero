# gluck-portero

Invite links for guest accounts on spain. The doorkeeper: it lets someone in
without ever holding their key.

Three halves, deliberately three processes:

| | |
|---|---|
| `portero.kelliher.info` | **Mint.** Behind Authelia, needs `portero-admin`. Creates the account, returns one link, and mails it through SES. |
| `invite.kelliher.info` | **Redeem.** Public, unauthenticated. The invitee chooses his own password. |
| `invite.kelliher.info/intake` | **Intake.** Public, unauthenticated, and holds no credential at all. It writes an address into a capped table it cannot read back. |

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

There is **no CLI yet**. This is a browser-session or `curl` interface, and the
gated hostname means a session is required either way.

## Inviting at scale: the intake pipeline

Someone asks for an account at `invite.kelliher.info/intake`. Nothing is sent,
nothing is created, and the page says the same thing whatever happened.

```bash
# what the operator does, on the gated hostname
curl -sS https://portero.kelliher.info/intake                     # list pending
curl -sS -X POST https://portero.kelliher.info/intake/7/approve \
  -H 'Content-Type: application/json' \
  -d '{"username":"dad","site_access_groups":["site-files-access"]}'
curl -sS -X POST https://portero.kelliher.info/intake/7/send      # mail it again
curl -sS -X POST https://portero.kelliher.info/intake/7/reject    # or refuse
```

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
| intake | `127.0.0.1:9103`, INSERT into the intake table and nothing else |

The intake table lives in `/var/lib/gluck-portero-intake`, shared through the
`portero-intake` group and nothing else. The group is **not** named after the
unit: systemd allocates a `DynamicUser` named after the unit and refuses to
start if a static user or group already holds that name, which is a `217/USER`
exit with "User or group with specified name already exists".

The directory is **state outside the closure**: a rollback does not remove it,
and the revocation is one `rm -rf /var/lib/gluck-portero-intake`.

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

`nix flake check` runs seven suites, two whole-system tests and a packaging
check: 11 checks, 100 cases.

| suite | what it pins |
|---|---|
| `invites` | a token we did not sign is never interpreted; tampering, signature swaps, expiry, unsigned payloads; re-signing a nonce rebuilds exactly one token |
| `spent` | single use comes from a primary key, not a read-then-write |
| `budget` | a key spends only its own allowance; the window slides; memory is bounded when the key space is not |
| `pending` | the cap is a schema trigger, not application politeness; approval has one winner; a row edited behind mint's back fails its MAC |
| `redeem` | invalid, expired and used are byte-identical; the link works once; a typo does not burn it; a GET flood spends neither the POST budget nor the nonce; the token never reaches a log |
| `mint` | `lldap_admin` cannot be granted; a caller without the group gets 403; a GraphQL error carrying HTTP 200 is not success; a rewritten intake row is never mailed |
| `intake` | accepted, duplicate, malformed, flooded and full render identical bytes; no route returns a row; the address reaches no log |
| `integration` | the original loop against a real lldap: zero credential, single use |
| `pipeline` | intake to mail to redemption against a real lldap **and a real SMTP server**, with the intake unit started with no credentials directory |
| `packaging` | both entrypoints import out of the derivation the units execute, and neither public half imports the mailer |

`./negative-controls.sh` is the suite that tests the tests: it breaks nine
properties one at a time and requires the named check to fail. One case is the
divergence that matters, dropping a module from the shipped tree, where
`packaging` must fail **while the unit suites stay green**.

Every security property has a **negative control**: the check is broken
deliberately and the suite must fail. Two of those controls found real problems.
One test of atomicity passed against a deliberately broken read-then-write
implementation, because threads under the GIL would not interleave; it was
replaced with a deterministic version that makes the read lie.
