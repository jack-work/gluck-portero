# gluck-portero

Invite links for guest accounts on spain. The doorkeeper: it lets someone in
without ever holding their key.

Two halves, deliberately two processes:

| | |
|---|---|
| `portero.kelliher.info` | **Mint.** Behind Authelia, needs `portero-admin`. Creates the account and returns one link. |
| `invite.kelliher.info` | **Redeem.** Public, unauthenticated. The invitee chooses his own password. |

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

**Step 3 currently needs the operator.** Authelia requires an elevated session to
register a TOTP device, an elevated session needs a one-time code, and the
notifier writes to a file on spain because there is no SMTP:

```bash
ssh spain@spain 'sudo cat /var/lib/authelia-main/notification.txt'
```

Read the code, tell the invitee by phone. A one-time code is not a password: it
expires, it is single use, and it authorises one device registration.

**Recorded debt:** with no SMTP there is no self-service password reset, so the
operator is the reset mechanism by hand, forever. Configuring a real relay is the
follow-on fix and it blocks nothing today.

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
| mint | `127.0.0.1:9101`, no state |
| redeem | `127.0.0.1:9102`, one sqlite table of spent nonces |

Both loopback; only Caddy reaches them. Both carry `MemoryMax` and `CPUQuota`,
because spain is the house router on a single unbacked NVMe.

## Secrets

Three files, all sops, all delivered by `LoadCredential` into a per-unit tmpfs at
mode 0400. Never argv, never `Environment=`, never the Nix store.

| credential | held by | must be |
|---|---|---|
| `inviteKeyFile` | both | at least 32 bytes. Rotating it invalidates every outstanding invite |
| `adminPasswordFile` | mint | an `lldap_admin` |
| `redeemPasswordFile` | redeem | `lldap_password_manager` and **not** `lldap_admin` |

Generate the signing key without it ever reaching a terminal:

```bash
head -c 48 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' \
  | sops --set '["portero-invite-key"] ...'   # or: sops edit and paste
```

A Nix assertion refuses a configuration where mint and redeem share a credential
file, because that is the mistake that quietly undoes the split.

## Tests

`nix flake check` runs four suites, 51 cases.

| suite | what it pins |
|---|---|
| `invites` | a token we did not sign is never interpreted; tampering, signature swaps, expiry, unsigned payloads |
| `spent` | single use comes from a primary key, not a read-then-write |
| `redeem` | invalid, expired and used are byte-identical; the link works once; a typo does not burn it; the token never reaches a log |
| `mint` | `lldap_admin` cannot be granted; a caller without the group gets 403; a GraphQL error carrying HTTP 200 is not success |

Every security property has a **negative control**: the check is broken
deliberately and the suite must fail. Two of those controls found real problems.
One test of atomicity passed against a deliberately broken read-then-write
implementation, because threads under the GIL would not interleave; it was
replaced with a deterministic version that makes the read lie.
