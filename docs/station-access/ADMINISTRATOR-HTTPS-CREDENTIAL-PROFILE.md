# Administrator HTTPS credential provisioning profile — source proposal only

**Date:** 2026-10-29  
**Profile schema:** `zog-admin-credential-provisioning-proposal-v1`  
**Shared transport:** host-identify HTTPS credential delivery v1  
**Shared source:** `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b` (host-identify 0.3.5)  
**Purpose:** `station-administrator-password`  
**Consumer:** `station-access`  
**Credential ID:** `station-admin`  
**Status:** proposal/test only; remote administrator provisioning remains disabled.

This profile is a purpose-specific consumer of the common HTTPS credential
delivery design. It does not make administrator passwords generically readable
by enrolled Hosts and is not enabled in the existing issuer-only HTTPS broker.

## Existing behavior reconciled

### Django account password

Django stores a one-way password hash. The Users API never returns plaintext or
the hash. Creating/resetting an account runs the existing Django password
validators. Password, active-state and administrator-role changes revoke
existing database sessions and unused VNC grants; an administrator changing
their own password keeps only the current browser session.

The account's concurrency revision is the existing **opaque keyed revision
string** returned by `user_views.revision(user)`. It is not an integer counter.
A provisioning proposal binds that exact opaque revision. Any password, role,
active-state or other account edit changes it and makes an earlier proposal
stale.

### FIRST-LOGIN

`FIRST-LOGIN.txt` can be a recoverable plaintext only because initial setup
intentionally wrote an owner-protected bootstrap file. It is not derived from
the Django hash.

`export_station_login` accepts an owner-only FIRST-LOGIN file or explicit
owner-protected JSON source and calls `check_password` against the current
active `station-admin` superuser. A stale FIRST-LOGIN password therefore fails
after password rotation. The command does not overwrite an old export on
failure and never reverses a password hash.

FIRST-LOGIN should be treated as an intentionally retained bootstrap secret,
not as automatically current account state.

### Legacy station_login_file

host-discover's current legacy `station_login_file` path reads an explicitly
provisioned owner-protected 0600 JSON file containing
`{"username":"station-admin","password":"..."}`. Only after a Host is already
bound does it place that plaintext into a HostIdentity-signed HTTPS heartbeat.
`station_login_withdraw=true` sends an explicit null withdrawal.

station-access removes `station_login` from the ordinary report before report
persistence and stores the credential separately in its AES-GCM
`StationCredential` vault. This is an existing **push/export** path. It is not
the new HTTPS delivery profile and a signed heartbeat does not authorize a Host
to read a Command-Center administrator password.

Migration away from this legacy path must be explicit: withdraw the old
registry-held export, rotate/re-provision as needed, and do not silently reinterpret
an old heartbeat export as a common-protocol authorization or installation
receipt.

### StationCredential vault

The central StationCredential vault intentionally contains recoverable
plaintext after decrypting its AES-GCM row because it supports explicit audited
administrator reveal. That browser permission boundary is separate from
machine credential authority. A vault row does not prove a Host may receive the
secret, and browser administrator login does not confer machine-client delivery
privileges.

## Source-only proposal

`administrator_credential_profile.validate_proposal()` accepts exactly:

- schema and purpose above;
- consumer `station-access`;
- credential ID and selected account `station-admin`;
- `first-provision` or `rotate`;
- exact destination Host UUID and HostIdentity fingerprint;
- exact installation UUID and STATE volume UUID;
- exact control registry ID;
- positive credential revision;
- exact account database PK and opaque current account revision;
- independently reviewed operator approval SHA-256;
- UUID receiver grant;
- destination `protected-station-admin-state`;
- source kind:
  - `first-login-verified-export`, or
  - `operator-provisioned-new-secret`;
- `source_password_verified=true`;
- `session_revocation_required=true`.

The returned decision is deliberately secret-free and always contains
`remote_delivery_authorized=false`.

`validate_for_account()` additionally requires the exact current
`station-admin` PK, username, active superuser state and keyed account
revision. A password change therefore invalidates a previously prepared
proposal.

`source_password_is_current()` performs only an in-memory one-way
`check_password` verification. Passing the Django hash itself does not
recover or validate the secret.

## Shared HTTPS binding

`common_binding()` maps the proposal to the exact host-identify v1 destination
binding:

```text
Host UUID
HostIdentity fingerprint
installation UUID
STATE volume UUID
control registry
consumer = station-access
purpose = station-administrator-password
credential_id = station-admin
```

The common protocol still requires, independently:

1. HostIdentity-signed fresh request;
2. separately trusted Credential Authority authorization;
3. exact credential and authorization revisions;
4. durable HTTP nonce/request anti-replay state;
5. protected root-owned reception and account destination policy; and
6. a secret-free HostIdentity-signed installation receipt only after durable
   password installation and session invalidation are confirmed.

This proposal is not itself a signed authorization.

## First provisioning

First provisioning may use a still-current FIRST-LOGIN/export secret only after:

- explicit operator selection of the destination installation;
- source-file owner/mode validation;
- `check_password` against the current active `station-admin`;
- exact current account revision;
- separate operator approval and receiver grant;
- positive credential revision.

Enrollment, signed beacon, managed inspect session, browser login, or existence
of a StationCredential row is insufficient.

## Rotation

Rotation requires a new explicitly supplied/generated recoverable plaintext.
It must pass the same Django password validators and be committed through the
normal account history/session-revocation path. The resulting new opaque
account revision and a new credential revision are then bound into a fresh
operator-approved proposal.

Changing a Django password does **not** rewrite FIRST-LOGIN, an old
`station_login_file`, another registry's vault row or a previous proposal.

The common protocol's interruption rules apply: a delivered-but-unreceipted
password remains uncertain; a second delivery is blocked until reconciliation,
and cancellation after delivery forces another credential rotation rather than
redelivering the exposed bytes.

## Recovery and revocation

Account history and audit metadata remain secret-free. Disabling/demoting the
account or changing its password invalidates the bound account revision.
Existing session/VNC revocation semantics remain authoritative.

A future protected receiver must retain monotonic authorization/request/
delivery state across restart and prove the selected account was actually
updated before sending an installation receipt. It must never restore an old
password merely because delivery response state was lost.

## Tests and dependency adoption

The existing station-access source tests prove:

- FIRST-LOGIN export succeeds only while its plaintext matches the current
  active administrator;
- password rotation makes the old FIRST-LOGIN source fail without rewriting an
  old export;
- profile rejects hashes, plaintext fields in the proposal, wrong account,
  browser consumer/destination, bad approval, unchanged/invalid revisions and
  missing session-revocation requirement;
- old account revision is rejected after password rotation.

A focused workflow
`.github/workflows/administrator-credential-profile.yml` checks the profile's
exact common binding on Python 3.12 and 3.13 against host-identify
`4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`.

The currently accepted station-access public companion manifest predates
host-identify 0.3.5. This review branch does **not** rewrite that accepted
manifest or its evidence hashes. Formal companion-pin adoption is a separate
station-access review prerequisite before this profile can be enabled.

## Activation remains blocked

No generic host, browser route, signed beacon, managed session or issuer-only
Cloudflare broker route is allowed to select this purpose. No live password was
sent, no account was remotely mutated, no session was remotely revoked, and no
new port-443 credential route was activated by this source work.

Before activation, host-install/root ownership must define the exact protected
administrator receiver, destination UID/storage, authority pin, interruption
recovery and native password/session verification.
