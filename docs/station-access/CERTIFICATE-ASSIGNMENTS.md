## Reviewed managed signing-key provisioning — October 20, 2026

**Root pin producer input, not root installation or live HTTPS authorization.**
The supervised host-discover root checkpoint requires a separate,
installer-reviewed control-registry Ed25519 signing-key pin.
Managed assignments are signed by the *same* station control signer used
for managed admission, never by the standalone-local intent signer.
The pinned public key is nonsecret, but its **selection and trust path**
must be independently authenticated.

After authenticating the station installation and independently reviewing the
managed control key fingerprint, an authorized operator may invoke the local
Django management command in the installed station software/state environment:

```sh
python -m django export_managed_certificate_authority_pin \
  --settings=zog.station_access.project.settings \
  --host-id '<approved Host UUID>' \
  --installation-id '<approved installation UUID>' \
  --registry-id '<approved control registry ID>' \
  --host-fingerprint '<approved HostIdentity SHA-256 fingerprint>' \
  --expected-key-id '<independently reviewed station control key SHA-256 fingerprint>'
```

The command returns exactly the five nonsecret fields required by the
host-discover root pin contract: `schema:1`,
`kind:"zog-certificate-assignment-authority-pin"`, `registry_id`,
`authority_public_key`, and `authority_key_id`.
It checks the *current* unarchived managed host, approved HostIdentity,
installation UUID, control registry, live managed session binding and protected
control signer. It refuses a different key fingerprint. It does not export
a private key, look up arbitrary certificate assignments or write any file.

This is a **candidate for an authenticated deployment handoff** only:
host-install must independently verify the configured control-registry key
through its approved native installation/enrollment path and install the
reviewed candidate at
`/etc/zog/host-install/certificate-assignment-authority.json` as root:root
0444, beneath trusted root-owned ancestry. Do **not** pipe untrusted CLI/HTTP
output straight into that protected path. Host-discover checks the actual
installed root pin and its own separate root-owned rollback checkpoint.
The command can prepare a pin before `HOST_CERTIFICATE_ASSIGNMENT_ENABLED=1`;
enable advertisement only after native installation has confirmed a matching
root pin. The station application does not claim to remotely inspect this
root-owned host file.

The managed session's already-authenticated `public_key` continues to
identify the same signing key; neither its response nor the certificate
assignment response itself is sufficient to create a root trust anchor.
The dedicated local signer and the standalone-local receipt remain separate.
This command does not implement local root-owner handoff, issuer policy,
Cloudflare token delivery, Certbot, nginx or TLS activation. Native Gate B/C
and public export are independent NO-GO requirements.

---

# Certificate hostname authority — station-access v1

## Managed producer compatibility update — 2026-10-15

**This section supersedes the earlier managed-host request and signing
examples below.** The earlier examples describe the initial station-only
receipt format and are **not** the current host-discover producer contract.
The standalone-local signer and receipt remain separate.

Station-access pins host-discover to
`341255fd0ebdee5eedfd4be9a40829ec17391887` and implements:

- Signed POST `/api/hosts/<host-uuid>/certificate-assignment/` with exact
  `zog-host-certificate-assignment-request-v1` body: `schema`,
  `host_id`, `installation_id`, `known_revision`,
  `known_operation_id`, and `managed_session`.
- Exact `zog-host-certificate-assignment-response-v1` reply containing
  `schema`, `host_id`, `state` (`unassigned`, `unchanged`, or
  `receipt`), `revision`, and `envelope`.
- A managed receipt has `zog-certificate-assignment-envelope-v1` fields
  `schema`, `key_id`, `assignment`, `signature`. Its inner
  `zog-certificate-assignment-v1` is signed using the exact bytes
  `b"zog-certificate-assignment-v1\\0" + canonical_json(assignment)`.
  The authority key is the protected, independently pinned managed control
  signer already supplied by station's managed-session contract. The local
  `zog-certificate-assignment-receipt-v1` signer remains distinct and never
  substitutes for a managed command-center authority.
- Retrieval requires an approved HostIdentity, a live matching managed
  session, exact installation ID, signed request and unused replay nonce.
  Historical operation/revision conflicts are blocking, not hints to retry
  with a fresh certificate order. Receipt semantics are validated by the
  host-discover consumer using a pinned authority key and durable
  highest-seen revision across restart.
- The producer only advertises `"certificate_assignment":{"version":1}`
  on a managed heartbeat when `HOST_CERTIFICATE_ASSIGNMENT_ENABLED=1`,
  managed admission is enabled, an approved managed session is present, and
  the protected managed signer is usable. It is otherwise unavailable.
- Both managed and standalone local station assignment changes acquire
  the authoritative shared DNS/FQDN owner lock before the station security
  gate. Loss of the reviewed DNS owner blocks changes; local mode does not
  require managed HostIdentity or command-center enrollment.
- Explicit higher-revision revocation and UUID-to-canonical-payload
  idempotency persist. One installation may not silently replace a signed
  policy for another installation, and prior revoked names remain fenced
  against cross-installation reassignment pending separately reviewed
  transition.

The station API and source-only tests do not provision managed keys, open
challenge routes, bind root issuer policy, install TLS keys, reload nginx or
prove live HTTPS. **CI is still unavailable before workflow steps**; this
source pass is not operational acceptance.

---


**Source date:** 2026-10-15. **Status:** source-only issuer-intent producer,
not host acceptance. See certify-manage's
`handoffs/2026-10-14-local-certificate-assignment.md`.

## Authority and separation

Station-access supplies a versioned, **separately signed provenance
receipt** describing what its administrator approved. This is not the
root-controlled certbot policy `zog-certify-manage-v1`. The root-controlled
host owner MUST independently authenticate this receipt against its
explicitly pinned station certificate-assignment public key, enforce
installation/host UUID and DNS/provider/challenge/grant constraints,
check revocation and expiry, and create the protected issuer policy.
Neither a web session nor a successful beacon/heartbeat alone permits
certificate preparation/issue/reconcile, secret provisioning, nginx
delivery, certificate reload or traffic cutover.

`HOST_CERTIFICATE_ASSIGNMENT_SIGNING_KEY_FILE` and
`HOST_CERTIFICATE_ASSIGNMENT_SIGNER_ID` are explicitly provisioned by
the trusted owner. The signer MUST be a distinct private Ed25519 key,
in a 0600 non-symlink file owned by the station process identity. A
missing/unsafe signer blocks assignment approval and revocation;
there is **no** development fallback. Host-discover/host-deploy pin
its **public** key and expected signer ID independently, not via the
same HTTPS response or administrator-supplied request. The station
database stores only signed statements and approval records, never the
signer's key. Do not reuse the archive issuer key, managed enrollment
key, compiler observer certificate, ACME keys or DNS tokens.

## Administrator assignment request

`POST /api/setup/certificate-assignments/` requires authenticated
superuser and Django CSRF. The body must be **exactly**:

```json
{
  "schema": "zog-certificate-assignment-v1",
  "action": "approve",
  "origin": "managed",
  "host_id": "11111111-1111-4111-8111-111111111111",
  "binding_id": "selected-cert-zone",
  "credential_id": "22222222-2222-4222-8222-222222222222",
  "credential_revision": 4,
  "zone_id": "cloudflare-zone-id",
  "zone_name": "example.org",
  "policy": {
    "schema": "zog-certify-manage-v1",
    "certificate_id": "station-web",
    "hostnames": ["compiler.extra.example.org"],
    "email": "ops@example.org",
    "acme_directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "challenge": "dns-01",
    "dns_plugin": "dns-cloudflare"
  },
  "expires_at": "2026-10-30T12:00:00Z",
  "expected_revision": 0,
  "operation_id": "33333333-3333-4333-8333-333333333333"
}
```

All UUIDs above are illustrative; use approved **actual** identities.
Expiry is strictly UTC, between ten minutes and 30 days from approval.
The app requires an approved host identity and a durable
`ManagedAdmission` installation UUID; the assigned hostname must
match a currently synchronized, enabled, exact DNS assignment with
an acknowledged record ID and revision. Primary or additional reviewed
DNS bindings are supported; the selected Cloudflare credential UUID,
revision, zone ID/name and administrator owner must match the existing
reviewed selection. No new DNS reservation or provider write occurs.

**Standalone local:** use `origin="local"` and `host_id=null`, plus
the EXACT reviewed zone/credential/binding and a hostname one label
under an enabled, administrator-owned additional DNS destination
prefix. The application installation UUID must come from the
root-provisioned `HOST_LOCAL_CERTIFICATE_INSTALLATION_ID` environment
value, never the browser payload. Command-center enrollment and a
managed Host UUID are not required. A *fresh passed read-only
provider-access check for that exact active zone* is required, but
does **not** prove DNS-write permissions. The host owner separately
verifies the scoped DNS challenge capability. The local consumer is
always `station-nginx-https`; a managed host's is
`host-nginx-https`. No caller-chosen consumer or arbitrary issuer
program is possible.

Receipt output:

```json
{
  "schema": "zog-certificate-assignment-receipt-v1",
  "statement": {
    "schema": "zog-certificate-assignment-v1",
    "signer_id": "station-certificate-1",
    "origin": "managed",
    "assignment_id": "<UUID>",
    "installation_id": "<approved installation UUID>",
    "host_id": "<approved Host UUID or null>",
    "host_fingerprint": "<approved Ed25519 fingerprint or null>",
    "credential_id": "<credential UUID>",
    "credential_revision": 4,
    "zone_id": "<reviewed zone ID>",
    "zone_name": "example.org",
    "binding_id": "selected-cert-zone",
    "policy": "<the canonical policy JSON object above>",
    "consumer": "host-nginx-https",
    "revision": 1,
    "state": "approved",
    "approved_at": "<ISO-8601 UTC datetime>",
    "expires_at": "<UTC datetime>",
    "operation_id": "<UUID>"
  },
  "signature_ed25519": "<base64 Ed25519 signature>"
}
```

The signature is over UTF-8 JSON canonicalized with
`json.dumps(statement, sort_keys=True, separators=(',',':'),
ensure_ascii=True, allow_nan=False)` — **not** the response
envelope. Consumers must validate complete closed schemas, pinned
signer public key/ID, signature, exact audience (installation ID,
Host UUID/key and consumer), credential/zone/challenge scope,
monotonic revision, expiry and revocation. A previously seen higher
revision, a conflicting signer/origin, or a same-revision different
receipt must **block**, not replace the local owner policy. A host
must fence the certificate assignment if freshness/status cannot be
checked within its owner-approved offline validity window.

The change is serialized under the station security gate. A repeated
`operation_id` with the identical entire request returns the
same receipt, except a superseded old approval never resurrects
authority. Reusing the operation ID for a different request is a
409 conflict. To revoke, submit `action="revoke"` with the exact
old policy, host, binding, credential and zone, `expected_revision`
equal to the displayed current revision and a **new** operation ID.
The new signed statement has `state="revoked"`, incremented
revision and `revoked_at`. Retain revocation tombstones;
deleting a Django row is **not** revocation. The owner must retain
highest-seen revision across reboot and reject old signed approvals.

The admin `GET /api/setup/certificate-assignments/` lists at most
100 records including their signed receipts; it never returns signing
keys, API tokens, ACME accounts, private certificates or nginx paths.

## host-discover managed outbound retrieval contract

After an **independently approved** host identity and managed admission,
host-discover signs a `POST` (not a GET, nor an ordinary heartbeat)
to `/api/hosts/<approved-host-uuid>/certificate-assignment/` using
the existing `zog-host-v1` RFC 9421 Ed25519 profile. Body is:

```json
{"schema":"zog-certificate-assignment-v1","request_id":"<fresh UUID>"}
```

This binds method, URL, host UUID, host key, content-digest and nonce.
Station-access validates the exact approved key, verifies the
signature, persists the replay nonce under its security gate, and
checks the current installation binding and DNS/credential projection.
The HTTPS response is no-store:

```json
{
  "schema": "zog-certificate-assignment-v1",
  "host_id": "<approved Host UUID>",
  "request_id": "<request UUID>",
  "state": "approved",
  "receipt": {"schema":"zog-certificate-assignment-receipt-v1"}
}
```

States are `unassigned`, `approved`, `expired`, `revoked`,
`conflict`. A conflict returns **no installable receipt**. Expired
or revoked responses can carry the last signed receipt for precise
fencing; the owner must not treat these as positive authorization.
No hostname is assumed before an assignment is present. Host-discover
must independently validate the *separately signed* receipt and its
own protected installation/Host identity, persist highest-revision
anti-rollback state, and pass it to the root-controlled policy binder
through the approved local supervisor. The beacon must never run
Certbot, install keys or equate successful transport with authority.

### Host-discover Regular implementation assignment

Implement this retrieval as a **new** bounded, no-redirect HTTPS
operation in `host-discover`, separate from heartbeat's archive
response. Use its existing supervised key/transport and protected
root journal; pin the new signer and origin in trusted bootstrap.
Add tests for wrong host/key, replay, trust-key mismatch, tampering,
expired/revoked receipts, stale revision, central/local conflict,
installation mismatch and lost replies. Do **not** modify the
managed enrollment profile to require any FQDN at bootstrap.
Revocation/expiry checks must fail closed across restart. Do not
interpret an unsigned transport response as permission to invoke
certify-manage.

## Separately owned work / limits

Station-access checks currently persisted DNS/projection evidence,
not a fresh external DNS lookup during receipt creation. A local
read-only Cloudflare domain check is not proof of write permission.
The protected host owner must independently revalidate policy
binding and current provider authorization before issuer mutation.
Its Cloudflare secret bridge must place only the scoped token in
issuer-only 0600 `dns/cloudflare.ini`, preserve credential
revision/revocation and deny station-web cross-UID access.

This implementation does NOT: create a public host account, install
issuer policy, open challenge ports, issue/renew a certificate, send
DNS tokens, publish nginx certificates, expose the local issuer's
private key to a command center, or switch archive role. No live
ACME acceptance or public TLS cutover is claimed.

## Administrator UI and current integration status (2026-10-15)

Administration → HTTPS certificates retains the nonbinding issuer proposal
editor and separately presents **Versioned certificate assignments**. The
review form selects an existing administrator-owned DNS zone binding, an exact
managed host (or standalone local origin), reviewed FQDN, and a bounded
authority expiry. It does not choose a Certbot command, executable, Linux
username or host-local certificate output directory. Existing assignments
are listed with state/revision/expiry and explicit revocation. A lost approval
reply retains the submitted operation ID for safe retry; a changed proposal
requires a newly reviewed operation. The admin GET returns bounded stored
host/binding selectors and signed receipts, not credentials.

The current station API supports signed managed retrieval, but **host-discover
does not yet implement the consumer**. Root-control has not yet connected
the protected issuer-policy binder or reviewed Cloudflare credential
provisioning. Consequently certificate issuance, local nginx delivery and
external TLS readiness remain unavailable. The existing
`/api/setup/certificates/request/` remains fail-closed with HTTP 503.
No managed or standalone installation should install a local issuer policy
merely because a station assignment exists.


## Standalone headless retrieval

An installation that has no command-center account or managed Host UUID
uses its locally configured root-owned installation UUID and an approved
local station intent receipt. The separately authenticated host owner can
read that receipt through the source-only Django management command:

```sh
STATION_ACCESS_STATE_DIRECTORY=/protected/station-state \\
  python -m django read_local_certificate_assignment \\
  --settings=zog.station_access.project.settings
```

Invoke this command only through the verified station state/software
environment and after local owner authorization. It returns bounded JSON
with `state` and `receipt`: `unassigned`, `approved`, `expired`,
`revoked`, `conflict` or `installation-unavailable`. It performs no
provider I/O, Certbot operation or nginx update. A changed or expired
zone-access observation returns `conflict` with no installable receipt;
an explicit signed revocation remains visible. A privileged consumer
must still pin the receipt signer and check installation ID, policy,
revision, scope, expiry and local owner grant before installing the
root-protected issuer authorization.

**Note:** The management command's exact entry route is the installed
Django command infrastructure; host-install must verify that route in
its own compiled software view before deploying a systemd consumer.
