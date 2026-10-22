# Issuer-only local Cloudflare credential reader

**Source owner:** station-access Regular; **contract:** \`zog-station-issuer-cloudflare-read-v1\`. **State:** opt-in source producer only; no live provisioned socket, token transfer, issuer installation or production DNS-01 acceptance. Root-control installer is separately implemented at \`zog/root_control/issuer_credentials.py\` and consumes a private token FD.

## Security principal and trust boundaries

This is a **dedicated Django management daemon**, not an HTTP API, not a
host-discover beacon extension and not a web-session export. It must run
under the isolated station credential-vault UID/GID, *different from* the
station web UID, issuer UID and root controller. It reads the local station
database and vault keyring through precisely provisioned protected mounts,
not through a generic web-export route. Do not give the web UID access to
the vault reader socket, projection or issuer-private certificate-data.

The deployment owner configures the following **trusted daemon settings**
(not client arguments):

- \`HOST_ISSUER_CREDENTIAL_READER_UID\`: numeric, nonzero vault-reader UID;
  required to equal the process EUID at startup
- \`HOST_ISSUER_CREDENTIAL_SOCKET_PATH\`: fixed path of the owner-created
  AF_UNIX \`SOCK_STREAM\` listener; inherited socket FD **3** (systemd socket
  activation); mode **0600**, socket inode and EUID must match, parent
  directories must not be writable by untrusted principals
- \`HOST_ISSUER_CREDENTIAL_AUTHORIZATION_FILE\`: fixed, absolute local
  root-owned nonsecret projection; 0440 root:vault-reader-group, nlink=1,
  every parent root-owned/non-symlink/non-group-writable, caller cannot
  supply a path
- \`HOST_LOCAL_CERTIFICATE_INSTALLATION_ID\`: original owner-provisioned
  UUID for standalone-local approvals; managed assignment uses the approved
  HostIdentity/ManagedAdmission

The projection is **not** the root authorization file itself. Root's
\`/etc/zog/issuer-credentials/<project-digest>.approval.json\` remains 0600
and root-only. Root/host-deploy must durably install a byte-consistent,
nonsecret, root-controlled station-readable projection and revoke it on
policy or credential changes. If the projection cannot be read, *deny*.

The station-reader projection has an exact, closed schema:

\`\`\`json
{
  "schema": "zog-station-issuer-reader-authorization-v1",
  "authorization": {
    "schema": "zog-issuer-cloudflare-credential-v1",
    "state": "approved",
    "project": "/reviewed/project",
    "certificate_id": "station-web",
    "assignment_id": "<uuid>",
    "assignment_revision": 1,
    "credential_id": "<uuid>",
    "credential_revision": 1,
    "zone_id": "approved-zone",
    "zone_name": "example.org",
    "grant_id": "<32 lowercase hex>",
    "storage_id": "<32 lowercase hex>",
    "policy_sha256": "<64 lowercase hex>",
    "receipt_sha256": "<64 lowercase hex>",
    "expires_at": 1800000000
  },
  "origin": "local",
  "installation_id": "<approved installation uuid>",
  "host_id": null,
  "account_id": "<32 lowercase Cloudflare account hex>",
  "owner_user_id": 1
}
\`\`\`

All example identities are placeholders, not valid runtime permission.
The nested \`authorization\` must exactly equal the **root owner's**
nonsecret approved record for this selected project/issuer grant/storage.
The projection adds the previously approved station origin/installation/
Host/account/admin identity; it does not create authority or broaden a
token's Cloudflare permissions. A root owner must independently bind the
same assignment and highest-seen revision, issuer grant/storage,
certificate policy and nonce before installation. Station cannot mint
root approval via this interface.

## Wire and response

Root installer opens the **preapproved private socket** and supplies one
request (max 1024 bytes), newline-delimited canonical JSON, then performs
\`shutdown(SHUT_WR)\` so that the reader knows the request is complete:

\`\`\`json
{"schema":"zog-station-issuer-cloudflare-read-v1","operation":"read-approved-cloudflare-issuer-token","authorization_id":"<sha256 of canonical JSON root authorization>","nonce":"<32 fresh lowercase hex>"}
\`\`\`

The reader obtains kernel \`SO_PEERCRED\` **before parsing**, requires
\`uid=0\`, then independently verifies its root-owned projection's SHA-256
ID. It serializes security decisions through station's security gate,
records the opaque nonce in durable SQLite with a 48-hour anti-replay
window and never records token bytes. A reused nonce is rejected across
restarts. A lost reply can be retried with a fresh nonce **only** while the
same authorization remains currently approved; root still rechecks its
own ledger. Any failure returns **zero bytes** and closes the socket.

On success, the response is **only** the ASCII Cloudflare API token,
20–4096 bytes matching \`[A-Za-z0-9_-]+\`, without newline, JSON framing,
INI labels or a status object. The privileged root caller must forward
it through a private FD to \`install_from_fd\` and ensure no token is put
in argv, environment, journald or operational request JSON. The root
installer writes the private issuer-owned \`dns/cloudflare.ini\` and
separately records its nonsecret receipt. No reader socket is exposed
outside the local application/host namespace.

## Pre/post vault read checks

Before decrypt and again after the vault operation, the reader requires:

- exact unexpired/revoked-free \`CertificateAssignment\` UUID, revision,
  origin, installation UUID and Host identity, with DNS-01,
  \`station-web\`, and \`dns-cloudflare\` policy
- SHA-256 canonical JSON of both current certificate policy and signed
  assignment receipt equal the durable root authorization's nonsecret
  digests; no lower revision, signer substitution or role crossover
- recorded approving station administrator matches selected enabled DNS
  destination owner; exact Cloudflare credential UUID/revision/account,
  zone ID/name and fresh passed zone-access observation
- for managed only: current approved host signing key/admission and
  synchronized live DNS assignment; for standalone: root-provisioned
  installation UUID and no managed name claim
- unchanged AES-GCM source row (\`key_id\`, ciphertext, provider, revision,
  account) and root authorization projection across the decrypt
- no alternate provider, arbitrary credential, Cloudflare API hostname,
  token from a remote command center or caller-selected issuer storage

A provider-zone listing **does not verify DNS-write power or narrow a
token**. Root/host-deploy must separately review a zone-limited
issuer-specific token and enforce revision/permission freshness just
before any selected issue/renew. No \`certify-policy\` mount is made writable.

## Operation and acceptance

For the isolated, reviewed station vault service (not the station web
process):

\`\`\`sh
STATION_ACCESS_STATE_DIRECTORY=/protected/station-state \
  python -m django serve_issuer_cloudflare_reader \
  --settings=zog.station_access.project.settings
\`\`\`

FD 3 must already be installed by the trusted owner; the reader does not
create a socket or choose a filename. Missing settings, wrong EUID, loose
socket/authorization permissions or unavailable protected state cause
service failure. The reader uses no generic root RPC, browser API,
host-discover transport, DNS update, Certbot invocation or nginx API.

The focused source regression is
\`python tools/test-backend.py tests.host_registry.test_issuer_cloudflare_reader\`.
Test cases cover UID gate, nonce replay, immutable identity,
cross-zone/provider refusal, revocation/expiry, absent vault,
unsafe token bytes, mid-decrypt rotation and silent error handling.
GitHub Actions are currently blocked pending the public repository
migration. Even after source tests pass, host-deploy Work still owns
cross-UID native acceptance, audited issuer-only file delivery,
crash/reboot recovery, ACME staging and real DNS-01 verification.

**NO-GO:** no production DNS-01, automatic credential provisioning or
certificate delivery is authorized solely by this station source patch.
