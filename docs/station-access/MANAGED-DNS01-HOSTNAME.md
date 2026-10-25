# Reviewed DNS-01 hostname authority for an enrolled non-resident host

**Source-only candidate — review before native adoption.** This path is for a
*genuinely enrolled* `generic` Host whose managed session and retained STATE
are already accepted, but whose host OS has no supported signed AWS identity.
It must not relabel that identity as AWS or invent a synchronized A record.

For [the October 25 credential-binding preflight](https://github.com/zog144/know-file/blob/eb676a231f4f66e0f69a118e825c12c6501adbac/station-access/verification/credential-binding-preflight-2026-10-25/README.md),
the intended non-production test hostname is
`issuer-test.zog-network-demo.uk`. The selected policy stays
`station-web`, `dns-01` / `dns-cloudflare`, Let's Encrypt **staging**.
The original enrolled Host UUID, Ed25519 fingerprint, installation UUID,
STATE volume, managed issuer authority ID and registry ID must all remain
unchanged. This source review is **not** station operator signer approval,
issuer token delivery, root grant, ACME issuance or public DNS publication.

## 1. Why this is separate from AWS DNS

The original `dns_evidence.RegistryEvidenceSource` and
`dns_destinations.configure` require `provider='aws'` plus freshly
matched signed cloud identity, EC2 inventory and an observed public
address. Those restrictions remain fully unchanged for A-record
reconciliation. For a non-resident managed installation, host-discover
intentionally signs a `generic` report; transplanting EC2 instance IDs
from an inventory observation would invent host provenance.

A DNS-01 ACME challenge needs verified DNS **zone control**, but does
not require the host to publish an A record first. The operator-only
`managed-dns01` binding therefore represents an exact *hostname
authority intent*, not a DNS record or a host cloud identity.

## 2. Protected prerequisites

- Native station must first run accepted source and migration
  `0017_manageddns01hostname`. An existing installed station and its
  signer, database, controller history, server CA and HostIdentity
  must be retained; migration is additive.
- An **active superuser** must be created by a separately authorized,
  supported Django administration/bootstrap procedure (zero were present
  in the October 25 preflight). Do not seed the ORM or fabricate an
  administrative identity with a script.
- The independent protected provider vault, reviewed Cloudflare
  credential, exact account and credential revision must be installed.
  A successful account-token verification and zone **GET** does not
  prove the token has least privilege or actual DNS-edit permission.
- An approved **shared, single-writer network-register DNS controller**
  must already be configured and fully initialized in its own protected
  state. These commands do **not** auto-create or reset its ledger,
  switch controller mode or adopt records. The configuration domain
  must equal the credential's reviewed Cloudflare zone
  (`zog-network-demo.uk` here).
- Host must be non-archived `generic`, with one approved HostIdentity
  matching a current, nonexpired ManagedAdmission. The installation,
  STATE volume UUID, managed authority ID, registry ID and approved
  fingerprint are read from authoritative station state, never pasted
  from a historical sample.
- The hostname must be **one label below the verified zone**; it
  may not overlap primary/additional DNS namespaces, a prior
  hostname grant, any owned DNS assignment or a different
  certificate installation. All prior DNS-01 name grants remain
  reserved even after revocation, pending separate reviewed release
  policy.

## 3. Supported operator review and commit (read-only provider operations)

Run within the retained station's authenticated, protected management
environment. This is an **operator-supplied exact identity review**, not
a browser or unauthenticated API:

```sh
python manage.py manage_managed_dns01_hostname review \
  --owner '<existing active superuser PK>' \
  --host '<retained enrolled Host UUID>' \
  --installation '<retained ManagedAdmission installation UUID>' \
  --fingerprint '<exact approved HostIdentity SHA-256>' \
  --registry '<current managed registry ID>' \
  --hostname issuer-test.zog-network-demo.uk \
  --credential '<vault ProviderCredential UUID>' \
  --credential-revision '<current exact integer revision>' \
  --zone-id cb17d0d6ac465756492edbcde2b53801
```

The action uses the selected Cloudflare credential through the protected
vault to verify the active account-bound zone, parent delegation,
authoritative SOA, nameserver configuration, complete read-only zone
inventory and name/prefix availability. It creates only a protected
hash-bound **10-minute review record** and returns a review ID; it writes
no DNS record, does not claim AWS inventory, and does not sign an
installable certificate policy.

After a *separate explicit operator review* of the nonsecret output,
commit the **same review**, with the same superuser:

```sh
python manage.py manage_managed_dns01_hostname commit \
  --owner '<same superuser PK>' --review-id '<64-hex review ID>'
```

Commit rechecks all protected inputs, live managed-session/STATE binding,
Cloudflare zone authority and full DNS record inventory under the shared
controller lock. It saves a durable `ManagedDns01Hostname` row and a
security audit event. Retries of the **same committed review ID** are
idempotent; a different review cannot silently rebind an existing
Host/hostname. The returned binding ID is `managed-dns01`,
`provider_writes=0`.

A required negative case is a mismatch or expiry of the managed session,
host key, installation UUID, STATE volume, managed authority, registry,
operator, credential revision, nameservers, cloud source or zone record
inventory. **All must stop**, without creating or replacing a grant.

## 4. Separate certificate assignment decision

A reviewed hostname grant is **not** a signed certificate assignment.
Once the reviewed controller/credential, native station signer/root trust
and activation conditions are independently met, an authenticated
administrator can use the existing
`POST /api/setup/certificate-assignments/` policy approval with:

- `origin: "managed"`, the **unchanged** enrolled `host_id`,
  `binding_id: "managed-dns01"`;
- exact Cloudflare `credential_id`, `credential_revision`,
  `zone_id`, `zone_name` and hostname from the active grant;
- `policy.challenge: "dns-01"`,
  `policy.dns_plugin: "dns-cloudflare"` and the already reviewed
  policy, expiration, expected revision and durable operation UUID.

Station-access validates that this very host, installation, STATE volume,
registry and HostIdentity still own the exact unambiguous hostname,
under the original DNS controller + security locks. It signs only
the original managed `host-nginx-https` envelope. No new issuer
protocol, HTTP-01 fallback or permission to supply arbitrary policy
bytes is introduced. The actual selected host must independently
verify that signed envelope before using its own Certbot runtime and
**separately protected** DNS-01 credential grant. Host-install's
token/ledger delivery is not solved by station source alone.

If authority is withdrawn or an enrolled binding changes, retrieved
approval fails closed. Explicitly **revoke the signed certificate
assignment first**, then the hostname intent:

```sh
python manage.py manage_managed_dns01_hostname revoke \
  --owner '<superuser PK>' --host '<original Host UUID>' \
  --expected-revision '<current binding revision>'
```

Do not delete the binding row or recycle its hostname silently.

## 5. Acceptance boundaries and Work continuation

1. **station-access Regular:** review new source, source CI, migration,
   negative tests, and public PR; do not certify runtime from CI alone.
2. **station-access Work:** on retained station, verify installed source
   and migration, protected operator/bootstrap identity and vault,
   and the shared DNS controller state. Complete **read-only review**
   with actual enrolled IDs; store the hash-bound receipt. A command
   returning `BLOCKED` is not a reason to invent metadata.
3. **Authorized operator:** explicitly approve the verified review,
   then run the supported commit. Confirm existing HostIdentity and
   ManagedAdmission are unchanged; verify zero DNS writes and
   inspect administrative audit history.
4. **Station signer/host-install owners:** only after independent
   authority checkpoint, grant/storage, DNS token transport,
   controller selection and host acceptance may the globally
   gated assignment producer be enabled and a signed policy
   issued. Certbot, Cloudflare DNS mutation, nginx publication and
   reboot tests are **separate native gates**.

**Current status:** source candidate only. No credential, controller
ledger, DNS name, A/TXT record, EC2 resource, HostIdentity, STATE,
issuer grant or certificate was installed or modified by this source
branch.
