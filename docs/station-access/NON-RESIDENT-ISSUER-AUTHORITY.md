# Non-resident STATE issuer authority — station-access owner contract

**Status:** source-only owner handoff; implementation/deployment not accepted.  
**Companion handoff:** [host-install non-resident STATE and issuer plan](https://github.com/zog144/host-install/issues/2) (2026-10-23).  
**Station producer:** managed certificate-assignment v1 and its local, read-only `export_managed_certificate_authority_pin` command.  
**Host consumers:** host-install native installer, host-discover root supervisor, controller-owned certify-manage, and host-deploy certificate consumer.

This contract applies to a **non-resident Zog installation** using the already
booted host OS and a verified, dedicated `/state` filesystem. It does not
provision that filesystem, authenticate a production station, enable root
execution, or issue a certificate. A resident/bootable Zog installation has
its own later acceptance gate.

## 1. Two independent pieces of evidence

A candidate pin exported by station-access is **not itself an authenticated
root trust anchor**. The native owner needs both:

1. **An independently authenticated expected station control signer**: the
   exact Ed25519 public-key fingerprint and `registry_id`, obtained through an
   explicitly reviewed station installation/registry authority channel. That
   channel must be independent of the pin export, the managed session
   `public_key` in a network reply, any signed assignment carried by the
   same proposed key, a heartbeat/beacon, and browser-supplied data.
   Record who authorized the expectation, the authenticated source/path,
   how it was checked, the intended registry and installation, and its
   fingerprint. **No such independent production expectation is supplied by
   this source tree or the isolated compiler preparation fixture.**
2. **An admission-bound station candidate**: output of the supported local
   `export_managed_certificate_authority_pin` command, constrained to the
   exact approved Host UUID, installation UUID, registry ID, approved host
   Ed25519 fingerprint, current managed-session bindings and a caller-supplied
   `--expected-key-id`. The command compares the currently configured
   station managed signer to that expected key, but cannot prove that the
   caller independently authenticated the expected value.

Suggested **review-record fields** (not a new wire schema, signed proof or
installer input until the owning programs approve them): station source
revision/installation identifier; reviewed registry ID; Host UUID; STATE
volume and installation UUIDs; approved host-key fingerprint; independently
authenticated station control key ID; verifier/approval reference; provenance
channel; verification date; candidate pin Git/byte SHA-256; and exact consumer
source revisions. Never put private keys, session tokens, credentials or a
signed certificate policy in this record.

### Existing read-only exporter

In an installed, authorized station Django environment, the owner may use:

```sh
python -m django export_managed_certificate_authority_pin \
  --settings=zog.station_access.project.settings \
  --host-id '<approved Host UUID>' \
  --installation-id '<approved installation UUID>' \
  --registry-id '<reviewed registry ID>' \
  --host-fingerprint '<approved host-key SHA-256>' \
  --expected-key-id '<INDEPENDENTLY reviewed station signer SHA-256>'
```

Output is exactly the five-field
`zog-certificate-assignment-authority-pin` v1 candidate:
`schema`, `kind`, `registry_id`, `authority_public_key`, and
`authority_key_id`. The station exporter reads no installed root-owned
pin, writes no host file, creates no local root authority, and does not enable
the certificate assignment producer. Do not derive
`--expected-key-id` from the very output being verified.

## 2. Protected native acceptance boundary

**host-install**, not station-access, must independently verify that the
authenticated expectation and exported candidate agree, the registry and
Host/installation enrollment bindings are current, and the canonical STATE
installation is verified and not on a recovery hold.

Only after that approval can host-install install
`/etc/zog/host-install/certificate-assignment-authority.json` with
root:root 0444 and protected root-owned parent ancestry, then read back
the actual installed bytes/identity/ownership. A candidate file, copied
operator JSON, HTTP response, or matching candidate-derived SHA-256 alone
does **not** satisfy this gate.

**host-discover** independently consumes the installed root pin, checks
the protected managed journal and signed assignment, and maintains a separate
root-owned anti-rollback checkpoint at
`/state/host-discover-certificate-authority/authority.json`.
The root checkpoint is not the `zog-certify-manage-v1` policy and is not
permission to run the issuer. Source interface:
[host-discover certificate authority owner handoff](https://github.com/zog144/host-discover/blob/unstable/docs/host-discover/CERTIFICATE-AUTHORITY-OWNER-HANDOFF.md).

The managed assignment capability must not be advertised until the native
installation has proved a matching reviewed pin. **This is an operator-owned
activation precondition, not a root-pin verification performed by station-access.**
At this source revision, station's `managed_enabled()` checks the global
`HOST_CERTIFICATE_ASSIGNMENT_ENABLED` setting, managed-admission enablement
and local signer availability; the heartbeat additionally requires a managed
session. Neither check authenticates a remote host's installed root pin or
provides per-host pin-readback gating. The operator must keep the global
advertisement disabled unless **every host eligible for the advertised
capability** has independently accepted native pin evidence, or a separately
reviewed per-host authorization gate is implemented. Exporter success, a
managed-session response or a heartbeat capability is not such evidence.

A key replacement/rotation or a changed registry, Host UUID, installation
UUID or control checkpoint is an explicit reviewed transition, not an
instruction to overwrite the file.

## 3. Selected issuer composition belongs to controller owners

box-control/root-control and certify-manage must independently bind an
actual selected program/application, immutable generation and software view,
dedicated numeric issuer UID/GID and grant, owned `certificate-data` storage
(mode 0700) under verified STATE, protected policy digest, preparation
revision, and supported durable request ID. A selected `inspect` result must
be authenticated against the **actual** selected runtime, boot ID, systemd
InvocationID, UID/GID, exact grant, storage and policy. An independent
controller record reopen is **not** the same as executing selected inspect.

The previously retained compiler's synthetic `.invalid` policy and its
`private-native-admission-20261023-v2` preparation fixture demonstrate a
bounded prepare capability only. That compiler had **no canonical /state
installation or root authority pin** at handoff time. Its grant/STATE data,
source tuple and identities are not portable installation inputs. The
historical compatible generation and view are evidence to be independently
selected/revalidated on a fresh host, **not** an approved new deployment lock.

Without a hostname assignment, the native lifecycle reports the actual
`awaiting-operator-approved-hostname-challenge` / empty inspection state.
There must be no fabricated lineage, implicit public ACME issuance, private
credential transfer, DNS mutation, nginx activation or certificate staging.

## 4. Source and native acceptance matrix

| Contract | Current source boundary | Required next evidence |
| --- | --- | --- |
| Managed exporter matches signer and approved admission | Station unit tests; candidate only | Independently verified expectation provenance, exact Host/installation/registry/key binding and read-only export |
| Root-owned authority pin and protected checkpoint | host-discover source contract | host-install verified STATE, root installation/readback; host-discover independent checkpoint/replay rejection |
| Native non-resident STATE | Host-install owns records/provisioner | Dedicated device/PARTUUID/UUID, real mount, interrupted provisioning recovery, root-disk/wrong/RO refusal, reboot |
| Issuer runtime preparation | Isolated compiler prepare evidence only | Fresh compatible controller/grant/immutable view/0700 storage under actual STATE |
| Selected issuer `inspect` | No station endpoint or implied controller permission | Actual selected invocation with durable ID and authenticated boot/InvocationID/UID/GID/grant/storage/policy receipt |
| Certificate issue, renew, stage and HTTPS | Not authorized here | Separate certificate owner, host-deploy and native lifecycle acceptance |

### Required negative cases

Block a candidate-derived expected key, mismatched registry or host signer,
rotated/unapproved key, expired or mismatched managed session, archived/revoked
HostIdentity, wrong installation UUID, absent/wrong/read-only or unmounted
STATE, missing/corrupt/root-mismatched pin, root-owned checkpoint rollback,
policy/grant/storage mismatch and false selected-inspect provenance.
A network outage or `unassigned` response must not erase established
higher-revision root history.

## 5. Handoff order

- **Now:** station-access/source owners and host-discover/host-install review
  the independently authenticated signer expectation and publish a
  nonsecret, exact-pin provenance/approval record.
- **Concurrently:** host-install develops the non-resident STATE installation
  and dedicated-volume provisioning contract.
- **Next:** controller/certify-manage owners specify the real application,
  selected inspect interface and compatible immutable source pins.
- **Only after prerequisites:** host-install Work may accept on a separately
  authorized disposable non-resident host; host-deploy later accepts actual
  certificate delivery/HTTPS.

No shared compiler reprovisioning, format, reboot, cloud resource mutation,
new certificate request or public cutover is authorized by this document.
