# Credential v1: independently approved Command-Center offline bootstrap

**2026-10-30 — source-only proposed native contract.** Owner: station-access Regular with host-install/protected installer owner. Retained [Work evidence](https://github.com/zog144/know-file/blob/2e202e9e89ff32af6e258f7d2f64a4f9e659e6c8/station-access/verification/credential-v1-offline-preparation-2026-10-30/README.md). **Offline preparation approval is already valid and does not require repeating.** It does not approve an operator signing key, root grant, live service, credential export or a new Host identity.

## Observed facts, not new authority

The existing **Command-Center Host** is the externally managed AWS station `i-0c676721165320da0`, running the existing station-access service and database. The exact [source-only staged software](https://github.com/zog144/station-access/pull/12) is rooted in `/opt/station-trust/credential-v1-4966c5a7-offline` at station-access source `4966c5a7419ba62335eadc6b71ec0fe530270a13`; it is not the active venv. The live database was observed as UID 999, mode 0644, dev/inode to be read back; **inode 307826** is the previous observation, not an authorization to assume it remains current. The live database is still at migration 0017; schema 0018/0019 was successfully rehearsed on an isolated copy. Six DNS-controller protected files, including the original lock and ledger identities, were preserved. Do not reset them.

**A Command-Center installation is not an Enrolled Host.** Enrolled consumer Host `305a221a-ef73-42a8-af21-a0b28bca5201`, installation `fdf20ffe-2353-40a8-a198-508e103f4348`, STATE `8c7affc9-8be7-4959-9040-d144b5b4dc98`, and its signed hostname assignment belong exclusively to the *remote issuer consumer*. None of these may be transplanted as the Command-Center's identity. Likewise, root-installing `/state` or minting a host-install schema-2 installation ID on the existing station is a **different, separately authorized migration**, not a prerequisite which source code may fabricate. In this initial adapter the existing protected station database remains the only reviewed app-state observation, and `canonical_host_install_state_verified=false`.

The prior Work inspection did not find an independently installed operator public pin, narrow root grant, issuer-reader authorization/socket, canonical signed v1 authorization, Credential Authority signing key or signing-role endorsement on the Command-Center. **Missing is a hard STOP**. An AWS instance ID or the station's own certificate signer fingerprint is not an independent operator approval key.

## Supported root-owner identity review contract — no installation

New isolated module `zog.station_access.credential_v1_offline_identity` implements read-only Ed25519 review. It neither imports the Django registry nor opens a credential vault nor creates any file. It expects a root-owned **existing** independently provisioned operator public key (0444), and a root-owned **existing** 0600 signed attestation, each one link and without symlink ancestors.

The signed `zog-command-center-offline-installation-identity-v1` object contains exact fields:

```json
{
  "schema": "zog-command-center-offline-installation-identity-v1",
  "station_role": "command-center-host",
  "installation_mode": "externally-managed",
  "state_mode": "existing-station-application-database",
  "command_center_host_id": "<operator-assigned UUID distinct from enrolled Host>",
  "command_center_installation_id": "<operator-assigned UUID distinct from enrolled consumer installation>",
  "external_host_instance_id": "i-0c676721165320da0",
  "external_host_evidence_sha256": "<sha256 of independently AWS-verified host evidence>",
  "station_registry_id": "<approved current registry ID>",
  "station_source_commit": "4966c5a7419ba62335eadc6b71ec0fe530270a13",
  "database_path": "<observed absolute existing live station database path>",
  "database_device": 0,
  "database_inode": 0,
  "database_owner_uid": 999,
  "database_mode": 420,
  "database_parent_device": 0,
  "database_parent_inode": 0,
  "enrolled_consumer_host_id": "305a221a-ef73-42a8-af21-a0b28bca5201",
  "enrolled_consumer_installation_id": "fdf20ffe-2353-40a8-a198-508e103f4348",
  "enrolled_consumer_state_volume_id": "8c7affc9-8be7-4959-9040-d144b5b4dc98",
  "certificate_signer_pin_sha256": "<previously pinned station signer public-key sha256>",
  "review_revision": 1,
  "issued_at": 0,
  "expires_at": 0,
  "signature_ed25519": "<canonical base64>"
}
```

**All zero values and placeholders above are invalid review inputs**, not defaults. The native installer observes device/inode, path, parent inode and account; checks that root-owned protected parent ancestry and database inode are stable; verifies independently obtained AWS IID/instance identity and the exact selected source hash. An operator who independently controls the *pre-pinned operator private key*, **outside the candidate station**, signs:
`b"zog-command-center-offline-installation-identity-v1\\0" + canonical(unsigned_attestation)`.
The public key is supplied through an independently authenticated operator/bootstrap channel and its SHA-256 is checked against the separately approved expected fingerprint. The module cannot authenticate how the operator first approved that fingerprint: host-install/protected installer must record that external evidence. Neither the source checkout nor station certificate signer may act as its own approver.

Example command (only after actual independently approved files exist; do not execute with placeholder paths):

```sh
sudo /opt/station-trust/credential-v1-4966c5a7-offline/venv/bin/python \
  -m zog.station_access.credential_v1_offline_identity \
  --signed-attestation /etc/zog/trust/command-center-offline-identity.json \
  --existing-operator-public-pin /etc/zog/trust/operator-ed25519.pub \
  --expected-operator-pin-sha256 EXACT_INDEPENDENTLY_APPROVED_64_HEX \
  --expected-aws-instance-id i-0c676721165320da0 \
  --expected-station-source-commit 4966c5a7419ba62335eadc6b71ec0fe530270a13
```

The command reads and emits **only a nonsecret, unsigned review report** with its own `authorized_for_authority_installation=false` and `authorized_for_credential_delivery=false`. Its local database/device observation is not AWS cryptographic identity verification or authority adoption; read-only output alone **never authorizes installation**. A changed installation, filesystem inode, boot lineage or host provenance requires a new independent owner review. No key generation, enrollment, Cloudflare read, database migration, file publishing, systemd manipulation or network changes occur.

## Protected installer / host-install owner: exact next implementation boundary

1. **Independent host identity**: establish and document trusted AWS IID verification (and expected instance identity), installation management/provenance, and selected existing station database/software root; bind operator-approved Command-Center UUIDs *distinct* from the remote consumer. Explicitly attest externally-managed OS and station app-state mode. Do not represent the Command-Center as canonical host-install `/state` when the protected live inspection did not find it. If canonical `/state` must eventually be installed, make that a distinct operator-reviewed disk/state migration; no destructive provisioning on the retained instance.
2. **Offline root owner**: identify the existing independently trusted protected installer service/UID, installed source, and a root-controlled **existing** owner-lock path. Only that owner may introduce the operator 0444 public pin after verifying it out of band. Require exact source/RECORD and stable state/database identity; stage all new authority inputs under a separately root-private **offline** directory, not active `/etc` or live service environment. Reuse tested descriptor-anchored, durable, no-replacement primitive (host-install `state_io.publish` or an equivalently audited owner); verify same-byte resume, symlink/hardlink failure, atomic fsync and no credential bytes in receipts. This module deliberately does not invoke an unapproved candidate installer as root.
3. **Prepare real authority inputs, not self-approval**: after a separately authenticated existing operator key, propose exact PR #11 `GRANT_FIELDS`, independent operator signature over its canonical unsigned body, original issuer-reader 0440 projection, **separate** Credential Authority v1 Ed25519 PEM+0444 pin, canonical signed v1 authorization with distinct UUID and its domain-separated operator endorsement over exact grant/envelope/key SHA-256. Prepare original certificate signer pin as an **existing** input; never overwrite or reuse it to sign credential deliveries. Root-owned 0600/0444 modes, no symlinks or second links. Do **not** install grant or token reader into live paths without a new approval of actual fingerprint/hash, revision, expiry and consumer.
4. **Review, then seek actual approval**: return source/RECORD, trusted operator pin fingerprint and proof of its independent origin, native Command-Center identity evidence digest, signed root-grant/envelope and signer-endorsement digests, full expiry/revision/consumer/hostname bindings, original certificate-signer fingerprint, protected path/inode/DAC, and an explicit **review-only** status. The operator then approves the exact content separately. The prior offline software-staging approval remains valid; do not ask for it again.
5. **No production adoption** until protected owner simultaneously coordinates root grant/authorization changes with the SQLite `SecurityGate` ledger writer, verifies migration and restart/reboot, and independently confirms authorized receiver HostIdentity, protected anonymous FD receipt, nginx TLS route and revocation/uncertain-delivery behavior. Ingress/broker flags remain false; no real Cloudflare token, DNS/ACME/Certbot, admin password or issuer preparation retry.

## Required negative tests

Wrong independently expected operator pin; candidate self-signed pin; missing signed attestation; altered grant/identity; wrong Command-Center instance ID, source or DB inode; different owner/permissions, symlink/hardlink and replaced file; enrollment UUID reused as station installation; untrusted certificate signer reused as operator; expiry/revision rollback; host-install canonical `/state` invented from consumer identifiers; operator-approval record absent; staging partial writes; service restart before authority acceptance; no import of real secrets.

**Disposition remains BLOCKED for authority material preparation until independent operator/bootstrap inputs and installer owner provenance are supplied.** No production/endpoint/credential operation is authorized by this document or its source tests.
