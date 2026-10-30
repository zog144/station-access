# Canonical Credential Authority v1 — independent signing review and native installation handoff

**Review date:** 2026-10-30. **Scope:** Command-Center Host producer only, not arbitrary Enrolled Hosts. Source: station-access draft PR #11 stacked on PRs #10 and #9; host-identify shared protocol v0.3.5 at `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`. This checklist does not approve live service activation or Cloudflare export. The legacy raw-token endpoint and SSH proposal must remain disabled.

## 1. Authority signing — independently reviewed trust graph

There are **three separate Ed25519 roles**. They must not be conflated:

1. **Operator approval key (independently pre-pinned):** root:root 0444 raw 32-byte public key in `HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE`. A root-protected approval file `HOST_CREDENTIAL_HTTPS_OPERATOR_APPROVAL_FILE` (0600) signs the *existing narrow grant* `HOST_CREDENTIAL_HTTPS_AUTHORITY_FILE` (0600), as implemented by PR #9. A newly generated candidate key is never allowed to approve its own provenance.
2. **Station certificate-assignment signer:** existing separately installed 0444 pin `HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE`, still bound to the original operator-signed grant through `independent_signer_pin_sha256`. This is **not** the HTTPS credential delivery signer.
3. **Credential Authority v1 signer:** separate root:root 0600 Ed25519 PEM `HOST_CREDENTIAL_V1_SIGNING_KEY_FILE` and root:root 0444 raw 32-byte public pin `HOST_CREDENTIAL_V1_SIGNER_PIN_FILE`. The private key must match this pin; it must match neither the operator pin nor the certificate signer pin. Do not copy a current certificate signing private key to make this work.

The source now requires a **second operator-signed approval of the new signing role**, installed at `HOST_CREDENTIAL_V1_AUTHORITY_APPROVAL_FILE` (root:root 0600, symlinks and hardlinks disallowed). This record has **exactly**:

```json
{
  "schema": "zog-credential-v1-authority-signing-approval-v1",
  "grant_sha256": "<SHA-256 of canonical nonsecret PR #9 root grant JSON>",
  "authorization_envelope_sha256": "<SHA-256 of exact canonical signed v1 authorization envelope bytes>",
  "authority_signer_sha256": "<SHA-256 of raw 32-byte v1 public signing key>",
  "authorization_id": "<exact canonical UUID>",
  "revision": 1,
  "expires_at": 0,
  "signature_ed25519": "<canonical base64 of 64-byte operator signature>"
}
```

The illustrative `expires_at:0` above is deliberately **not valid**. For actual offline preparation, the operator selects a real future Unix timestamp **no later than the root grant expiry** and **not before the signed v1 authorization expiry**. The operator signs `b"zog-credential-v1-authority-signing-approval-v1\\0" + canonical(unsigned_record)`, using the independently pinned operator private key outside the candidate station. The signed receipt is read and reverified by the protected root broker; there is no browser/remote endpoint for generating it. Changes to the signer, envelope, revision, grant or signature all fail closed.

The independently signed `HOST_CREDENTIAL_V1_AUTHORIZATION_FILE` (root:root 0600) uses **canonical JSON bytes** of `zog-credential-authorization-envelope-v1`. The envelope is signed by the distinct Credential Authority key. It binds exact origin, HostIdentity fingerprint, Host UUID, installation UUID, STATE UUID, registry, `certify-manage`, `issuer-cloudflare-dns01`, credential ID `cloudflare-<32 lowercase hex UUID>`, credential revision, *distinct* canonical authorization UUID/revision/status/expiry. Do not substitute the older 64-hex SHA-256 `authorization_id` of the protected issuer-reader projection for the canonical UUID: the existing operator grant still binds that separate nonsecret issuer-reader authorization digest.

**Independent provenance gate:** establish and record key generation/import ownership, separately authenticated operator public pin, separate station certificate signer pin, root grant signature, new canonical v1 key pin, exact signed authorization bytes, new operator endorsement and installation/STATE identity via an already trusted process. A signature produced by the same candidate does not prove that the candidate was approved.

## 2. Installer-owned artifacts and DAC

| Artifact | Required owner / protection |
|---|---|
| Original root grant, approval, canonical signed authorization and v1 role approval | root:root, mode 0600, one link, no symlink, parent chain root-controlled/nonwritable by group/other |
| Operator public pin, station certificate signer pin, new Credential Authority public pin | root:root, mode 0444, raw 32-byte keys, original trusted fingerprints recorded separately |
| v1 Credential Authority private PEM | root:root, mode 0600, one link, no symlink; never argv, environment, journal, backup export or browser |
| Original vault-reader authorization projection | Existing protected root:issuer 0440 control, exact approved project/account/assignment/credential/zone/grant/storage |
| Persistent STATE-backed station database, SQLite WAL and migration 0019 | Protected persistent database identity; retain original ledger and replay history across restart/reboot |
| Broker listener | Separate root-owned AF_UNIX pathname under protected root-owned parents; exact path, mode 0660, isolated group only for approved ingress UID |
| Dedicated ingress process | Non-root UID (not Django/station admin/issuer), no root groups, no vault/private-key mounts, no station DB access or browser session state |

The privileged broker service is systemd **socket activated with exactly one inherited FD 3** (`LISTEN_FDS=1`, `LISTEN_PID=` service PID). Validate `AF_UNIX`, stream/listening state, selected `getsockname()` path, root-controlled path and parent DAC, exact ingress kernel peer UID via `SO_PEERCRED`. Linux socket FD and pathname inode numbers are **not** expected to match. Prevent path replacement after socket activation, unauthorized group access and lock/STATE replay-DB replacement. The old PR #9 broker and socket must not be routed or enabled.

The separate WSGI module `zog.station_access.credential_v1_wsgi:application` must run in an isolated non-root service. Proxy only exact `POST` routes to its private listener under the already authenticated Command-Center HTTPS origin. Pin TLS origin; do not follow redirects, infer authority from client Host/X-Forwarded headers, allow cookies/browser Authorization or map `/api`, beacons or noVNC here. Disable secret-bearing access/error/body logs, response buffering to disk, caching, compression, debug traces, SSM echo and diagnostic responses. Private broker reply and HTTP response must not be recorded.

**Source defaults are intentionally impossible to activate merely through environment variables:** `HOST_CREDENTIAL_V1_BROKER_ENABLED=False` and `HOST_CREDENTIAL_V1_LIVE_ENABLED=False`. `ZOG_CREDENTIAL_V1_HTTPS_INGRESS_ENABLED` also defaults absent. A separate explicitly reviewed native installer/activation change, attested as installed bytes, is required. Never flip these gates in production as a shortcut to acceptance.

## 3. Native sequencing and acceptance evidence

1. **Read-only preflight:** identify the existing Command-Center Host, exact installation/STATE, source and all companions. Verify full reviewed PR #11 stack, the pinned host-identify v0.3.5 and retained accepted network-register provenance; verify installed wheel/RECORD and source hashes. No self-authentication from a candidate export.
2. **Protected offline preparation:** materialize new signer, separate pin, v1 signed authorization, root operator endorsement and retained grant/projection through the native protected installer; independently inspect file owner, mode, link count, symlink ancestry, canonical bytes/signatures and all revision/expiry joins *without reading or delivering a real token*. Keep source live flags disabled.
3. **Storage and reboot:** apply `host_registry.0019_credentialv1ledger` on durable STATE, verify SecurityGate transaction, ReplayRecord, WAL/fsync and exact database inode protections. Restart and reboot; verify no rollback, ledger disappearance, new blank state, or accidental database path replacement.
4. **Isolated ingress and socket admission:** prove dedicated UID/GID, no Django/vault/DB/root permissions, exact nginx HTTPS route and trusted scheme, protected broker/listener path, root listener mode and `SO_PEERCRED`. Refuse untrusted local clients, wrong origins, crossed identities, symlink/hardlink/replaced files, wrong AF_UNIX FD, unsupported content type and oversized/duplicated JSON.
5. **Synthetic end-to-end evidence:** test genuine Host RFC9421 request, root grant and operator signatures, separate v1 authority signature, purpose and consumer selection, protected nonsecret Cloudflare projection and private vault reader mock. Test wrong grant revision, key pin, envelope substitution, expired/revoked Host/session/hostname/zone, and current-key rollover. No real Cloudflare token.
6. **Durability and lost response:** one-time signed HTTP nonce plus UUID request in same SQLite writer; pending before vault read; signed delivery state before bytes sent. Test process crash at every boundary, uncertain response, restart, reboot, duplicate receipt, cancellation and rotation-required. Use a separate Host-signed installation receipt only *after* root-control's independently attested private FD installation.
7. **Cross-owner producer/consumer contract:** box-control/root-control must verify canonical `zog-credential-delivery-envelope-v1`, write only to a protected anonymous FD and invoke `issuer_credentials.install_from_fd`. host-deploy follows separately after successful receiver tests. Receipt does not authorize Certbot, DNS-01, ACME or nginx reload.

**Output requested from native Work:** exact Host and installed source/RECORD identities, independent approval/pin fingerprints and their verified origin (not private key bytes), root/grant/authorization/assignment/revision hashes, socket/UID isolation checks, migration and restart/reboot receipts, synthetic signed message hashes, source-only vs installed-byte discrepancy list and explicit **GO/NO-GO** for any later *separately authorized* live activation.

**Current disposition: NO-GO for real credential delivery and native activation until every above gate passes.**
