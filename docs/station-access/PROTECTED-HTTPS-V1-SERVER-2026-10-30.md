# Protected HTTPS credential producer + durable ledger (canonical v1)

**Status 2026-10-30:** source candidate, draft PR #11 stacked on PR #10 and PR #9. No native activation, token export or endpoint installation has been authorized. This source does not enable any listener.

## Canonical protocol — exact source pin

Use **host-identify 0.3.5** source commit `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`, `zog.host_identify.credential_delivery`. Do **not** alias PR #9's raw token/32-hex-nonce draft, root-control's custom `zog-protected-*` response or host-deploy's custom receipt. A separate accepted companion-pin migration is needed before installed use.

The v1 HTTP paths (requiring receiver owner agreement) are POST to:
- `/.well-known/zog/credential-delivery/v1`: Host RFC9421 signed canonical `zog-credential-request-v1` → independent Credential-Authority-signed JSON `zog-credential-delivery-envelope-v1`.
- `/.well-known/zog/credential-delivery/v1/receipt`: Host-signed, **secret-free** `zog-credential-installation-receipt-v1` → empty 204 after durable receipt admission.
- `/.well-known/zog/credential-delivery/v1/cancel`: Host-signed `zog-credential-cancel-v1` → empty 204 after durable cancellation.

Failures return indistinguishable empty 403, no redirect, policy message, secret-bearing response or diagnostic. Proxies must suppress body access/error logs, response buffering to disk, caching, compression and retained headers. The HTTPS origin is independently installed and exact: no user-supplied Host/X-Forwarded-* claim becomes signature authority.

## Process and data separation

`credential_v1_wsgi:application` is **not** the Django web router. It runs under a dedicated nonroot UID, without Django settings, DB permissions, vault mounts, operator/signing keys or root access, on a private nginx Unix listener. It validates fixed route, method, scheme, length and signed message headers before relaying original bytes through a separate protected AF_UNIX socket. It handles only a bounded signed response transiently, never arbitrary vault inventory. Browser logins, beacons, /api, noVNC, cookies and Authorization headers never authorize delivery.

`serve_credential_v1_broker` is a root-only, systemd-fd-3 socket-activated process. It validates real AF_UNIX listening socket type, exact bound path, root-owned socket pathname and protected root-owned parents, and kernel `SO_PEERCRED` against one designated ingress UID. **Linux sockfs FD and path inodes are deliberately not compared**. The broker has one fixed frame and returns either a signed JSON body or a short acknowledgement; failures emit no diagnostics on the socket. Neither program provisions nginx, root socket or an enabled service.

`credential_v1_authority` reads the **separately operator-approved** 0600 root grant from PR #9, independently pinned signer and root-owned 0600 canonical authorization envelope. The authorizer must pin the exact HostIdentity fingerprint, enrolled Host UUID, installation, STATE, registry, consumer `certify-manage`, purpose `issuer-cloudflare-dns01`, Cloudflare credential UUID/revision, grant revision and expiry. It rechecks current signed certificate assignment, protected root projection, original vault-reader authorization SHA-256 and genuine `managed-dns01` hostname/zone selection. It does not infer root approval from a station candidate signer or beacon alone. Only the original root-to-vault AF_UNIX protected token reader can produce the selected credential. The shared canonical authorization UUID is distinct from the older issuer authorization policy SHA-256; **never coerce one into the other**.

The canonical signing key file (`HOST_CREDENTIAL_V1_SIGNING_KEY_FILE`, 0600) must be independently provisioned with a pinned 32-byte Ed25519 public key via the existing protected station signer-pin/grant acceptance ceremony. If the retained older pin is not a raw compatible Ed25519 key, native installation must review and prepare an explicitly reapproved signer/grant transition. Do not overwrite an existing independently trusted certificate signer or invent a new pin from the candidate itself.

## Durable SQL state, crash and replay

Migration `host_registry.0019_credentialv1ledger` introduces `HttpsCredentialV1Ledger` (one nonsecret canonical shared state per Host/consumer/purpose/credential) and `HttpsCredentialV1Operation` (one UUID request and minimal signed delivery correlation). Neither may store plaintext/base64 token or a reusable secret digest. The original `SecurityGate` SQLite writer and `ReplayRecord` provide **one atomic transaction** for Host RFC9421 nonce consumption, request admission, cancellation or installation receipts. `host-identify` canonical `new_ledger/advance_authorization/admit_request/record_delivery/record_installation/record_cancel` are the only state machine.

A request is committed as pending **before** attempting local vault read. A signed delivery is committed as delivered **before** any outbound secret response. If the response is lost, old request ID or HTTP signature nonce must not be replayed. Delivered without a Host-signed root installation receipt remains unresolved and blocks another delivery. Signed cancellation of an already-delivered response sets `rotation_required=true` and prevents same-revision redelivery. Root operator revocation can be durably reconciled using `reconcile_credential_v1_authorization --expected-envelope-sha256 <digest> --commit`; default is review-only and no secret is read. Preserve original ledger across restart/reboot; never reset it to recover from an uncertain response.

**Source enablement is deliberately false** in Django settings (`HOST_CREDENTIAL_V1_BROKER_ENABLED=False`, `HOST_CREDENTIAL_V1_LIVE_ENABLED=False`) and `ZOG_CREDENTIAL_V1_HTTPS_INGRESS_ENABLED` is unset. The old PR #9 raw-token ingress remains independently disabled. No source-only approval means a live flag may be enabled.

## Required gates and cross-owner acceptance

1. Independent native operator approves exact Command-Center Host/source/wheel RECORD, original signed/root grant, independently supplied signer key/pin and authorization UUID/revision, selected station and issuer. Do not derive trust from the candidate station signer.
2. Test nginx HTTPS peer authentication, exact path and proxy mode, Unix listener ownership/mode and peer UID, root grant/source/path race protections, missing/foreign signer and consumer, rejected browser and generic administrator/archive purpose, root/STATE/credential revision drift and concurrent send/revoke cases.
3. Native SQLite persistence, migration and recovery after service restart and machine reboot, duplicate signature and request IDs, delivery-before-response crash, lost response with unreceipted secret, cancellation/rotation, receipt after revocation and authorization revision rollback.
4. box-control/root-control native receiver verifies the **same v1** signed envelope, uses a protected anonymous FD to `issuer_credentials.install_from_fd`, returns a signed, secret-free receipt **only after durable installation**, and tests adverse delivery interruption.
5. host-deploy then adapts its separate owner-policy/NGINX ledger to the canonical contract; no Certbot, Cloudflare DNS, ACME or nginx reload is initiated merely by receipt.

**CI is source-only**, with no real Cloudflare token. Even all-green source CI is not native GO.
