# Command-Center HTTPS Credential Authority — producer v1

**2026-10-29 decision:** port 443 authenticated HTTPS replaces the SSH forced-command proposal. The prior SSH design must not be activated. This is a source contract, not permission to export a real Cloudflare token. Retain PR #8's managed-dns01 hostname approval, signed certificate assignment, current Host enrollment, local protected Cloudflare vault reader, root authorization projection and revocation checks.

## Trust boundaries

**Command-Center Host** means the explicitly approved control/credential authority installation. **Enrolled Host** means an independently approved HostIdentity and installation/STATE, not merely any host sending a beacon. **Receiving consumer** is the separate, approved certify-manage root-owned issuer instance on that exact Enrolled Host. These are three distinct authorization checks. The Command-Center origin/signer expectation must be established independently, not exported from the candidate being reviewed.

The dedicated non-root WSGI process zog.station_access.credential_https_ingress_app behind the existing nginx HTTPS reverse proxy handles only POST /.well-known/zog/credential-delivery/v1. It must have no Django settings, vault keys, DB privilege, root UID or browser session; isolate the process and its private nginx Unix listener. The existing Django /api, noVNC and beacon routes are not credential endpoints. Suppress ingress/proxy request and response bodies, error templates, disk buffering and debug logs. The ingress contacts a root-controlled broker on an independent local AF_UNIX socket, verifies kernel SO_PEERCRED UID=0 and receives only a specifically approved response. The protected broker re-verifies client signatures and grants; its own listener enforces the single approved dedicated ingress UID. It calls the existing local vault reader via a second socket with a separate nonce. That vault process still requires root SO_PEERCRED, separate vault execution identity and protected 0440 projection.

## Wire contract (exact v1)

URL: POST https://<independently trusted Command-Center origin>/.well-known/zog/credential-delivery/v1, TLS over 443, no redirect, query or fragment. Never build signature origin from caller-supplied Host or forwarded headers. No cookie or browser Authorization headers.

Authentication: existing zog.host_identify.signatures RFC 9421 Ed25519 zog-host-v1; exact components @method, @authority, @target-uri, content-type, content-digest, x-host-id, x-host-key and @signature-params. Content-Type application/json, Content-Digest, Signature, Signature-Input, X-Host-Id and X-Host-Key. Existing 120-second signature lifetime plus skew; signed nonce recorded in existing persistent ReplayRecord. HTTP TLS authenticates the Command-Center HTTPS origin, and the signed message authenticates the approved HostIdentity; neither alone is permission to retrieve a credential.

Body: strict UTF-8 JSON, 1–2048 bytes, no duplicate fields, nonfinite numbers or extras, with exactly these typed fields:

- schema = zog-credential-delivery-request-v1
- purpose = issuer-cloudflare-dns01 (ONLY enabled v1 purpose; admin, archive and arbitrary types rejected)
- host_id, installation_id, state_volume_id, assignment_id = lowercase canonical UUID strings
- registry_id = current approved registry identifier
- consumer = certify-manage
- destination = issuer-dns-cloudflare
- authorization_id = SHA-256 lowercase 64-hex digest of protected root issuer authorization
- assignment_revision, credential_revision = positive integers (not bool)
- nonce = fresh 128-bit random value encoded as lowercase 32-hex, unique per operation

Result after independent native activation: HTTP 200 application/octet-stream with only the 20–4096-byte ASCII Cloudflare token. Denied requests return empty uniform 403 with no diagnostics, token hash, URL, private credential detail or browser-readable secret. No-store/no-cache, nosniff and no-referrer. The unprivileged ingress handles only that one approved secret transiently; it never obtains arbitrary vault read ability.

Ingress→broker frame: one newline-terminated strict JSON object schema=zog-credential-delivery-ingress-v1, body=the original exact signed request text, headers=exact six signed/proof headers; maximum 4096 bytes and one operation per private connection. The broker re-verifies the original raw body and signature against the configured independent HTTPS origin, current approved HostIdentity and enrolled ManagedAdmission. It does not trust ingress headers as an authorization decision.

## Root operator authority and durable history

A separate native installer must provision (never auto-generate) four protected files under preexisting, root-controlled directories:

1. HOST_CREDENTIAL_HTTPS_AUTHORITY_FILE (root:root 0600): exact schema zog-command-center-credential-authority-grant-v1 with state=approved; purpose, consumer, destination, host_id, fingerprint, installation_id, state_volume_id, authority_id, registry_id, assignment_id, assignment_revision, credential_revision, authorization_id, grant_id, storage_id, operator_approval_sha256, independent_signer_pin_sha256, revision and expires_at. No wildcards, caller-selected paths or shared credential inventory.
2. HOST_CREDENTIAL_HTTPS_OPERATOR_PIN_FILE (root:root 0444): independently approved raw 32-byte Ed25519 operator public key. The candidate station signer cannot approve itself.
3. HOST_CREDENTIAL_HTTPS_OPERATOR_APPROVAL_FILE (root:root 0600): exact schema zog-credential-delivery-operator-approval-v1 with grant_sha256 and canonical base64 Ed25519 signature. Sign domain prefix zog-credential-delivery-operator-approval-v1 followed by NUL and canonical JSON bytes of grant with operator_approval_sha256 removed. grant_sha256 must match those bytes; the canonical approval receipt SHA-256 must equal grant.operator_approval_sha256. Never infer the trusted operator pin from this candidate approval.
4. HOST_CREDENTIAL_HTTPS_SIGNER_PIN_FILE (root:root 0444): independently authenticated Command-Center certificate-assignment signer pin; SHA-256 must match grant.independent_signer_pin_sha256. Keep it separate from HostIdentity and the operator approval key.

The retained root-controlled HOST_ISSUER_CREDENTIAL_AUTHORIZATION_FILE (0440) remains authoritative for exact root project, installed certificate policy, assignment/revision, credential/revision, zone/grant/storage and account owner. The current live managed-dns01 hostname grant and exact approved Cloudflare credential are checked through existing issuer_cloudflare_reader._assignment and its selected() path before any token read. Enrollment or an inspect-only managed session is never an automatic operator grant.

Before decrypt, the protected broker holds the shared station SecurityGate to atomically consume the HTTPS operation nonce, signed-message replay nonce and persist the highest operator grant/credential revision. HttpsCredentialDeliveryNonce records 48-hour nonsecret nonces; HttpsCredentialDeliveryRevision records per-Host maximum revision plus digest and rejects rollback or same-revision substitution. Capacity exhaustion fails closed; reboots preserve these STATE-backed tables and previous issuer vault reader nonce history. On loss of response, no replay: initiate a new independently signed request. After vault read, recheck exact root grant, approval/pin, current enrollment, policy, signed assignment and current credential revision before writing the response. Audit uses purpose, Host/assignment IDs and revisions only; never password, token or token digest.

## Native activation and owner handoff

Default code status: broker setting HOST_CREDENTIAL_HTTPS_BROKER_ENABLED=False, live release HOST_HTTPS_CREDENTIAL_LIVE_ENABLED=False and ingress variable ZOG_CREDENTIAL_HTTPS_INGRESS_ENABLED unset. No nginx route, systemd service, root approval, private key, source pin or Host state is installed by this source PR.

host-identify: reuse existing Ed25519 HTTP signer, verify exact HTTPS TLS origin, bind genuine approved Host key + operation nonce separately, preserve independently supplied command-center signing pin; do not broaden beacon content.

host-install: verify exact installed root broker/ingress/protocol source and RECORD, native nginx route/socket/UID isolation, independently installed operator and station signer pins, current Host/installation/STATE and monotonic consumer policy, durable receiver receipt, crash/reboot and cancel behavior; credential response must go only to an approved root-controlled local private file descriptor.

certify-manage: accept only purpose issuer-cloudflare-dns01 and destination issuer-dns-cloudflare. Compare selected issuer grant/storage, signed certificate assignment and exact credential revision before and after private reception. Never emit token in logs, argv/env, browser, SSM, Django, journal or CI; no Certbot execution, DNS-01 TXT write, ACME authorization or nginx reload follows merely from an HTTP response.

Native tests must reject stale/foreign signer, HostIdentity, project/STATE/install/registry, wrong consumer/destination, revoked certificate/hostname/credential, expired grant/managed session, invalid HTTP signature, wrong TLS origin, replay, rollback, partial response, path/UID substitution and reboot ledger loss. Keep the protected command-center operator and receiving installation distinct. Explicit owner approval is required before first real release. No Cloudflare token is exported in this source pass.
