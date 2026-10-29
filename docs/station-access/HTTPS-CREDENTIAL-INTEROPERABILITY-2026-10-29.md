# Canonical HTTPS credential delivery interoperability — station-access source handoff

Status: reviewed source **NO-GO**; no credential sent, no listener enabled.

**Single protocol owner:** host-identify `zog.host_identify.credential_delivery` v1 (0.3.5, source `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`). The station-access PR #9 experimental request, reply and replay protocol MUST NOT be treated as equivalent.

## Canonical v1 — required messages

1. `zog-credential-authorization-v1`, signed with `zog-credential-authorization-envelope-v1` by the independently pinned Credential Authority signing key. Bind exact Host UUID, approved HostIdentity fingerprint, installation, STATE, registry, consumer, purpose, credential ID, credential revision, authorization UUID, monotonic authorization revision, approval, state, expiry and revocation. The root-only operator approval remains a separate prerequisite for issuance of this signed authority.
2. `zog-credential-request-v1`, a HostIdentity RFC9421 signed POST. Its UUID `request_id`, `action=deliver|renew`, previous delivery ID, creation and expiry are validated against the current independently signed authorization. Consumer and purpose are fixed to `certify-manage` and `issuer-cloudflare-dns01` for the only initially approved profile. Signature nonce must be durably consumed separately from the shared request-state ledger.
3. `zog-credential-delivery-envelope-v1`, **Credential Authority Ed25519 signed** envelope containing `zog-credential-delivery-v1` with request/delivery UUIDs, authorization ID/revision, credential ID/revision, consumer, purpose, issue/expiry and bounded base64 secret. Delivery is NOT installation. Persist `record_delivery` before transmitting the response; never persist the secret/base64 or a reusable digest in the ledger. 16-KiB secret upper bound is shared-protocol maximum; the Cloudflare-specific reader retains its narrower token restrictions.
4. `zog-credential-installation-receipt-v1`, HostIdentity RFC9421 signed, secret-free, only after root-owned private-FD installation and durable installed-byte/state checks. Bind request and delivery UUIDs, receipt UUID, current Host/installation/STATE/registry, consumer, purpose, authorization and credential revision, installed_at. Verify signature and `record_installation` with nonsecret durable state.
5. `zog-credential-cancel-v1`, HostIdentity RFC9421 signed. Pending cancellation is terminal without exposure; cancellation after delivery forces rotation and blocks same-revision redelivery. No receipt cannot be read as installation success.

The shared `zog-credential-delivery-ledger-v1` implements `new_ledger`, `advance_authorization`, `admit_request`, `record_delivery`, `record_installation`, `record_cancel`. These transitions and their duplicate/rollback rules are authoritative. The station database must durably serialize ledger write and HTTP-signature nonce consumption under its original protected security lock, including across process restart and reboot; do not start a second insecure state machine.

### Fixed HTTP framing and error behavior for owner review

Proposed fixed canonical paths on the independently pinned Command-Center HTTPS origin:
- POST `/.well-known/zog/credential-delivery/v1`: signed request → signed delivery envelope, application/json (never raw token);
- POST `/.well-known/zog/credential-delivery/v1/receipt`: signed secret-free receipt → empty 204 only after durable install receipt verification;
- POST `/.well-known/zog/credential-delivery/v1/cancel`: signed cancel → empty 204 only after durable cancellation.

These **path choices still require receiver-owner acceptance** because the host-identify pure protocol does not prescribe URLs. No aliases to the old root-control `/api/hosts/credential-delivery/v1/receive/` may be enabled. The exact URL including path participates in the RFC9421 signature, so this must be settled before any native work.

All failure responses: uniform empty 403 (or 503 only for an independently agreed upstream outage that cannot reveal authorization state), no redirect, exception, token metadata, HTML/JSON diagnostic or caller-controlled path. An uncertain delivery after network failure is recorded as delivered/rotation-required rather than repeated. Native HTTP proxy logging, buffering, caches and compression must not store secrets. Do not overinterpret source CI as evidence of these controls.

## Identified incompatibilities — replacements, not aliases

| Component | Current draft | Required shared v1 |
|---|---|---|
| station-access PR #9 | `zog-credential-delivery-request-v1`, 32-hex nonce, extra consumer signature, no authorization envelope | `zog-credential-request-v1`, UUID request, current separately signed authorization, Host RFC9421 authentication |
| station-access response | unauthenticated raw token octet stream | independently authority-signed `zog-credential-delivery-envelope-v1`, bounded base64 |
| station-access replay | 48-hour nonce + highest revision tables only | full shared nonsecret ledger, durable pending/delivered/installed/cancelled history and signature-nonce ledger |
| root-control PR #16 | `zog-protected-credential-delivery-v1` and `zog-protected-credential-response-v1`, custom signature domain | identical host-identify v1 request, authority envelope, delivery signature and installation/cancellation receipt |
| host-deploy PR #6 | `zog-protected-credential-delivery-request-v1` and `zog-protected-credential-delivery-receipt-v1` | nonsecret owner-policy adapter to canonical request, signed delivery and signed installation receipt |
| HTTP limits | station max 2 KiB request / 4 KiB token | common 64-KiB message / 16-KiB secret maxima (profile may narrow, never widen) |

For Cloudflare producer: retain PR #8 `managed_dns01_hostname.selected()`, current Host enrollment, approved certificate assignment, root-only vault reader, exact owner, Cloudflare zone/revision, original protected broker/Unix peer and independently authenticated signer/operator pins. These determine **whether** a purpose-specific authorization may be signed and which source may be read; they are NOT new wire schemas.

For station-access PR #9: its legacy network ingress and raw-token response **must stay disabled**. Remove it from any prospective nginx/service activation before adopting the canonical server. Do not enable both experimental and canonical formats.

## Test vectors / cross-owner acceptance

Tests must use deterministic fixture identities, Ed25519 keys, timestamps and nonsecret synthetic values. Validate exact canonical JSON bytes, independent authority signature, Host RFC9421 request, delivery signature, secret-free installation receipt, cancellation, revocation and state after interrupted delivery. Reject wrong Host/installation/STATE/registry, key/purpose/consumer, changed authorization or credential revision, duplicate operation, unsigned delivery, changed token after signing, receipt before install, cancellation after delivery without rotation, and HTTP redirects.

Consumer owners should first run their fixture suite against the **identical** host-identify v1 source pin and fixtures; no native install or credential export until full producer/consumer matrix passes, then protect and attest final installed wheels and their RECORDs.

**Companion-pin isolation:** the long-lived public source manifest intentionally still pins pre-0.3.5 host-identify. Run the above test from its separate pinned v1 workflow, not as part of the legacy Django test package. Acceptance of the newer companion pin and its installed source rights remains an independent migration gate.
