# Signed host protocol, version 1

Machine authentication is deployed through the maintained host-install/host-discover flow; unpacking station-access source is not a deployment action. Historical bearer-token migration requires a separately reviewed staged procedure; it is not a current source-installation or automatic credential-conversion path. User browser authentication and CSRF protection remain unchanged.

## Trust boundaries

HTTPS authenticates the command center and protects responses. Host Ed25519 signatures prove possession of an individual private key. Administrator approval binds that exact public key to an immutable Host UUID. Neither a key fingerprint alone nor claimed AWS attributes establishes permission. Separately controlled archive policy grants operations on named collections.

`host-identify` is a shared Python package. It uses pyauth/http-message-signatures 2.x for RFC 9421 canonicalization/signature processing, cryptography Ed25519, and PyJWT for archive access tokens. This is a narrow application profile, not a custom signature algorithm. The historical tested package versions must be pinned to the selected source/requirements and corresponding verification evidence; this page does not substitute for their present compatibility checks.

Primary references:
- https://github.com/pyauth/http-message-signatures
- https://www.rfc-editor.org/rfc/rfc9421.html
- https://pyjwt.readthedocs.io/en/stable/usage.html

## Dedicated host key and fingerprint

A host creates its key locally on first use under `/var/lib/host-discover/identity/identity.pem`. Directory 0700, file 0600, owned by host-discover. It is separate from TLS keys, archive access signing keys, and future root filesystem release-signing keys. SHA-256 of the raw 32-byte Ed25519 public key, represented as 64 lowercase hex characters, is the fingerprint and RFC 9421 keyid. The enrollment public_key is canonical base64 of those 32 bytes.

Creation is protected by a local file lock, atomic replacement, file fsync, and directory fsync. Ordinary restarts and reinstalls preserve the directory. Never bake this state, its binding.json, or archive credentials into images. `tools/check-image-identities.py ROOTFS` is an image publication gate for the documented paths; image builders must also exclude any operator-configured alternate state paths.

## Exact HTTP signature profile

One signature, label `host`, tag `zog-host-v1`, algorithm `ed25519`. Covered components must be exactly:

    "@method" "@authority" "@target-uri" "content-type" "content-digest" "x-host-id" "x-host-key"

Required signature parameters: created, expires, nonce, keyid, alg, tag. Unknown parameters or component parameters are rejected. Lifetime is positive and at most 120 seconds. Maximum signature age is 120 seconds; clock tolerance is 5 seconds. Nonce is 22–64 URL-safe base64 characters; the daemon generates 24 random bytes. No timestamps supplied by the host are used as the received time.

Content-Type must be application/json. Content-Digest must be the single SHA-256 digest of the actual transmitted body, in `sha-256=:base64:` form. The application independently computes and compares this digest: RFC 9421 library verification alone does not validate the body. JSON is serialized once, then those exact bytes are signed and sent. Server rejects bodies over 16 KiB, queries, redirects, and the wrong external authority.

Replay records contain fingerprint, nonce, and acceptance expiry, with a database unique constraint. Retention ends only after signature expiry plus tolerance. Cleanup occurs on requests and can run via `prune_host_security`. The global cap is 10,000 records; capacity failure denies requests rather than dropping live replay records. Replay protection requires the same durable database for every worker; do not use per-process caches. Restoring an old DB snapshot can restore old replay state: isolate signed ingress for at least 125 seconds before resuming after such a rollback.

## Proxy reconstruction

Set HOST_IDENTITY_ORIGIN to one canonical external HTTPS origin, e.g. the reserved non-deployable example origin `https://registry.example.org`. The request Host must equal that authority. The external target URI is this configured origin plus the exact Django request path. No X-Forwarded-* input participates in reconstruction. nginx must preserve Host and route these paths unchanged over a private/loopback upstream. Do not allow public access to the Django upstream. Signed endpoints accept only POST, fixed enrollment or UUID heartbeat paths, and no query string. Encoded/re-written paths are not supported.

The AWS hostname can continue serving the browser UI, but signed clients use the canonical origin. TLS certificate validation remains enabled; custom CA trust is optional. Both urllib transport and enrollment reject redirects. The client never changes destination based on a response.

## Enrollment

POST /api/hosts/enrollment/ with:

    {"public_key":"<base64 raw key>","claimed_host_id":"<UUID or empty>","report":{"version":1,"hostname":"example"}}

The request is signed with the submitted key; x-host-key and keyid must equal its fingerprint. x-host-id is claimed_host_id when present, otherwise `pending`. Reported cloud attributes use the existing heartbeat schema; every claim is untrusted.

A new valid request receives HTTP 202 and `{status:"pending",fingerprint:...}`. It does not create a Host or grant DNS/archive access. Pending records are immutable snapshots, deduplicated by fingerprint, expire after 24 hours, and never extend expiry on polling. A maximum of 1,000 pending/rejected entries is retained. Rejection is retained for 30 days; after expiry the key can request approval again, never automatically obtain it. Revoked approved-key records remain durable and are not silently reusable.

Before cryptographic work, database rate counters enforce 60 enrollment requests/minute globally and 10/minute per REMOTE_ADDR. Behind a reverse proxy, REMOTE_ADDR is conservatively the proxy address: this intentionally shares a limit unless the deployment implements a separate trusted address mechanism. Arbitrary X-Forwarded-For is ignored. Counter rows expire after one minute and are bounded by the global admission rate. Configure nginx machine-endpoint rate limits as well. Capacity rejection returns 429; retries may wait 60 seconds. Regular signed heartbeats are not enrollment polling.

Administrator UI: `/host-identities`. Compare the full fingerprint via SSM/another trusted deployment channel, paste it into the confirmation field, explicitly choose an existing host or a new generic host, and approve. Approval records actor ID/username and timestamp. For AWS, explicitly select its inventory record. A claimed UUID, matching IP, or instance ID never selects it automatically. New generic records cannot accept claimed AWS identities until correctly bound through an administrative workflow; choose the existing AWS record at approval.

An authenticated retry with an approved key receives `{status:"approved",host_id:...,fingerprint:...}`. No archive token is sent by enrollment. The daemon persists its assigned UUID and fingerprint in private binding.json, then uses signed heartbeats. A replacement key returns to pending; it cannot overwrite the old binding until approval. Revoke the current key explicitly before approving a replacement against the same UUID.

Rejection/revocation endpoints are session-authenticated superuser-only POST actions with CSRF protection. Policy changes are separate audited actions. `/api/hosts/identities/` exposes public fingerprints/claims/status/audit only; never credentials or private keys.

## Signed heartbeats and commit ordering

POST /api/hosts/<uuid>/heartbeat/ uses x-host-id = UUID and x-host-key/keyid = approved fingerprint. The report schema remains version 1. Correct signature, active approval, matching UUID, freshness, unused nonce, and existing report validation are all required.

A singleton database write lock serializes security changes across workers. Signature verification happens outside the lock; active key/host binding and expiry are checked again after acquiring it. Replay insertion, policy read, token issuance, and report timestamp update commit together. Approval/revocation/policy updates take the same lock. SQLite storage errors return failure; PostgreSQL also uses this row update lock, though this release's concurrency tests run on SQLite only. Large-fleet throughput is not claimed: a single authority and a bounded worker pool are intentional for this first release.

A heartbeat that commits before revocation may already have issued a token, even if its response arrives later. A revocation that commits first prevents issuance. This is serialized authorization, not instantaneous cancellation of in-flight network responses.

Success: HTTP 200, Cache-Control: no-store, schema version 2, host_id, received_at, archive. `archive:null` explicitly withdraws local archive authorization. All signature/token processing errors are sanitized; request or response credentials must not be logged by middleware/proxies/APM.
