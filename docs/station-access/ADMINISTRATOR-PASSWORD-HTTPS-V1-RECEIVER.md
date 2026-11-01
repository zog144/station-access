# Protected station-access administrator password reception — source contract v1

**Status:** source-only, disabled by default. This draft is not live credential provisioning. Related work: station-access #15, host-install #2, station-access PR #12 canonical HTTPS candidate chain, and host-identify 0.3.5.

## Boundary and current user workflow

The public `/api/users/` browser endpoint remains administrator-session/CSRF authenticated. `host_registry.user_views.save` already uses `SecurityGate`, `validate_password`, `set_password`, `revoke` and secret-free `SecurityAudit`; password changes invalidate database sessions and unused VNC grants. They do **not** terminate an already connected noVNC WebSocket. The local `FIRST-LOGIN.txt` or `export_station_login` source is a protected **previously retained plaintext** credential only when it remains current and authorized. Django hashes cannot be reversed to obtain a password, and changing an account does not rewrite or silently export FIRST-LOGIN credentials.

The new `host_registry.administrator_credential_receiver.install` is **not mounted as an API, Django view, login endpoint or beacon handler**. The caller must be an independently admitted local installer/broker, not a browser or enrollment process. The receiver checks:
- Source-hard-disabled `HOST_ADMIN_PASSWORD_V1_RECEIVER_ENABLED=False` and an exact dedicated **nonroot UID** (`HOST_ADMIN_PASSWORD_V1_RECEIVER_UID=None` by default). Those flags are test-only on this branch; native permission to change them is separate.
- Independently installed 32-byte operator Ed25519 and producer Credential Authority public pins, different keys, each matching a root-owner attested SHA-256. No selected candidate proves its own trust origin.
- An exact canonical JSON `zog-station-admin-password-approval-v1` signed under domain `schema + NUL + canonical(unsigned_approval)`. This operator policy selects a single account ID + username + current opaque account revision, exact destination Host/fingerprint/installation/STATE/registry, `station-access` consumer, `station-access-administrator-password` purpose, fixed credential ID `station-admin`, credential and authorization revision, signed producer-authorization envelope SHA-256, signer fingerprint and expiry. The current account must still be active staff/superuser and its revision must match *inside* the Django SecurityGate write transaction. Browser rights or a signed beacon never substitute for the approval.
- Signed canonical host-identify `zog-credential-authorization-envelope-v1`, exact RFC9421 Host-signed `POST /.well-known/zog/credential-delivery/v1` request and Credential Authority-signed `zog-credential-delivery-envelope-v1`, including matching exact destination/revision/nonce/request/delivery IDs, approved action and short expiry. Unsupported purposes/actions fail closed.
- A **read-only sealed anonymous Linux memfd** passed through a separately verified local FD transfer. The FD must be a zero-link regular file, read-only and carry all four Linux write/grow/shrink/seal seals. Its bounded UTF-8 bytes must exactly match the previously verified signed HTTPS delivery. No password is supplied as argv, environment or browser JSON. No password or base64 encoding enters DB, receipts or logs. The independent host-install/root-control owner still must implement and attest transport **SCM_RIGHTS** provenance, socket/process UID/cgroup, secure FD transfer and receipt signing: this Django method is not proof of those native controls.

## Durable mutation and receipt

Django migration `host_registry.0020_administratorpasswordreception` creates a protected, secret-free historical record per delivery, with unique `request_id`, `delivery_id` and account/credential revision. The account is protected from deletion while a record remains, preventing replay history loss. The same `identity.locked()` transaction performs original-account/revision/role recheck, signed HTTP nonce consumption, Django password validation and hashing, database-session and unused VNC-grant revocation, protected history insertion and audit. If any step raises before transaction commit, all database changes roll back.

The method returns only a `zog-station-admin-password-protected-commit-v1` result with the exact request ID, delivery ID, authorization ID, revision, selected account ID and commit timestamp, marked `committed-awaiting-host-signed-receipt`. **It does not sign the host receipt.** Only the independently installed host-identify/host-install receiver may construct and send the canonical Host-signed `zog-credential-installation-receipt-v1`, *after* confirming this durable result with exact request, delivery and destination. On uncertain response, the same protected UID may inspect that record using the request ID; it must not reapply an already committed request or roll back its credential high-water. Producer rotation/authorization revocation and durable ledger are independent native gates. Uncommitted operations can be safely reviewed, not blindly re-delivered.

## Integration owners and gating

**station-access Regular:** source, migration, Django protected mutation, synthetic signed-vector tests, docs and source CI. **host-install Regular:** implement separate canonical HTTPS consumer selection, independent operator policy installation, selected root/installer-to-nonroot receiver FD transfer with FD seal+SCM_RIGHTS+peer proof, durable receiver handoff and Host-signed receipt/cancel protocol. Verify exact Host/installation/STATE and user/account/purpose/credential revisions before calling Django; preserve crash/reboot receipt and idempotency.

**Native Work:** verify installed source and wheel RECORD, source signing and operator key provenance, selected account/revision, root/Django UID isolation and socket ownership, rollback, reboot and caller denial. Then seek separate operator approval before a delivery endpoint or live password transfer. Retained FIRST-LOGIN and station-login files must not be reused as authorization. Do not export Django password hashes or presume they contain a recoverable secret.

**Source tests are synthetic only. No real password transfer, credential authority activation, root installation, browser API exposure, AWS or STATE modification is approved here.**


## Draft root broker ↔ Django local FD handoff (task 4)

The protected local process boundary now has a source-only adapter,
`administrator_fd_broker.install_from_broker` and
`administrator_fd_broker.inspect_from_broker`. **Neither is a URL, enabled
service, task handler or installed privilege.** A separate setting,
`HOST_ADMIN_PASSWORD_V1_FD_BROKER_ENABLED=False`, is hard-disabled alongside
the existing receiver. The installed root broker UID pin is absent by default
(`HOST_ADMIN_PASSWORD_V1_FD_BROKER_UID=None`). Source tests temporarily
override these values; that is not operator authorization.

The independently installed broker must prepare an `AF_UNIX SOCK_SEQPACKET`
connected channel, with both directions' `SO_PASSCRED` enabled **before**
any message may be queued. The receiver binds Linux `SO_PEERCRED`,
per-message `SCM_CREDENTIALS`, the independently pinned PID/UID/GID, PID
start time and exact cgroup, and the exact signed
request/delivery/authorization/revision/account frame. Only one read-only,
anonymous, fully sealed FD is admitted through `SCM_RIGHTS`; extra
descriptors, truncation and foreign peers fail closed. The FD is closed after
Django's existing protected writer attempts the transaction.

After the Django commit, a secret-free commit result is sent back on the same
peer-verified channel. If that response is lost, the *protected original
installer* connects again and sends an exact descriptor-free recovery
operation. Django looks up durable `AdministratorPasswordReception` history
and returns the same committed result, never rehashing a new password nor
replaying the delivery. The host-install owner must compare the returned
metadata with the original signed request/delivery and its durable ledger;
expired historical delivery is **inspection-only**, not a new grant.

Common transport source: [root-control PR #19](https://github.com/zog144/root-control/pull/19).
Installer source: [host-install PR #11](https://github.com/zog144/host-install/pull/11).
A new reviewed, immutable root-control dependency pin, trusted installed
source/wheel, root-managed socket and unit identity, operator authority,
real post-fork peer proof and native rollback/reboot acceptance are all
outstanding. **No live password transfer or Host-signed receipt is approved.**
