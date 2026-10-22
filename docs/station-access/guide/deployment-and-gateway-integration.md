# Deployment and gateway integration

## Separate the public portal from the deployment owner

Station-access presents browser workflows and reads authorized controller/project state; it does not automatically become the owner of EC2, DNS, image-build artifacts, host-discover credentials or a compiler workspace. **host-deploy** remains the owner of provisioning and authenticated compiler dispatch. **image-build** constructs immutable software; **box-control** launches it as configured program services. Source installation and a passing CI job do not replace an already running production station.

The [bounded deployment jobs](../DEPLOYMENT-JOBS.md) distinguish saved desired registry destinations, explicit read-only host inspection, a time-limited review, confirmed application and later signed host acceptance. A successful SSM job means only that its narrowly scoped operation completed; it is not evidence of enrollment approval or external network reachability. The page does not run arbitrary shell or install/update entire hosts.

## Durable application and archive ownership

Production state is not one generic writable volume. The [production composition and migration design](../PRODUCTION-STATE-MIGRATION.md) separates station-access (`web`, its SQLite database, secrets and historical station state) from archive-mirror (`server`, `refresh-scheduler`, its catalogue/object store). **Two independent box-control persistent application identities** must own their writable STATE volumes; separate mount names in one application do not provide independent ownership.

Immutable Python/Django dependencies, frontend bundles and notices are staged by image-build into read-only software artifacts/views; databases and vault keys remain durable mutable state. The deployment owner must bind the exact new application/view identities, preserve historical records through frozen checkpoint migration, confirm a single writable owner and independently verify archive integrity.

The source migration tool is not an implicit live migrator. It must operate on an operator-frozen source and leave rollback checkpoints intact. Never mount the old live writer and replacement against the same mutable database/store.

## Host-directory capability versus arbitrary host access

Host-discover renews mirror role/lease intent by atomically replacing files. Consumers must be granted the **parent export directory**, not a stale single-file inode. The host binding policy is root-owned, exact-project/application/program scoped, read-only and independently checked at the root-control boundary. An application cannot nominate arbitrary host paths or treat a broad `/run` bind as an authorized shortcut.

The newer production composition restricts the `mirror-live` capability to the archive-mirror server and scheduler; station-access web does not need the grant. Do not copy leased host-discover credentials into application source or writable store. The [older cutover handoff](../STATION-PRODUCTION-CUTOVER.md) described an intermediate scheduler-only binding; the later [separate archive application composition](../PRODUCTION-STATE-MIGRATION.md) supersedes that **design shape**, while independently accepted production state still needs live verification.

## Authenticated compiler observations

The old `compiler_gateway:create_gateway` adapter cannot regain direct control over the already adopted host-deploy workspace. A modern bridge should use host-deploy's **authenticated owner service** with pinned workspace and ownership epoch, constrained server identity, transport security and explicit method scopes. An observation caller must not gain the ability to prepare or submit builds merely by being able to read compiler status.

The owner RPC candidate is documented in the host-deploy repository's [compiler owner RPC](https://github.com/zog144/host-deploy/blob/24be4cd3488ace40488256c3ea4a9cf4408b3130/docs/host-deploy/guide/compiler-owner-rpc.md). It is a source candidate, not proof of live service activation. Station's application network namespace must reach the owner over a deliberately routed endpoint; its `localhost` is not the host's loopback. Owner-ledger evidence is different from live EC2/SSM evidence.

## Controlled production cutover

A release-quality cutover requires explicit acceptance of all of these independent obligations:

1. Reviewed immutable application software and native runtime facilities actually mounted read-only.
2. Separately owned, durable station and archive data, with exact checkpoint hashes, single-writer fencing and rehearsed rollback.
3. Renewing, narrowly scoped host-discover mirror intent available within the target namespace and validated across rotations.
4. Authenticated compiler/owner observation where required, without bypassing host-deploy's adopted ownership epoch.
5. Verified startup, restart and reboot management and exact mount identities.
6. Preserved nginx, TLS, DNS, backups and incumbent services until the new candidate passes isolated acceptance and deliberate cutover authorization.

The [production cutover checklist](../STATION-PRODUCTION-CUTOVER.md) and [state migration handoff](../PRODUCTION-STATE-MIGRATION.md) are acceptance references, **not** permission to swap traffic. Some source handoff details are dated; use current host-deploy owner evidence for the final decision.

## Other integration contracts

- [Image-build Workspace/VNC runtime dependencies](../integration/IMAGE-BUILD.md)
- [Signed host enrollment and heartbeat](../SIGNED-HOST-PROTOCOL.md)
- [Archive issuer and verifier](../ARCHIVE-AUTHORIZATION.md)
- [Archive inventory API](../ARCHIVES-API.md)
- [Mirror role and lease lifecycle](../MIRROR-STARTUP-CONTRACT.md)
- [Deployment job protocol](../DEPLOYMENT-JOBS.md)

**Acceptance rule:** no documentation change, synthetic source test or candidate packaging result is evidence that a live host's port 443 routing was changed safely.
