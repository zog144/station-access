# Safe archival and enrollment matching — pass 5

Station-access 0.3.2. The bundled host-discover remains 0.3.1 and host-identify remains 0.3.0. No beacon protocol or daemon update is required for these GUI/backend improvements. Migration 0006 adds nullable archive time and archive actor fields; it does not archive, merge or delete any existing record.

## Removing an unwanted record

Open Hosts → Host details and removal. The preview identifies the label, registry UUID, provider/account/region/instance, every approved/revoked key, credential metadata, archive policy, mirror intent/acknowledgement, managed DNS/reservations and pending migration claims. It never returns passwords, tokens, token digests or encrypted credential contents.

“Remove record (archive)” requires confirming the exact registry UUID. The server rechecks a snapshot revision and all dependencies under the shared database security gate. Changed previews return HTTP 409 and require review again. Archival changes only archive time/actor and appends an audit event. No infrastructure calls, DNS deletion, key transfer, credential revocation, mirror shutdown or history deletion occur. Direct deletion through Django's Host admin is disabled.

Archival blocks while any of the following remains:

- An approved key. Explicitly revoke it through Host identities and stop/reconfigure the host's beaconer separately.
- An unrevoked legacy bearer credential. Revoke it explicitly through the existing administrative provisioning controls.
- A stored station-login credential. Withdraw it through the existing signed beacon login-withdrawal workflow before revoking that host's key.
- A nonempty archive grant policy. Withdraw it through Host identities. Revocation cannot invalidate already issued mirror bearer tokens immediately.
- A possible unexpired archive token. Conservatively wait until 15 minutes plus five seconds after the latest recorded authenticated-host receipt or key revocation. This deliberately may delay a host that did not receive a token; it also covers issuance before this release.
- A selected mirror role, or removal that has not acknowledged the current revision as stopped. Deselect it and obtain the stopped acknowledgement before revoking its key. Retained archives are not deleted.
- Any managed DNS assignment, even disabled. Disabling publication retains name ownership. Releasing a reservation requires a separate deliberate, audited DNS ownership operation after provider state is verified; archival does not offer an automatic release.
- A live pending migration claiming the record. Resolve or reject that request first.

Revoked keys, approval/revocation/migration audit events, stopped acknowledged role history, report/inventory history and empty policies remain attached to the archived UUID. Use the Archived records filter to inspect or explicitly restore it. Restoration is audited and does not approve a key or restore withdrawn permissions.

AWS inventory continues updating the same archived record; its unique cloud identity is retained, so inventory does not recreate it as a second record or unarchive it. AWS running/stopped summary counts include archived observations. Archival is not an enrollment ban. Existing revoked beacons are denied; an unknown key can still request enrollment. A request matching an archived record is blocked until an operator restores it and independently approves the exact fingerprint.

Possible duplicate notices compare non-cloud records with other records using reported names, labels and available cloud hints. A generic record with no heartbeat is also explicitly marked for review. These are review hints only: no automatic deletion, merging, matching authorization or key movement follows from a hostname or label. Internal UUIDs are registry identities, not malformed AWS instance IDs.

## Enrollment selection and authorization

1. A valid signed first contact proves possession of the submitted Ed25519 key and creates a bounded pending request. Invalid signatures cannot create requests.
2. Validate AWS hint syntax: exactly a 12-digit account ID, region and EC2 instance identifier. These fields are untrusted claims, not proof of account ownership or permission.
3. Match the exact account/region/instance tuple; never match enrollment using a hostname, label, IP or instance ID alone. Evaluate any claimed migration UUID as well.
4. A unique consistent active record is proposed automatically. A nonexistent claim, mismatched provider/cloud fields, conflicting UUID, multiple matches, archived target or another approved key blocks approval. The operator must resolve the conflict explicitly.
5. If there is neither an existing match nor a migration claim, explicitly approved AWS enrollment creates an AWS record with the validated tuple. Non-cloud requests create clearly identified non-cloud records. Ordinary AWS inventory must still verify addresses before DNS publication.
6. Display the complete copyable fingerprint, unverified reported hostname/AWS identity, selected record or new-record indication and matching reason. The operator enters the full fingerprint obtained independently from host-deploy and selects “Approve this fingerprint for this host.” The displayed copy button is a convenience, not independent verification.
7. Recompute matching under the database security gate at submission, alongside the existing approved-key constraints. Inventory commits use this same gate. If inventory appears after a new-record preview, approval refuses the stale new-record action and requires refresh. No duplicate generic record is created.
8. Repeated approval of the same active fingerprint and host returns the original result without another audit event. Repeating the original new-record approval also returns its recorded result. Revoked keys and requests targeting a different host return a conflict; keys never transfer silently.

Pending hints may be corrected by another valid signed contact from the same pending key, preserving the original expiry. This permits fixing a deployment's mistaken migration UUID without regenerating its key. It does not alter approved/rejected identities or extend pending retention. The GUI clears fingerprint confirmation when the proposed match changes, and stale submitted targets are rejected transactionally. Rejected requests remain rejected for their existing retention period.

## Deployment

This pass was deployed to the command center with migration 0006 on 2026-09-26. Existing duplicates were not altered. See PASS5-LIVE-DEPLOYMENT.md for live checks and existing host-key migration holds. The following procedure remains the deployment reference.

1. Pin the exact station-access source revision and retain its separately reviewed migration/acceptance evidence. Source publication is separate from live deployment; do not rely on an inaccessible private handoff as an implementation prerequisite.
2. Back up the command-center database and keep its settings, vault/signing keys, DNS controller state and host identities intact. Stop station-access and inventory/DNS workers briefly for a consistent code/schema rollout.
3. Install station-access 0.3.2 and its built frontend using the existing deployment layout. Keep companion dependency versions as pinned. In the configured service environment run `python backend/manage.py migrate` (or the equivalent backend working-directory command). Verify host_registry migration 0006 is applied and `manage.py check` passes.
4. Restart the workers and station-access. Refresh the browser. Check ordinary inventory/heartbeats, `/host-identities` and `/hosts/<UUID>`. No archive/remove action should occur without an operator's separate review.
5. Review the reported generic duplicates; inspect each dependency preview rather than assuming a UUID display means a record is disposable.

For code rollback, leaving the additive fields in place is safer than reversing the migration. The old GUI does not understand archival and could display archived records again. Pause enrollment/removal while resolving a rollout problem. Do not restore an old database over new identity or audit decisions.

## Verification

See TEST-RESULTS.md and verification/removal-*.txt. Tests exercise signature admission, inventory matching/new-cloud creation, exact triples, migrations/conflicts, multiple matches, changed hints, independent fingerprint approval, idempotence, concurrent approvals/inventory, archival dependencies and races, permissions/CSRF, retained history, archived inventory refresh, UI confirmation and billing-count visibility. A populated 0005 → 0006 migration fixture retains UUID, labels, cloud identity, report and audit events. No live mirror acceptance or visual browser/mobile inspection is claimed.
