# Production station/archive composition and frozen checkpoint migration

**Scope:** source/CI implementation of the 2026-10-11
"Production station and archive persistent-state composition" handoff.
Deployment owner is host-deploy; there is **no production cutover authorization**
in this source change. Source-state copies, toolchain host ownership, port 443,
nginx, existing writer, DNS and production backups remain untouched.

## Ownership and durable on-disk layout

The historical `archive-mirror/integration/persistent-station/application.py`
combines web and scheduler under one box-control storage ID. Different mount
**names** within that application still belong to that one ID; they do **not**
satisfy independent storage ownership. Do not deploy it as the final composition.

The replacement consists of **two** box-control applications:

| Application | Programs | Durable mount / guest path | Host capability |
| --- | --- | --- | --- |
| `station-access` | `web` | `<project>/state/mounts/persistent/<station-id>/station-data` → `/var/lib/station-access` | None for mirror role |
| `archive-mirror` | `server`, `refresh-scheduler` | `<project>/state/mounts/persistent/<archive-id>/archive-data` → `/var/lib/archive-mirror` | Scoped, read-only `mirror-live` for both programs |

The archive server itself rechecks the lease on authenticated requests and
readiness, so **both archive programs** need `mirror-live`. The station **web**
program never receives the grant. The root-owned
`/etc/zog/host-bindings.json` policy names the actual project, application,
program, `mirror-live` capability and narrow host-discover export source for
each authorized archive program. Controller mounts the directory at
`/run/zog-host/mirror-live`. Its contents are atomically replaced by
host-discover; do not copy leases or general host credentials into storage.

The station application contains its SQLite database, deployment secrets,
identity-independent application state and historical archive records that
remain *inert* when the optional embedded provider is disabled. The new archive
application exclusively owns the active catalogue at
`/var/lib/archive-mirror/catalogue.sqlite3` and object store at
`/var/lib/archive-mirror/store`. The station web deployment **must not set**
`ARCHIVE_MIRROR_CONFIGURATION` to enable the legacy embedded provider.
Archive inventory/observation pages remain part of station-access independently.
The archive provider serves its own authenticated HTTP endpoint and retention
policy. Routing/host authorization are host-deploy acceptance work.

The station and archive `software_view` fields must be resolved to exact
published SHA-256 image-build application views; rootfs must independently
provide the required Python/native executables and empty mount targets.
No `/opt` writable Python environment is created or reused. Never install
pip dependencies into mutable state.

## Deterministic immutable composition

From checkouts at accepted exact source pins, run the *offline* renderer on an
operator-controlled, **new** staging directory:

```sh
python -m zog.station_access.production_composition \
  --station-template station-access/integration/production/station-access/application.py \
  --archive-template archive-mirror/integration/production/archive-mirror/application.py \
  --station-view 'sha256:<actual-station-view-digest>' \
  --archive-view 'sha256:<actual-archive-view-digest>' \
  --output-directory /path/to/NEW/application
```

Replace the two digest placeholders with real 64-character lowercase SHA256
identities. The output layout is `application/station-access/application.py`
and `application/archive-mirror/application.py`, parseable by
`zog.box_control.specification.discover_applications`. Existing output
blocks rather than being overwritten. The renderer does **not** attest that
a named view is published, select a rootfs generation or mutate a project.
The project owner must check both image-build identities and its supported
software binding/preflight before preparing either application.

## Offline migration of frozen checkpoints

The deployment owner must provide:

- A **copy** of production `/var/lib/station-access` for rehearsal, or a
  fresh, quiesced checkpoint for the final maintenance window (includes
  `station-access.sqlite3`, `deployment-secrets.json`, and retained state).
- A matching frozen copy of `/var/lib/archive-mirror/store`, including object
  bytes, notices, and any retained pin/recovery sidecars.
- Two distinct controller-issued persistent storage IDs, each already prepared
  by box-control and verified against its own application. Their named
  writable mount directories must be **empty** before migration. Do not use
  paths that point to legacy host state.
- A completed, consistent archive catalogue. If the legacy archive tables
  live inside station SQLite, archive-mirror extracts all its `archive_mirror_*`
  tables and `archive_mirror` migration history into the independent catalogue.
  It does not copy the station user's authentication table into that catalogue.
  An existing separate `catalogue.sqlite3` under the old archive store is
  copied consistently instead. Ambiguous/missing catalogue tables block.

Command (example; paths and exact IDs must be supplied by host-deploy, never
constructed from guessed controller state):

```sh
python -m zog.station_access.state_migration \
  --station-source /path/to/FROZEN/station-access \
  --archive-source /path/to/FROZEN/archive-mirror/store \
  --station-destination /path/to/PREPARED/station-data \
  --archive-destination /path/to/PREPARED/archive-data \
  --station-storage-id <controller-station-storage-id> \
  --archive-storage-id <controller-archive-storage-id> \
  --confirm-frozen-checkpoints
```

The flag is an explicit operator assertion, **not** proof that a writer has
stopped. The tool never stops writers, invokes lifecycle APIs, migrates a live
database in place, changes nginx or adopts the compiler host.

Behavior: reject symlinks, hardlinks, devices, unsafe/noncanonical paths,
journal sidecars, aliasing destinations and unexpected existing state. Use a
SQLite backup operation for databases, exact byte copy and digest verification
for regular files; preserve/tighten private file modes. Each destination
receives a durable `.zog-state-migration.json` marker before data copying.
Missing/unfinished/conflicting markers block retries until an owner inspects
and deliberately recovers the attempted migration. A completed rerun is
recognized only with matching source/destination identities and verified data;
it cannot merge unrelated state or redo archive downloads.

Output is bounded JSON with
`schema=zog-station-state-migration-v1`, `state`, hashed source/destination
filesystem identities, **both distinct storage IDs**, checkpoint manifest
hashes, archive verification counts, and object/catalogue SHA-256 evidence.
No key bytes, auth tokens, absolute production paths or private file contents
are included. The CLI always emits `safe_to_cut_over=false`.

The archive verifier (`zog.archive_mirror.store_verification`) independently
checks SQLite integrity, every catalogue object's recorded size and SHA256,
snapshot/pin FKs, incomplete/active reviewed-source pin sets, retained notice
bindings and simulated prune protection. It **never prunes**. A nonzero
`currently_prunable_managed_sources` or `unreferenced_objects` needs
explicit operator review before production acceptance.

The static `/etc/archive-mirror/configuration.json` is **not** blindly copied
into either destination. After migration, provision trusted configuration
inside `archive-data` with `root=/var/lib/archive-mirror/store`,
`intent_file=/run/zog-host/mirror-live/mirror-intent.json`, the exact
enrolled host UUID, selected endpoint, issuer, audience and trusted **public**
keyring. Keep keyring publication and live host-discover export under their
respective owners. Do not copy secret/private keyrings.

## Acceptance procedure owned by host-deploy

1. **Rehearsal:** use matching frozen copies; render the two exact immutable
   views; prepare both persistent identities; run the migration; check the
   evidence, migrated SQLite row counts/secrets, licence notices, objects,
   pins, reviewed source sets, and expected launch bindings. Use an isolated
   listener; no production port-443 change.
2. **Read-only host contract:** verify `mirror-live` producer renewals, atomic
   replacement, withdrawal/expiry, and actual kernel mount evidence for both
   archive programs. Confirm the station web program has no host capability.
   A stale inode/file snapshot or missing export blocks.
3. **Runtime:** verify systemd service/process identities, invocation-scoped
   logs, an authenticated archive download and denied cross-collection token,
   authenticated station login, `/` and `/administration/archives`, and
   owner-aware compiler *observation*. Stop/relaunch both applications:
   the runtime IDs should change while each storage ID stays unchanged;
   byte hashes, pins and users must survive. Role withdrawal may stop the
   separate archive provider, but may **not** terminate station web or delete
   archive bytes. Verify boot startup/recovery.
4. **Final maintenance window:** host-deploy fences/stops the original sole
   writer, refreshes its SQLite online backup and archive checkpoint, reruns
   migration into verified new empty storage, and launches the new sole writer.
   Switch nginx only after authenticated readiness and owner approval. If
   readiness fails *before accepting writes*, return traffic to the old
   writer. Once the new app accepts production writes, do **not** blindly
   restore an earlier database; reconcile writes explicitly.

Retain the exact historical host checkpoint in the separately protected
owner record. It is **not** the final checkpoint. Avoid any independent
direct compiler writer and preserve the owner-authorized existing workspace
UUID and ownership epoch. Actual production identities, epochs and backup
paths are private operational evidence, not public source defaults.

**Remaining blockers:** host-deploy's namespaced, authenticated compiler
gateway and permitted operations; deployed immutable view identities and
runtime boot services; actual host resource/permission inspection; isolated
rehearsal against copied production state; maintenance fence and rollback.
The prior `production_cutover` probe tests a combined namespace and always
returns `safe_to_cut_over=false`; it must not be used as approval evidence
for this new split-application layout.

## Independent archive integrity command

After copying into prepared archive storage (or on a read-only copied
candidate), run:

```sh
python -m zog.archive_mirror.store_verification \
  --root /var/lib/archive-mirror/store \
  --catalogue /var/lib/archive-mirror/catalogue.sqlite3
```

A result with `valid=true` demonstrates catalogue/object/pin/notices
consistency, **not** lease authority, process readiness or production cutover
acceptance. Review the reported simulated `snapshots_prunable_if_run`,
`currently_prunable_managed_sources` and `unreferenced_objects` before any
later prune. Optionally add `--require-no-orphans` where an operator has
explicitly required zero retained unreferenced objects. This verifier never
executes prune or removes retained bytes.

For source databases predating the current `archive_mirror` migration set,
run the required Django schema migrations on an **isolated checkpoint copy**
before extraction. The exporter deliberately refuses missing catalogue tables
rather than inferring or silently losing review/pin records. Migration of
the final original production database remains owned by the maintenance-window
operator, with only one writer.
