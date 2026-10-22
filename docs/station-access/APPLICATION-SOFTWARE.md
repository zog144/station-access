# Application software inspection

The administrator-only **Administration → Application software** page presents
read-only evidence from immutable image-build application-software publications,
box-control's configured application view selections, and its advisory launch
preflight. The API endpoint is `GET /api/application-software/`.

## Evidence and trust boundary

The server reads a bounded published view directory from the *local trusted*
box-control project STATE. The module uses image-build's `read_view` and
`read_artifact` validators to check identities, symlink composition, retained
file inventories, and referenced artifacts. It does not instantiate producer
stores (whose constructors may initialize directories) and does not publish,
mount, activate, prepare, delete, or reclaim anything.

The endpoint is administrator-only, GET-only, and `Cache-Control: no-store`.
Returned data intentionally excludes absolute on-host paths, controller
credentials, raw manifest/provenance dictionaries, file/recipe source URLs,
and source URLs with query strings. HTTPS source links, if any, are drawn from
validated source identities; their presence does not imply provenance review.
A recorded notice file is not a license-expression or completeness attestation.

Selections come from box-control application specifications; retained runtime
counts refer to *expected-launched* bindings. Preflight results are **advisory**,
not launch authorization. `mount_observation: not-probed` is always explicit.
Published-but-unselected views are distinguished from selected views. Missing
stores and failed integrity checks remain unavailable, not zero/verified.
The listing is bounded and clearly marks truncated view/artifact results.

Immutable publication/launch evidence alone must never claim a runtime mount is
active. The separate, manually refreshed administrator-only kernel observation
can report live mount evidence using the versioned controller contract. Real
systemd/rootfs, X11 and reboot acceptance remains with host-deploy.

## Verification

`tests.station_access.test_software_inspection` checks authorization,
no-store, lack of mutation for unavailable stores, symlink rejection,
validated projection, credential/path redaction, and fail-closed status.
The frontend page tests verify selection, license-availability wording and
that mount readiness is not fabricated. All code runs through the ordinary
cross-repository Django/React GitHub Actions jobs.

## GitHub Actions acceptance (2026-10-10)

Run 38053931368 (historical private CI/verification evidence; not distributed with public documentation)
passed the Python namespace/wheel and React frontend pipelines, 263 registry
Django tests (one skipped in the ordinary suite), 105 station-access Django
tests, and 24 archive-inventory Django tests (one optional-provider skip).
Both formerly skipped integration cases passed in dedicated CI steps: the
privileged host-beacon supervisor and the optional archive-mirror signed
provider/receiver acceptance. No Django migration drift was detected.

## Application and runtime detail (2026-10-10)

Administrator-only `GET /api/application-software/applications/<name>/` reads
the **currently configured** immutable view and validates its exact artifacts
using image-build's `read_view` and `read_artifact` readers. The Applications
page links administrators to this detail page. It shows the full artifact/view
identities, revisions, allowlisted compatibility descriptors, HTTPS source
identity digests, and paths of notice files within the immutable artifact.
It never emits raw manifests, local root paths or license file contents.
Missing/invalid publications are reported as unavailable, not verified.

Runtime Detail obtains the **historical expected-launched** view, artifact IDs,
binding and manifest digests, plus selected rootfs generation from box-control's
persisted runtime reference, via the narrow adapter and runtime serializer.
It does not resolve these from current application settings. A former launch
may therefore differ from the current selection; administrators can compare
both snapshots, while ordinary authorized runtime owners see only historical
launch identities and never access the administrator inspection endpoint.

There is no observed-current mount claim, automatic migration, publication,
launch, package-store modification, or controller repair in either endpoint.
Compatibility requirements are declared metadata, not proof that the running
rootfs is presently compatible.

## Detail and runtime history acceptance

On October 10, 2026, GitHub Actions run 38071077908 (historical private CI/verification evidence; not distributed with public documentation) passed the three jobs after adding the application detail and runtime launch-software views: 263 registry tests (one skipped in the ordinary run), 115 station-access tests, 24 archive tests (one skipped in the ordinary run); the privileged beacon and optional provider cases both passed in dedicated steps. Frontend tests/build, component wheel/namespace, and Django no-migration-drift checks also passed. No live mount, rootfs, or host deployment was attempted.


## Kernel mount observation v1 (2026-10-10)

After binding the exact mount-observation-capable box-control, root-control and
image-build companions, station-access adds the administrator-only GET
`/api/runtimes/<runtime_id>/mounts/`. It verifies authentication and the
existing recorded runtime before invoking the narrow public controller method
`observe_application_runtime_mounts(runtime_id)`. The request never accepts a
PID, unit, mount destination or host source from the browser.

The server strictly checks the runtime identity, schema
`zog-runtime-mount-observation-v1`, `kernel-mount-namespace` evidence basis,
non-atomic snapshot, bounds and status vocabulary. It projects only allowlisted
fields: the recorded runtime identity, timestamp, program name/status,
mount namespace IDs, expected destinations, observed presence/access, backing
identity and explicit partial/truncation flags. Host backing sources, process
PIDs, systemd service names, raw paths, `/proc` contents and transport errors
are withheld. Invalid/unavailable results are generic 503 responses.

The Runtime Detail panel is rendered only for administrators and performs
**no automatic inspection**. An explicit Refresh observation action obtains
a new bounded kernel snapshot. This is displayed *separately* from immutable
historical software evidence. Multiple namespaces, unavailable evidence,
unexpected read/write flags, changed identity, missing mount, and inconclusive
backing are reported faithfully. An inconclusive observation is not green.
Kernel snapshots can become stale immediately and have no repair effects.
Historical runtime evidence remains available after service exit/reboot.

Ordinary users do not receive mount namespace details. No database migration,
background polling, automatic restart, repair, runtime launch or host deployment
is introduced. A real systemd/host-deploy acceptance remains a separate upstream
box-control and root-control milestone.

## Runtime kernel observation acceptance

The complete cross-repository GitHub Actions run
38088025187 (historical private CI/verification evidence; not distributed with public documentation)
passed all three jobs against the exact mount-observation-enabled companion pins:
263 host-registry tests (one ordinary-suite privileged skip), 124 station-access
tests, and 24 archive-inventory tests (one optional-provider skip). Both
skipped scenarios passed independently in their dedicated privileged/provider
steps. The React/frontend pipeline and Python namespace/wheel tests passed;
Django found no migration drift.

This is **fixture and CI acceptance** for station-access's consumer contract,
not disposable-host kernel acceptance. The application/runtime launch history
is never rewritten by inspection, and `Observed mounts` must be manually
refreshed; it is a non-atomic snapshot rather than lasting integrity proof.
