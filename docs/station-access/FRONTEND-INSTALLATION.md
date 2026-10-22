# Frontend source installation — component-maintainer workflow

This chapter describes an exact-pinned **component source checkout** and frontend build. It is **not** a replacement for the aggregate Zog release installer, a production runtime installation, or an authorization to deploy frontend assets without reviewed rootfs/application configuration.

Station-access 0.4.23 provides `tools/frontend-install.py`: a Linux, explicit
prepare/build/verify/activate workflow. `install` combines the first three stages;
it never activates. It is intended for a future box-control application lifecycle
to call without duplicating npm commands. It is not yet that lifecycle contract.
Python namespace migration, backend installation, migrations, noVNC provisioning,
TLS and live deployment are separate operations.

## Prerequisites and layout

The maintained **installer implementation currently requires a protected
version-share source baseline** containing exact blob hashes. This is a
limitation of the existing privileged-host installation path, not a
requirement for the public Node 24/npm 11.9 source-only build. Public
GitHub Actions can run `npm ci`, `npm test`, `npm run test:licenses` and
`npm run build` from an exact checked-out commit without version-share.
A separately reviewed Git-source verification adapter is still needed before
the privileged four-stage installer supports public checkouts. The installer
must fail closed on a missing baseline until that adapter is accepted.
Only committed, hash-matching build inputs are copied; a dirty frontend or
existing dist/node_modules/compiler cache is rejected. Pass the reviewed exact
source commit as `--source-revision`. Generated outputs stay outside Git.

The maintained `frontend/toolchain.json` pins **Node 24.19.0 and npm 11.9.0**.
Install those versions explicitly from your trusted toolchain distribution and
pass their absolute executable paths. Version mismatch fails; no latest-version
selection or toolchain download is performed. The command requires Python 3.12+
with Django 5.2 and Waitress 3 available to that interpreter for isolated serving
verification. The runtime service needs Python dependencies but never Node/npm.
This is version pinning, not independent toolchain binary provenance verification.

Run orchestration only under the separately authorized host owner. Have the
host owner provision dedicated unprivileged build and runtime identities under
its approved grant contract, with different UIDs and no shared privileged
groups. The example arguments below are placeholders, not actual host accounts.
Do not put runtime credentials or private application state in their build workspace.
The orchestrator clears supplementary groups when running npm/tests, uses a fresh
HOME/cache/config and strips application credentials and VITE_* variables. It
preserves only HTTP proxy and public CA-file transport settings; TLS verification
is not disabled. Proxy values are not copied into installation manifests. npm may
include transport details in staging logs; treat the staging tree as operator data.
Build scripts are trusted code and this identity separation is not a network or
filesystem sandbox. Restrict build-user access to other host files accordingly.

Example root: `/state/applications/station-access/frontend`. All ancestors must
be root-owned and not group/world writable, without symlinks. The command cannot
place this tree inside the source checkout. `/state` mount validation remains the
host installer's responsibility; do not prepare it on the wrong filesystem.

```
frontend/
  staging/<operation>/       # root-owned metadata/logs; work/ owned by build user
  releases/<release>/        # root-owned 0555 dirs / 0444 installed files
    dist/                    # complete HTML, JS/CSS, notices and frontend-build.json
    installation.json        # revision, source/lock/output hashes, toolchain, checks
  selection.json             # atomic active ID and retained asset sets
  activation.json            # interrupted activation recovery record, when present
  last-activation.json       # most recent successful selection and check
```

The runtime UID has read/traverse access but cannot replace or modify installed
outputs or the selection. Keep root and release parents nonwritable to build/runtime
users. A single nonblocking lock serializes prepare, build, verify, activate,
recovery and staging removal. Contending operations fail with a retry message.

## Supported command

From the exact retrieved source, using your selected Python environment:

```sh
python3 tools/frontend-install.py \
  --application-root /state/applications/station-access/frontend install \
  --source /opt/source/station-access \
  --source-revision EXACT_40_CHARACTER_COMMIT \
  --build-user APPROVED_UNPRIVILEGED_BUILD_ACCOUNT --runtime-user APPROVED_UNPRIVILEGED_RUNTIME_ACCOUNT \
  --node /opt/node-24.19.0/bin/node --npm /opt/node-24.19.0/bin/npm
```

The operation and verified release IDs are printed as JSON. For explicit stages,
replace `install` with `prepare`, then run:

```sh
python3 tools/frontend-install.py --application-root /state/applications/station-access/frontend build --operation OPERATION_ID
python3 tools/frontend-install.py --application-root /state/applications/station-access/frontend verify --operation OPERATION_ID
```

Build runs exactly `npm ci --include=dev` then `npm run build`. Development tools
are included regardless of the invoking NODE_ENV; the maintained build wrapper
forces production. The source lockfile may not change. Verification runs the
maintained frontend suite, `npm run test:licenses`, exact output/notice checks,
and a temporary Django/Waitress instance using the real frontend views. It checks
entry/client routes, HTML asset references, all output bytes/MIME and plaintext
notice endpoints. This isolated server does not test authentication, databases,
controller APIs or graphical sessions.

The installation manifest records source commit and input hashes, lock digest,
Node/npm versions, public build mode, complete output hashes (including the build
inventory), notice digest and observed checks. Hashes identify one output; they
are not a reproducibility claim. noVNC remains separately served and outside this
bundle's license review. Preserve its separate package/notice and serving workflow.
No rootfs or archive-artifact license completion is implied.

Network access to the lockfile's exact registry archives is required for a clean
cache. Each operation starts with an isolated cache; this initial implementation
does not promise disconnected installation or import an unchecked dependency tree.
There is no unlocked install fallback. Failures return nonzero with the relevant
staging log path and leave selection unchanged. To retry dependency/compilation
failure, use `build` on the still-prepared operation; failed verification can retry
`verify` while source/output remains consistent. A changed source requires a new
prepare. Missing prerequisite errors do not install a release.

## Serve and explicitly activate

Install the compatible backend first, and configure its existing Django/Waitress
service with:

```
STATION_ACCESS_FRONTEND_INSTALLATION=/state/applications/station-access/frontend
```

This takes precedence over `STATION_ACCESS_FRONTEND_DIRECTORY`. That legacy setting
still works for independently built single directories and for the image-build
composed application view. The canonical composed view root defaults to
`/applications/station-access` and can be changed only by the trusted operator
setting `STATION_ACCESS_APPLICATION_VIEW_DIRECTORY`.

When the frontend directory is beneath that application view root, frontend leaves may
be image-build's immutable relative symlinks into the sibling `/applications/.store`.
Station-access does not broadly trust the store: each accepted link must name a
64-hex artifact directory, must resolve to the **same logical path** as the view leaf,
must use image-build's exact relative target form, and must remain inside that one
artifact after resolution. Parent directories in the view and the store/artifact roots
must not be symlinks. Ordinary standalone frontend roots retain the existing
resolved-beneath-root containment rule. This composed-view exception relies on
box-control mounting the application view and artifact objects as trusted immutable
bindings; it is not an authorization mechanism for arbitrary writable directories. Requests do not run npm.
Before first activation, the versioned path returns 404; API routes are unaffected.
The reverse proxy must forward `/`, client-side routes, `/assets/`, `/licenses/`
and `/frontend-build.json` to Django; it must not serve a separate stale asset copy.

```sh
python3 tools/frontend-install.py \
  --application-root /state/applications/station-access/frontend activate \
  --release VERIFIED_RELEASE_ID --health-url http://127.0.0.1:8000
```

The origin must be this service, with loopback HTTP or normally verified HTTPS,
no embedded credentials or redirects. Activation validates installed hashes and
permissions, detects retained asset-name collisions, and atomically replaces a
small selection file. It then checks the served entry, routes, inventory, every
asset and licenses against this release, plus the previously active hashed assets.
If a check fails, it restores the prior selection (or removes the first selection)
and returns failure. Keep old releases: `/assets/` searches retained releases so
open browser sessions can fetch their prior hashes. There is no automatic release
pruning; capacity planning and future explicit retention policy remain necessary.

The selection must point to backend-compatible frontend code. This version introduces
`station-frontend-selection-v1`; future API compatibility changes require review.
Frontend rollback never rolls back backend code, APIs or a database migration.
For explicit rollback, run `activate` with the prior verified release ID and the
same health origin. It performs the same checks and retains the newer asset set.

If the orchestrator crashes after recording activation intent, the journal blocks
another activation. Run `recover` to restore its recorded previous selection,
then check the service before trying again. Do not edit the selection/journal by
hand. A failed check briefly exposes the candidate before restoration; this is
atomic selection, not zero-risk blue/green routing or transactional browser state.
The installer cannot guarantee service health if the backend/proxy itself is down.

Remove a staging workspace after inspection with `discard --operation ID`. This
only removes that operation beneath `staging`; it never removes releases or runtime
state. Successful releases do not depend on their staging tree.

## Source and release-build boundary

The maintained frontend build input is the repository-root `frontend/` directory.
`release-build` may select that source explicitly for the aggregate Zog source release
so image-build can construct station-access application state. Frontend source is not
ordinary Python wheel package data.

The former whole-repository `SHA256.json` / `tools/package-source.py` mechanism was
retired during the repository-structure cleanup. Release-build owns exact selected public
release input manifests; station-access no longer maintains a second full-repository
source ZIP inventory. The final pre-cleanup inventory and historical deployment helpers
remain in separately retained private source/verification history and are not public deployment instructions.

For image/application construction, retrieve the exact station-access source revision,
use this installer with the repository root as `--source`, and keep generated frontend
output under the prepared application root or other build artifact storage. Do not copy
the station-access repository wholesale into the Python wheel.

## Verification and boundaries

Focused tests: `python3 -m unittest discover -s tools/tests -v` with Django installed.
Local acceptance uses a disposable application root, real npm and HTTP serving,
plus failure injection for missing prerequisites, install/build/license failures,
missing output, collisions, serialization and rollback. The Work environment may
block OS identity switching; report that limitation separately rather than claiming
unprivileged execution was demonstrated. Actual service-account permissions and
box-control/rootfs/live-host acceptance remain deployment checks.

To repeat source-to-HTTP acceptance on a disposable host, use the clean checkout:

```sh
python3 tools/test-frontend-installation.py \
  --application-root /state/station-frontend-disposable-test \
  --source-revision EXACT_40_CHARACTER_COMMIT \
  --build-user station-frontend-build --runtime-user station-access \
  --node /opt/node-24.19.0/bin/node --npm /opt/node-24.19.0/bin/npm
```

The root must not already exist. It runs real npm and HTTP acceptance, confirms the
runtime user cannot overwrite installed output, and leaves a disposable result
for inspection. The second asset set is explicitly a synthetic activation fixture.
`--identity-fixture` is only for a restricted Work test environment: it substitutes
uid/gid switching and chown and reports that limitation. Never count that option
as real service-account acceptance or use this test root as a deployed release.
