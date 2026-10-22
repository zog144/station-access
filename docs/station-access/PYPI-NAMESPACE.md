# Zog Python namespace migration

Station-access now owns one component subtree in the aggregate Zog Python namespace:

```
src/zog/station_access/
```

There is deliberately no `src/zog/__init__.py`. The final aggregate
`zog` distribution is assembled by release-build, which owns the top-level
`zog/__init__.py`.

## Public Python contract

- Program/executable name: `station-access`
- Canonical import: `zog.station_access`
- Stable command callable: `zog.station_access.cli:main`
- Component version source: `zog.station_access.__version__`
- Current component version: `0.4.29`

Release-build can copy `src/zog/station_access/` directly into its aggregate
source tree. It must not rewrite imports or create compatibility packages under
the old `station_access`, `host_registry`, `archive_inventory`, or
`station_access_project` import names.

The component-local `pyproject.toml` exists for development, wheel-layout
verification, and installed-component testing. It is not authorization to publish
an independent `station-access` project to PyPI. Public Python publication is
only the aggregate `zog` distribution.

## Django layout and durable labels

The three station-owned Django applications now live at:

- `zog.station_access`
- `zog.station_access.host_registry`
- `zog.station_access.archive_inventory`

Their AppConfigs explicitly preserve the durable Django labels:

- `station_access`
- `host_registry`
- `archive_inventory`

Those labels appear in migration dependencies, model relation strings and existing
database migration history. They are serialized database/application identities,
not obsolete Python import paths, and must not be renamed as part of the PyPI
namespace migration.

The Django project package is `zog.station_access.project`. Settings, WSGI,
ASGI, URL includes, dynamic gateway factories, mock/patch targets and management
commands use the new Python namespace.

## Runtime data and source-only material

Python package data required at runtime:

- `zog/station_access/host_registry/fixtures/managed-state.json`

Django migrations remain package modules and therefore ship in the wheel.

Developer tests are source-only and live under `tests/`. They are
not copied into `src/zog/station_access/` and must not appear in the aggregate
wheel.

The React frontend is intentionally not Python package data. Production frontend
assets are built and activated by the existing four-stage frontend installation
workflow. The installed Python CLI uses the configured
`STATION_ACCESS_FRONTEND_INSTALLATION` or `STATION_ACCESS_FRONTEND_DIRECTORY`;
it does not locate `frontend/` relative to a Git checkout.

## Cross-component imports

Station-access uses the aggregate namespace for Zog Python dependencies:

- `zog.host_identify`
- `zog.archive_mirror`
- `zog.network_register`
- `zog.host_deploy` when deployment jobs are enabled
- `zog.box_control` when controller-backed features are enabled

Source-only integration tests also exercise `zog.host_discover` and
`zog.host_install`.

Host-identify, archive-mirror, network-register, host-deploy, host-discover and
host-install have namespace-capable source layouts. Station-access advanced its
exact network-register pin to the namespace-capable 0.12.0 revision
`d0610f4bd5fd25e265d9d3202c3de4cc32c34b04`. Box-control has also now
completed its upstream `zog.box_control` namespace migration. The repository now pins a namespace-capable box-control commit
`55a3c51e55b658fc89694fe03672a7e5d5720571` and its compatible image-build
commit `57f9b52fce4b19c06987f31f3c038b81a6c04f12`. This pin
combination passed the cross-repository Django integration job in GitHub Actions
run 38052828614, with 263 registry tests (one privileged-fixture skip), 98
station-access tests, and 24 archive tests (one optional-provider skip).
The Django migration drift check also passed. These are local fixture tests,
not a claim of live systemd/VNC/rootfs acceptance. No compatibility shims were added.

## Installed CLI/state boundary

`station-access` resolves directly to `zog.station_access.cli:main`.

The installed launcher no longer modifies `sys.path` or assumes a neighboring
`backend/` directory. Its default mutable state is
`~/.local/state/station-access` unless `STATION_ACCESS_STATE_DIRECTORY` is set.
Frontend selection is external mutable installation state, not wheel content.

Source-tree `serve.py` remains a thin developer wrapper around
the same installed callable.

## License and notice inputs for release-build

Release-build should preserve/review these repository inputs when assembling the
public aggregate release:

- repository `COPYRIGHT`
- repository `LICENSE`
- repository `THIRD-PARTY-NOTICES.md`
- complete `LICENSES/BSD-3-Clause.txt` and `LICENSES/GPL-3.0-only.txt`
- frontend `license-evidence.json` as build/review input
- the generated frontend license notice produced by the frontend build pipeline

Current new-export first-party component metadata declares
`BSD-3-Clause OR GPL-3.0-only` and includes both complete first-party
legal texts. Historical private records retain their earlier notice.
The aggregate Zog distribution owner must independently review and retain
third-party notices and reconcile its own pinned components before release.

## Regression checks

`tools/check-python-namespace.py` rejects:

- accidental `src/zog/__init__.py` ownership;
- runtime tests copied under `src`;
- obsolete top-level Python imports/configuration paths;
- dynamic import/mock targets using the old module names;
- obsolete nested repository paths such as `station-access/src` or `station-access/backend`;
- double `zog.zog` namespace prefixes;
- an incorrect console-script mapping;
- loss of required runtime package data.

GitHub Actions additionally builds a component wheel, inspects its exact contents
and entry point, installs it without dependencies, and imports
`zog.station_access` from outside the checkout. A separate job runs the pinned
frontend tests, license-evidence test and production build.

The current public-source workflow checks immutable public companion commits
without any private cross-repository token. Its production-facing Django
integration job deliberately blocks while `public-companion-pins.json`
remains `candidate-unaccepted` or companion-specific rights and consumer
evidence is absent. An independently authorized, isolated candidate test
run must verify imports, migration and Django fixtures before the source
owner reviews an accepted immutable pin revision. Passing fixture tests
is not live controller, host or certificate acceptance. See
[DEPENDENCIES.md](DEPENDENCIES.md) for this fail-closed boundary.
