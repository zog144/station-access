# station-access

**Documentation:** [Technical manual](docs/station-access/README.md) · [Source traceability](docs/station-access/TRACEABILITY.md). The manual organizes current concepts; linked detailed sources preserve exact contracts and historical evidence.

Station-access is Zog's React/Django portal for graphical workspaces, application and
runtime inspection, journald-backed logs, host enrollment/administration, DNS setup,
archives and provenance views. Its canonical Python import is `zog.station_access`;
the human-facing executable remains `station-access`.

## Repository layout

```text
src/zog/station_access/   installable Python runtime
tests/                    source-only Python/Django tests
frontend/                 React source and build inputs
integration/              reviewed production application declaration only
deployment/               retained non-executable generic data/configuration
docs/station-access/legacy/noninstallable/  quarantined historical VNC and timer examples
tools/                    maintained development/build/test utilities
docs/                     current product and source documentation
```

Historical private handoffs and live deployment records are deliberately
excluded. This public source uses an immutable ten-component selector in
[public-companion-pins.json](public-companion-pins.json); until its explicit
status is `accepted`, cross-repository integration and production use remain
blocked. A version-match alone is not acceptance.

## SR-06 source-publication boundary

The former `integration/application.py` VNC declaration and the two historic
systemd service/timer pairs are retained **only as plain-text historical
fixtures** in [the legacy non-installable archive](docs/station-access/legacy/noninstallable/README.md).
There is no approved runnable replacement for those programs. Do not move the
fixtures back into `integration/` or `deployment/`, enable legacy timers, invent
host accounts, or confuse the singleton web grant with a workspace identity.
`tools/check-public-source.py` and source tests enforce this boundary.

## Deployment boundary

`pip install zog` supplies the aggregate Python runtime. It is not intended to make
station-access immediately browser-ready by itself.

The supported production flow is:

1. `image-build` constructs or imports the required root filesystem and application software.
2. Python/Django dependencies and station-access runtime code are installed into the prepared application.
3. The frontend is built from `frontend/` as part of image/application construction.
4. The resulting application state is immutable/read-only at runtime.
5. `box-control` launches the prepared station-access application.

Node/npm are therefore build-time inputs, not runtime wheel dependencies. Station-access
must not build frontend assets on web requests or mutate its installed application state.

See [frontend installation](docs/station-access/FRONTEND-INSTALLATION.md),
[image-build integration](docs/station-access/integration/IMAGE-BUILD.md), and
[box-control adapter](docs/station-access/BOX-CONTROL-ADAPTER.md).

## Python package

The component source copied by release-build is:

```text
src/zog/station_access/
```

This repository deliberately does not contain `src/zog/__init__.py`; release-build owns
the aggregate top-level package. Component-development metadata lives in
[pyproject.toml](pyproject.toml). Public Python publication occurs only through the
aggregate `zog` distribution.

The executable entry point is:

```text
station-access = zog.station_access.cli:main
```

Django app labels remain stable for migration/database compatibility even though their
Python import paths use `zog.station_access...`. See
[the namespace contract](docs/station-access/PYPI-NAMESPACE.md).

## Local development

Install the exact companion revisions documented in
[DEPENDENCIES.md](docs/station-access/DEPENDENCIES.md), then use a private disposable state directory:

```sh
python serve.py --state-directory /absolute/private/station-state
```

For backend tests:

```sh
python tools/check-python-namespace.py
python tools/test-backend.py
```

For frontend development and validation:

```sh
cd frontend
npm ci
npm test
npm run test:licenses
npm run build
```

Generated `frontend/dist/`, databases, credentials, keys and runtime state are not source.

## Current documentation

Useful maintained interfaces include:

- [Portal operation and development](docs/station-access/PORTAL.md)

- [Archives API](docs/station-access/ARCHIVES-API.md) and [archive authorization](docs/station-access/ARCHIVE-AUTHORIZATION.md)
- [Registries and deployments](docs/station-access/REGISTRIES-DEPLOYMENTS.md)
- [DNS destinations](docs/station-access/DNS-DESTINATIONS.md), [DNS evidence](docs/station-access/DNS-EVIDENCE.md),
  [DNS membership](docs/station-access/DNS-MEMBERSHIP.md), and [DNS setup](docs/station-access/DNS-SETUP.md)
- [Signed host protocol](docs/station-access/SIGNED-HOST-PROTOCOL.md)
- [Workspace/VNC behavior](docs/station-access/VNC-WORKSPACES.md) and [websockify integration](docs/station-access/WEBSOCKIFY.md)
- [Workspace provenance](docs/station-access/WORKSPACE-PROVENANCE.md),
  [Generation provenance](docs/station-access/GENERATION-PROVENANCE.md), and
  [host generation/export](docs/station-access/HOST-GENERATION-AND-EXPORT.md)
- [Frontend installation](docs/station-access/FRONTEND-INSTALLATION.md) and
  [frontend license review](docs/station-access/FRONTEND-LICENSE-REVIEW.md)
- [Box-control log integration](docs/station-access/BOX-CONTROL-LOGS.md)

## Licensing

Original station-access-owned source, documentation and artwork in this
**new public-export source** are licensed at your option under
**BSD-3-Clause OR GPL-3.0-only**. This does not retroactively change private
historical snapshots or relicense React, Vite, noVNC, TurboVNC, rootfs
payloads, or other third-party software. Source redistribution and frontend
bundles must retain the corresponding copyright/license and third-party
notice texts. Public Python packaging still occurs through the aggregate
`zog` distribution, subject to its separate acceptance.

See [COPYRIGHT](COPYRIGHT), [LICENSE](LICENSE), and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
