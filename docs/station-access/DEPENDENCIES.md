# External dependencies — public source selection contract

**Status: migration review only; no accepted ten-component public pin set yet.**
Historical private dependency handoffs are excluded from this public
repository. They remain independently retained as private provenance,
not usable public dependency declarations. A public source build must
never download former private repositories or request a GitHub token.

## Immutable component selection

The station-access Django portal imports separately installed `zog.*`
components. Its selected source set currently requires review of these
public repositories:

- `zog144/host-identify`, `zog144/host-discover`,
  `zog144/host-install`
- `zog144/image-build`, `zog144/box-control`,
  `zog144/root-control`
- `zog144/archive-mirror`, `zog144/network-register`,
  `zog144/host-deploy`, `zog144/certify-manage`

The exact immutable source selection is in
[public-companion-pins.json](../../public-companion-pins.json). Its
`candidate-unaccepted` status is **not** a release selector or a CI pass.
Only an independently reviewed manifest whose status changes to `accepted`,
supported by cross-repository consumer and source-license evidence, may be
used to run the complete Django integration suite. Each full Git identity
must remain fixed throughout an acceptance run.

Use a detached checkout at each accepted exact 40-character commit in a
separate `dependencies/` working directory. Do not substitute a branch tip
or version string, and do not re-use the historic `version-share-handoff.json`.
All companion code remains outside this source tree. For the aggregate `zog`
distribution, independently selected release-build pins remain authoritative;
public source snapshots alone do not change them.

## Testing stages

1. Run Python 3.12 namespace/layout/source compile and wheel/import/CLI tests
   without other Zog component installations when supported.
2. With an approved exact companion source set installed in an isolated venv,
   run `python tools/test-backend.py`, archive ownership and controller
   acceptance fixtures, authenticated issuer/Cloudflare reader tests, DNS
   authority tests and Django migrations. Do not mark incompatibilities as
   optional when a selected integration depends on them.
3. Build the React frontend with the reviewed Node/npm toolchain using
   `npm ci --prefix frontend`, `npm test --prefix frontend`,
   `npm run test:licenses --prefix frontend` and
   `npm run build --prefix frontend`. Review generated notice and asset hashes.
4. Rerun source CI without repository secrets, sudo, production credentials,
   live AWS/DNS/issuer endpoints or privileged host runtime installation.
   Native systemd/rootfs/SSM/ACME/VNC operations require separate acceptance.

When testing a staged frontend, set
`STATION_ACCESS_FRONTEND_DIRECTORY` to its isolated build output.
Application-specific persistent state, certificate material and databases
must never be stored in this source checkout.

## Operational restrictions

The optional archive mirror Django application, host-deploy worker, certificate
issuer, DNS provider writers and box-control adapter must each be installed
and selected explicitly. Their presence as Python dependencies does not activate
their production operations. Keep privileges, ownership, saved requests and
reconciliation authority with the designated controllers.

The former private setup instructions, historical 0.4.x version-specific
handoffs, private-token read example and previous CI run counts are **historical
evidence**, not current installation instructions. Refer to the retained
private original commit for those details; do not transplant them into public
source or imply that historic acceptance applies to newly selected revisions.
