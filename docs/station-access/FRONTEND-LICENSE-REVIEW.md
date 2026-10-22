# Frontend license verification — 2026-09-30

Scope: station-access 0.4.15, based on unstable
`f93d56457ca3245471fea93e4155dda8fddccbfc`. The newer network-register integration
and its pins are preserved. This is a source implementation/local acceptance pass,
not deployment, public publication or a grant for any other component.

## Reviewed artifacts

A fresh `npm ci --include=dev` used the checked-in lockfile. The five exact packages
below were independently downloaded with `npm pack --ignore-scripts` from
https://registry.npmjs.org. Their archive SHA-512 values matched registry metadata
and the lockfile. Every regular file in each archive was compared byte-for-byte
with its installed counterpart (283 files total). Supplied legal files were read;
terms/copyright statements were compared with the package declarations. The recursive
legal-file search found only the listed files in these particular tarballs. The
search heuristic is not a general proof of complete license coverage.

| Included package | Version | Retained legal evidence | Observed terms/attribution |
| --- | --- | --- | --- |
| react | 19.2.0 | LICENSE | MIT; Meta Platforms, Inc. and affiliates |
| react-dom | 19.2.0 | LICENSE | MIT; Meta Platforms, Inc. and affiliates |
| scheduler | 0.27.0 | LICENSE | MIT; Meta Platforms, Inc. and affiliates |
| react-router | 7.18.4 | LICENSE.md | MIT; React Training LLC, Remix Software Inc., Shopify Inc. |
| vite generated helpers | 7.3.6 | entire LICENSE.md | MIT core; retains upstream aggregate MIT, BSD-2-Clause, CC0-1.0 and ISC notices and all attributions |

`frontend/license-evidence.json` records the exact tarball URLs, registry identity,
lockfile integrity, archive SHA-256, registry-reported repository/subdirectory and
Git head, full package-file digest/count, reviewed notice paths and notice SHA-256.
Those registry/source fields identify evidence; they are not a claim of registry
signature verification or an independent reproducible build from the Git source.
The complete Vite notice is retained conservatively; it is not a claim that all
Vite build-tool dependencies are present in browser runtime code. Upstream choices
and exceptions are preserved verbatim inside that document.

React Router's selected input file is under `dist/development/`, which is its
published ESM entry-point layout. The invoking NODE_ENV and output are production;
that pathname does not imply development React. A readable production-output
inspection found that the vendored turbo-stream sections present in the React Router
input were eliminated from this output (their decode/flatten/unflatten implementation
and identifying error text are absent). Future changes to routing features or
bundled exports warrant another review of embedded vendor code, not reliance on the
outer package's MIT declaration alone. `react-router-dom` contributes no retained
chunk module in this build; it is not listed as a separate emitted implementation.

## Coverage and fail-closed behavior

The existing Rollup-module mechanism is retained and now checks exact reviewed
package content and identity, rather than trusting package.json's license alone.
The generated document begins **Zog / station-access original material**. Every
third-party package has its own named/versioned section, declared and reviewed terms,
archive identity and complete upstream text. It does not grant a Zog license
to the combined JavaScript bundle.

Current output contains first-party CSS and JavaScript, the entry HTML, notices and
the build inventory. There are no copied public assets, fonts, images, binary assets,
workers, service workers or embedded data assets. The Vite module-preload helper and
CommonJS wrappers are identified explicitly and covered by Vite's retained notices.
The module list and coverage observations are included in `frontend-build.json`.
noVNC is separately served and is outside this bundle/review.

New or changed package bytes, a different archive identity, missing/unresolved
review evidence, missing/changed notice text, unreviewed legal files, unknown virtual
helpers, copied public files, unreviewed emitted assets, CSS resource URLs/imports,
and supported worker/embedded-asset patterns fail with actionable errors. They never
inherit the Zog license. Nonstandard/nested notice paths can be recorded explicitly
in reviewed evidence; a focused test exercises that path. No generic automatic
license classifier is claimed. Future asset types require explicit source, notice
and output-coverage support before the release gate permits them.

## Building, serving and packaging

`npm run build` still forces production even if the caller sets NODE_ENV=development.
Run `npm run test:licenses`, `npm test`, `npm run build`, then repository-root
`python tools/check-frontend-release.py`. The latter verifies exact upstream notice
bytes, source/output hashes and that no output is omitted. The inventory does not
hash itself; the source archive's SHA256.json covers the inventory too.

The normal Django/Waitress deployment now serves fixed public routes:

- `/licenses/`: notice document selected by the build inventory, verified by hash
  and served as UTF-8 plain text with nosniff and a restrictive CSP. Missing or
  mismatched evidence returns 404, with no substitution or URL fetch.
- `/frontend-build.json`: the retained build inventory, with no-store caching.
- `/assets/LICENSES-<hash>.txt`: the original immutable UTF-8 text asset referenced
  by the HTML `rel="license"` link.

A visible **Licenses** link is on the login page and signed-in navigation, opening
in another tab so VNC sessions remain in their existing page. Legal content is never
inserted into React as HTML. The standard deployment's nginx configuration proxies
these routes to Django (`location /`); the `/static/` alias is unrelated. Local HTTP
acceptance uses the actual Django WSGI application and Waitress, not a Vite fixture
server. No installed host configuration was inspected or changed in this pass.

`tools/package-source.py` runs the release gate and includes the complete frontend,
notices, inventory, evidence and license texts. The documented Python wheel remains
a backend package: install the frontend distribution alongside it and set
STATION_ACCESS_FRONTEND_DIRECTORY when using another layout. Do not distribute
backend-only wheels as if they contained the browser assets.

## Remaining scope

This review covers these exact published packages and this emitted frontend. It is
not independent verification of all upstream authorship, a full Zog dependency audit,
or a rootfs license conclusion. First public release is source-focused; users build
their own rootfs. No pre-built rootfs distribution is assumed here.

Archive-mirror/image-build own the separate artifact-bound notice contract and the
Archives source/rootfs views. No empty Archives panel or claimed completion is added
by this pass. Frontend notices cannot substitute for retained artifact-specific
source or generation evidence, including old generations without retained notices.

## Current installation workflow (0.4.23)

The earlier source-archive packaging description above is historical. Source archives
now exclude generated dist. The [frontend installer](FRONTEND-INSTALLATION.md) runs
these maintained checks in staging and retains notices/inventory with each installed
asset set. This historical verification originally used a private first-party
notice; the new public-export candidate now uses the separately authorized
first-party **BSD-3-Clause OR GPL-3.0-only** grant. Its original third-party
package identities and notices remain unchanged. Re-execute the production
build and license-evidence tests against this new candidate before claiming
updated acceptance.
