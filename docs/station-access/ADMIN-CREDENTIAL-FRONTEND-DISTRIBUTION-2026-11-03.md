# Administrator-credential frontend/npm distribution review — 2026-11-03

**Scope:** Candidate-only evidence for a future distributable station-access artifact. This work complements the already-completed Python wheel inventory in [host-discover PR #5](https://github.com/zog144/host-discover/pull/5), not a second Python provenance ledger. No administrator credential or Command-Center authority is installed, no production companion pin is changed, no STATE exists in this workflow and no rights-holder permission is inferred.

## Selected immutable source candidates

- Host-discover provenance PR #5: `11376e09d7b9ff1251eca0549c2730406be1ca66` with `verification/admin-credential-source-provenance-2026-11-02.json`. Its ledger declares `independent_rightsholder_permission=not-attested`, `production_pin_change=forbidden` and `candidate_adoption=not-authorized-by-this-ledger`.
- Station-access administrator credential receiver PR #18: `7e8829483c1f2d49b2a4e7f2d97c6c2b9e364a73`; the draft frontend evidence candidate is stacked on this exact source.
- Reviewed frontend Vite production inventory sources are `frontend/scripts/license-evidence.mjs`, `release-plugin.mjs` and `frontend/license-evidence.json`. This branch **extends rather than replaces** their original license/attribution gate.

## Artifact-to-notice evidence

The existing production Vite source gate rejects unreviewed source images/fonts/workers, virtual modules, CSS external URLs and copied public assets. Its `frontend-build.json` includes every generated file hash, source file provenance, source license texts, lock-bound npm package identity and reviewed notice digests. A generated `assets/LICENSES-<hash>.txt` carries verbatim reviewed upstream notices and first-party license texts and is linked by `index.html`.

The new `coverage.chunk_dependencies` records the exact reviewed npm package identities represented in **each emitted JS chunk**. `frontend/scripts/distribution-evidence.mjs` reads the actual built files, checks their hashes and path coverage, rereads original published npm notice bytes from the exact lockfile-selected `node_modules` archive identities, and verifies that the notice bytes appear in the generated license asset. It generates a **separate review-only** `ADMIN-CREDENTIAL-FRONTEND-REVIEW.json` containing:
- exact output asset SHA-256 and per-output npm notice paths/hashes, plus first-party license sources;
- all `package-lock.json` entries with immutable archive URL/integrity and a clear distinction between **reviewed emitted** packages and **npm build/test lock-only, not shipped** packages;
- source-ledger digest, explicit candidate revisions and unchanged no-rights/no-native/no-production adoption status.

An initial exact frontend-only CI build observed **four emitted output assets, five emitted npm dependencies and 191 locked npm entries**. The 186 lock-only entries are explicitly *not* declared approved for redistribution: including `node_modules` in a future artifact would require additional independent notice and rights review. Likewise, the remotely served noVNC installation and Python wheels are **outside** this frontend asset evidence.

The candidate-only workflow `.github/workflows/admin-credential-frontend-notice-evidence.yml` checks out exact host-discover PR #5, requires the receiver PR #18 ancestor, prevents changes to accepted `public-companion-pins.json`, uses pinned Node/npm tooling and runs the existing license/build checks before the extra review. The new `node --test` suite rejects missing and additional generated assets, altered JS files, missing/changed published notice bytes, missing manifest notice rows, tampered npm archive identity, forged chunk-to-dependency mapping, removed HTML license link, and a fabricated ledger rights/adoption claim. A short-lived Actions artifact contains the actual source-only notice manifest and attribution file; it is **not** a signed distributable release.

## Remaining separate gates

Independently attributable rights-holder authorization, first-party provenance and distribution notice review for **all bytes that would actually be shipped**, generated source-to-native/build reproducibility, reviewed package/asset inclusion at installation time, noVNC and Python wheel inclusion if applicable, original credential-authority source/revision authorization, native issuer installation and actual protected administrator account changes all remain pending. Passing source CI gives no authority to distribute a release or rotate an administrator password.
