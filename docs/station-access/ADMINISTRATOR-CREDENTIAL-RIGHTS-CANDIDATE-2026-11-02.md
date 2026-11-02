# Administrator credential v1: exact-source rights and dependency evidence (2026-11-02)

**Scope:** source provenance, dependency notices and consumer compatibility only. This is neither an owner-signed legal grant, an approved public release, nor native administrator credential installation. Reference tracking: [host-discover #4](https://github.com/zog144/host-discover/issues/4).

## Source revision and permission ledger

| Repository | Exact reviewed commit | Observed first-party license blob SHA-1 | Notice blob SHA-1 | Independent exact-revision legal permission |
|---|---|---|---|---|
| host-identify | `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b` | `e9ff0303fc483b30cee48e503f2c86e5b5b140e7` | `c365eb11014ac8abeed28f67778b51c9588992c1` | **PENDING** |
| host-discover PR #2 dependency | `ed63d8df3cb733192c82b60dd95d13389b9922b5` | `ca56aaf8d8fe938ed915ce2fdb58650ce2721a97` | `60264a9c522c3808ba687346ee816202862c6b5b` | **PENDING** |
| host-discover PR #3 profile | `4653cbffcef627dd8945dcb0d14deac5947e97fa` | `ca56aaf8d8fe938ed915ce2fdb58650ce2721a97` | `60264a9c522c3808ba687346ee816202862c6b5b` | **PENDING** |
| host-install PR #11 | `5c03d935be85622789b18559448e1560066d0a37` | `1b04ccfebcecd431a15e03bd9ff376826c0856f6` | `ac7c663f78201cba0f26c0f931e8f6c23e3714bf` | **PENDING** |
| station-access PR #18 | `a7faf74b23478f473cfb7908306bdc2dd5b3cffc` (source before this ledger correction) | `256b0d4cade2d0958384ddf803bf198a086796dc` | `81946531be927fe6f8beabbaf6d08ea7d93c194e` | **PENDING** |

The first-party files declare `BSD-3-Clause OR GPL-3.0-only` with full separate license texts. Their unchanged blobs support source-level license *continuity*, not an independently authenticated legal permission from the named copyright owner or any possible additional contributor. The public grants expressly exclude private historical source and independently acquired upstream material. GitHub authorship metadata is not a legal authority certificate. No specific infringement was found; confirmation is simply absent.

Host-discover PR #3 now has PR #2's exact head as a merge parent; only its three profile source/test/documentation blobs differ. The strict scope is the operator-selected `station-access` consumer, `station-access-administrator-password` purpose and `station-admin` credential identity, with account ID and revision separately signed. No production source has been repinned.

## Actual artifact boundaries / notices inventory

- **host-discover 0.4.14:** metadata requires `host-identify==0.3.5` and `host-install==0.14.9`; `setuptools>=80,<83` is a separately acquired build-system tool. The component's notes explicitly do not ship those sources. Its own test/dev tools retain their upstream licenses.
- **host-install 0.14.9:** standalone component metadata declares no runtime Python dependency; source uses separately acquired system and other Zog interfaces. Its notices exclude kernel, systemd, filesystem utilities, firmware and AWS tools from the first-party grant.
- **station-access 0.4.29:** metadata selects `host-identify==0.3.5`, `archive-mirror==0.4.2`, `network-register[dns]==0.12.0`, Django 5.2.x, Waitress 3.x and boto3 1.x, with separately selected controller and deployments extras. Its tested Python 3.12 environment is recorded in `requirements-security-tested.txt` (27 named distribution pins, including cryptography, requests and transitives). This is an inventory of the **tested environment**, not a complete notice pack or the actual release wheel contents.
- **Browser build:** npm/Rollup emits a bundled-package inventory, hashed full notice text and `rel="license"` link. Unbundled npm test tools are not a shipped browser distribution. The generated `dist/frontend-build.json` and `LICENSES-*.txt` must be checked against the *actual future output*, not reconstructed from the input manifest.
- **External software:** noVNC, TurboVNC, rootfs tools, Python environment, kernel, image-build packages and any native SSH/systemd/AWS components are outside this source candidate. Their notices, chosen license expressions, redistribution/source availability and upstream authenticity remain a separate complete release-bill-of-materials decision. None is assumed cleared by the first-party notices.

## Acceptance and follow-up boundary

Source/consumer checks previously passed on candidate heads:
host-discover [exact installer compatibility 41307288497](https://github.com/zog144/host-discover/actions/runs/41307288497),
host-install [source 41307164882](https://github.com/zog144/host-install/actions/runs/41307164882),
station-access PR #18 [exact three-owner 41312415374](https://github.com/zog144/station-access/actions/runs/41312415374),
[canonical HTTPS v1 41312415375](https://github.com/zog144/station-access/actions/runs/41312415375),
and [full source 41312415358](https://github.com/zog144/station-access/actions/runs/41312415358).
Those are compatibility/automated source tests, not independent owner-signed rights clearance. Recheck against the final head after this review-only correction.

Before a per-revision rights GO, obtain dated, authorized, independent original-owner/contributor attestations or equivalent verifiable grants **naming each exact revision** and preserving the old private-history exclusion; then verify full *distribution-derived* dependency/source/notice inventory, decide downstream BSD-vs-GPL obligations, and record separate acceptance/approval. A source-only pass cannot install a protected sender/FD receiver, activate a signing authority or publish/reuse a password.

The preceding `credential-v1-companion-candidate.json` had `rights_acceptance=accepted` for host-identify, host-discover and host-install without the independent grants required by host-discover #4. The new candidate manifest now explicitly marks that field **pending-independent-owner-attestation** while keeping verified consumer compatibility and all native/publication/delivery disallowances unchanged. The production `public-companion-pins.json` is **not modified**.
