# Third-party licensing and release scope

For this new public-export candidate only, original station-access first-party
source, documentation and artwork held by Alex Black are offered under
**BSD-3-Clause OR GPL-3.0-only**. See [LICENSE](LICENSE) and the complete
[BSD-3-Clause](LICENSES/BSD-3-Clause.txt) /
[GPL-3.0-only](LICENSES/GPL-3.0-only.txt) texts. This authorized public grant
does not retroactively rewrite the private historical source records.
All independently authored dependencies, bundled libraries and upstream assets
retain their own licenses; this project does not assert ownership of them.

The browser build contains third-party libraries with their own copyright holders
and licenses. `npm run build` inventories the packages actually included by Rollup
and emits their full supplied license/notice texts, alongside the station-access
public dual-license notice, into a hashed `dist/assets/LICENSES-*.txt` file. `dist/index.html`
links this through `rel="license"`. `dist/frontend-build.json` records the bundled
package names, versions, license declarations and source/output hashes. Keep these
files with the JavaScript/CSS in every distribution. Vite-generated helpers are
covered by Vite's MIT notice, included separately in the build notices.

Dependencies installed separately (Django, Waitress, boto3, cryptography, dnspython and their
transitive dependencies, the external Zog components, noVNC/TurboVNC and rootfs
packages) are not relicensed here. Their notices and any source-distribution
obligations remain applicable to the actual release. npm development/test tooling
is not shipped in the browser bundle; its license metadata remains in the lockfile.
This build inventory is evidence for the bundled browser libraries, not a legal
clearance of the complete Zog operating-system distribution.

Before public release, the consolidation project still needs to reconcile the
exact companion revisions and their license grants, inventory the actual Python
and rootfs distributions and their notices/source requirements, and repeat its
secret/provenance review. In particular, a private companion repository without a
license grant does not acquire one from this repository.

License identifiers follow SPDX: https://spdx.org/licenses/ and
https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/ .

## Reviewed frontend output

See [the 2026-09-30 verification record](docs/station-access/FRONTEND-LICENSE-REVIEW.md) and `frontend/license-evidence.json` for exact reviewed artifacts and remaining scope. Builds now check published package bytes and explicitly reviewed legal paths, including support for nested/nonstandard paths. The previous top-level filename search alone was not comprehensive. `/licenses/` exposes the notice document as plain text; `/frontend-build.json` retains the inventory. The first release is source-focused and does not assume distribution of pre-built root filesystems.
