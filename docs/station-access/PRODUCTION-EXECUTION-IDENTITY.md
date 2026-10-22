# Controller-managed station execution identity

**Date:** 2026-10-12. **Source contract:** `zog-execution-identity-v1`.
**Production cutover:** NO-GO pending root-control grants and live acceptance.

## Source contract

The persistent single-instance station production template at
`integration/production/station-access/application.py` declares
`execution_identity="application"`. It deliberately does not specify
`user`, `group`, UID or GID for preparation or web. box-control resolves
the protected application grant before preparation and binds the same
numeric identity to both programs and durable runtime references.

The controller still uses `regular` as a *legacy parser placeholder*
before the symbolic grant has been bound. This is not an instruction to
create that host account. Missing, changed or stale grants must fail closed.
The original `integration/application.py` VNC multi-instance example has been
moved to `docs/station-access/legacy/noninstallable/vnc-application.py.txt`.
It is **historical, noninstallable** and cannot use this persistent-singleton
grant. The old `user="regular"` does not authorize a host account; a new
workspace-specific identity/runtime contract must be reviewed separately.

Rendering two immutable software views in `production_composition`
preserves the symbolic station declaration and rejects missing identity
or injected named credentials. The archive-mirror template is maintained
by its own owner and requires a **distinct** controller grant before
production rehearsal. Rendering remains source-only; it never provisions
grants or authorizes cutover.

## Host-deploy-owned execution and state migration acceptance

1. Inventory the actual host UID/GID allocation, reserved ranges, active
   processes, files and ACLs. The root-control *administrator* provisions
   the distinct station and archive grants in protected host state. Inspect
   the bound grant ID, version, project/application scope and numeric UID/GID
   through authoritative root-control evidence. Never infer IDs from the
   filename, template, browser, or the existing host UID/GID 993.
2. Explicitly review the existing station and archive state ownership and
   migrate from frozen copies into the prepared, *distinct* storage
   identities. Keep backups and fencing. Do not recursively chown existing
   controller storage, repair mismatches silently, or invent an identity.
   `state_migration.py` already refuses uncheckpointed SQLite WAL/SHM or
   journal files in its source; freeze and checkpoint before migration.
3. After explicit ownership migration, audit the new station state with
   the exact verified grant's UID/GID **inside its intended mount**.
   The read-only diagnostic below checks the main SQLite file, any present
   WAL/SHM/journal sidecars, deployment secrets, optional compiler-RPC
   credential bundle, directory traversal and conservative DAC. Its
   parameters are *observational expectations only*, never a grant:
   
   ```sh
   python -m zog.station_access.production_identity_audit \
     --state-directory /var/lib/station-access \
     --expected-uid <uid-from-protected-grant> \
     --expected-gid <gid-from-protected-grant>
   ```

   A mismatch is blocking and is **not automatically corrected**. The
   report omits host paths, certificates, hashes and secret contents,
   and always says `safe_to_cut_over=false`. It cannot authenticate
   the administrator's asserted UID/GID or prove no additional ACL access;
   root-control and host-deploy must do those checks independently.
4. Run the *exact application* prepare and web commands under box-control
   in an isolated candidate. Confirm the real systemd numeric User/Group,
   process real/effective/supplementary credentials, guest NSS compatibility,
   kernel mount DAC, read-only rootfs and immutability of expected references.
   Authenticate a browser login against the migrated SQLite database.
   Verify secrets are usable but not disclosed.
5. Verify compiler RPC `compiler.status` and `dispatch.status` using the
   **new candidate's** station-owned observer key, never inherited host
   export credentials. Reject mutation scopes, bad TLS and unavailable
   owner. Validate scheduler-only scoped `mirror-live` host-discover
   export visibility and renewal; the station **web** must have no grant.
6. Interrupt/restart preparation and web, then reboot only under separately
   approved host-deploy authority. Confirm exact grant binding and state
   ownership survive, no different identity is substituted, and no second
   compiler writer appears. Preserve live production until all independent
   gates—including archive-mirror—pass.

No nginx, 443, DNS, SQLite production migration, host credential
provisioning or compiler dispatch is performed by this repository pass.

## Source-only isolated acceptance tightening (2026-10-12)

The composition renderer now requires both production application templates
to use `execution_identity="application"`. The archive source was subsequently pinned to
`2858e83814a3bfcf2ac52d28b7d5e391b1b4e309` for its v2 ownership
guard (validated passing archive CI).
Per-program named `user`/`group` or an omitted grant fail parsing;
unreviewed mount targets, station commands and environment capabilities
are rejected before any rendered output is created. This does not
assert that two host grants were provisioned or that their numbers differ.

For an *isolated candidate* (not a live portal readiness shortcut),
request the stronger audit profile with `--require-compiler-rpc`.
It refuses missing/incomplete observer credentials, public certificate
files, unexpected observer-directory files, inconsistent SQLite WAL/SHM
presence and an active rollback journal, in addition to ownership/DAC
violations. Ordinary diagnostic mode retains pre-provisioning behavior.
Both profiles only observe caller-provided numeric expectations and
always report `safe_to_cut_over=false`; neither validates the protected
grant itself, cross-application ACLs or live systemd credentials.

A dedicated source regression migrates disposable initialized Django state
and independently verified archive data into separate storage IDs, then
starts the real module/Waitress server and signs in with the previously
created administrator credentials over loopback HTTP, preserving the
original `deployment-secrets.json` bytes. It does not touch any deployed
host or production database.

## Archive-mirror v2 ownership guard (2026-10-13)

The production renderer accepts the *specific* archive-owned environment
setting `ARCHIVE_MIRROR_REQUIRE_OWNERSHIP="1"` only for archive-mirror
`server` and `refresh-scheduler`, and requires that exact string value on
**both** programs after box-control's defined string normalization.
The shipped archive-mirror source uses literal string `"1"`. Numeric Python
`1` is accepted because the parser normalizes it to exactly `"1"`.
Missing, disabled (`"0"` or `0`), empty, boolean (`True`/`False`),
float (`1.0`), other altered, and whitespace variants block composition
before any output is created. This does not accept generic truthy values. The setting is
rejected on archive preparation and station web. No other environment
capabilities, host credentials, mount targets or caller-selected users are
introduced. The rendered immutable archive spec is checked again.

Cross-repository composition tests must use the pinned archive-mirror source;
an absent checkout is a test **failure**, not a skip. This is a static
source/template acceptance only. The runtime archive provider must still
verify actual controller ownership and host bindings at launch. The
host-deploy Work owner must obtain separate live proof before cutover;
this renderer does not bypass that guard or grant archive access to web.
