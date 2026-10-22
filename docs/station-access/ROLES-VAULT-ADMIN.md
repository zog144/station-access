# Host cards, station login vault, and mirror roles — pass 3

This is a complete local source release. It does not modify the running command center, beaconers, AWS resources, or DNS. The previously delivered signed-identity release also requires its staged deployment; do not assume it is already running in production.

## Host cards

The Hosts page uses a responsive grid of black-outline panes. Each pane stacks host identification, classification, address/DNS, AWS state, heartbeat, login, and mirror-role controls. Search, filters, label editing, DNS editing, inventory coverage, and last-known data remain available. Long names wrap inside a pane rather than creating a horizontally scrolling table.

Logins are masked by default. Reveal is an explicit administrator-only, CSRF-protected POST audited with the administrator and credential revision. Passwords are held only in the current component's memory, hidden after 30 seconds, on tab hiding, on credential revision/source changes, and when the card unmounts. Reveal responses use `Cache-Control: no-store`. Browsers/screenshots/clipboard tools remain capable of capturing deliberately revealed secrets; this is an administrator vault, not a password manager browser extension.

## Create the central vault

Use the same runtime account as Django. Create `/var/lib/station-access/station-vault` with owner-only mode 0700, then, in the backend environment:

```
python manage.py create_station_vault /var/lib/station-access/station-vault/keyring.json
```

Set the service environment:

```
HOST_VAULT_CONFIGURATION=/var/lib/station-access/station-vault/keyring.json
```

The command exclusively creates a 0600 file; it never overwrites existing keys. The keyring contains a random AES-256-GCM encryption key, separate from the database, Django deployment secrets, host keys, and archive-token signing keys. Encrypt/decrypt uses host UUID and credential revision as authenticated context. Never include the keyring in a source archive, reusable rootfs, database dump, or ordinary backup bundle. Back it up separately using an encrypted administrator backup procedure: losing it loses access to existing encrypted credentials. Database administrators cannot decrypt a database-only copy; compromise of the running command center can access the vault, as intended by this early-development model.

The normal host list includes only availability, username, revision, timestamps, and whether the reporting key remains approved. Credentials do not enter `Host.report`, enrollment claims, ordinary identity responses, or audit event details. Existing encrypted credentials remain available to administrators after host revocation, with an outdated-source warning; revocation prevents further host updates and token issuance.

For rotation, add a new random 32-byte base64 key under a new key ID in the protected JSON keyring and change `active`. Retain old keys: subsequent credential reports re-encrypt that host's row under the active key. Before retiring an old key, verify that no StationCredential rows refer to its key ID and account for retained encrypted backups. This release does not automatically destroy keys or provide an unattended bulk rotation job.

## Provision the beacon's station login export

The hash in Django cannot recover a lost password. This release reads an existing known password; it does not reset passwords automatically. From each station's Django runtime, run:

```
python manage.py export_station_login --source /path/to/FIRST-LOGIN.txt --output /private/staging/station-login.json
```

The source must be an owner-only 0600 file, either the historical `Username: ...`/`Password: ...` format or JSON with `username`/`password`. The output parent must exist as an owner-only 0700 directory. The command checks the password against the current active superuser `station-admin`; a stale FIRST-LOGIN password fails without replacing a valid export. It prints no credential.

Through the trusted deployment connection, install the export as `/var/lib/host-discover/identity/station-login.json`, owned by the beacon account, mode 0600. Its parent is the beacon's existing 0700 directory. Set:

```
"station_login_file": "/var/lib/host-discover/identity/station-login.json"
```

The daemon sends it only with a signed, bound host heartbeat over verified HTTPS. The command center rechecks that exact key's approval under the same lock used for revocation before storing it. A missing, malformed, or incorrectly permissioned export is omitted with a sanitized diagnostic; it does not erase the last known central credential. Re-export after changing the station password. The command center records host-reported credentials; it does not attempt remote logins to validate their ongoing accuracy.

To explicitly withdraw the stored credential, set `"station_login_withdraw": true`; a successful signed heartbeat sends `station_login: null`. Removing the file/configuration alone means “no update,” not withdrawal. Disable withdrawal before publishing a new export.

Exclude FIRST-LOGIN files, station-login exports, databases, keyrings, and the complete identity/credential state directories from all shareable source archives and reusable images. Existing uploaded archives are not remotely scrubbed by this implementation; rotate any password that was previously disclosed.

## Select mirrors

In a host's pane, enter its explicit HTTPS origin and choose **Assign mirror role**. An approved public-key identity is required. Any subset may be selected, up to the initial bounded limit of 32 providers. This is administrator selection, not distributed leader election. Duplicate origins are refused. Multiple independent central writers are not introduced by this release.

The endpoint is an origin, for example the reserved non-deployable placeholder `https://mirror-01.example.org`, with no credentials, path, query, or fragment. DNS and TLS must already work. Saving uses the current role revision; stale concurrent edits are rejected. Assignment, receipt, starting, running, blocked/failed, and ready are different states. Ready means a fresh signed heartbeat reports that the local adapter checked all required programs and the HTTPS serving probe. It is not a separate central Internet reachability test. The UI ages readiness out when inventory refresh fails.

**Remove role; retain archives** withdraws the role on the next successful heartbeat. The daemon stops only its recorded application runtime (or cancels its uncertain pending start). All archive files and data remain in place. Offline hosts are shown as awaiting/stale and stop after their role lease expires when the controller can run. The application contract additionally requires self-enforcement of the lease so a dead beacon cannot leave an authorized schedule running indefinitely.

Provider assignment grants no download permission. Configure each consumer's operations and collections separately on Host identities. The existing 15-minute per-host Ed25519 token remains the sole archive access credential; there is no fleet password. Selected providers receive trusted public verification keys through local provisioning, never the command center's private signing key. All mirrors in the initial cluster use the same explicitly configured audience and enforce operation/collection grants on every request.

## Staged deployment and rollback

1. Retain protected backups of the current database, configuration, and signing/vault key material separately. For the supported signed identity protocol, follow [SIGNED-HOST-PROTOCOL.md](SIGNED-HOST-PROTOCOL.md). The earlier bearer-token migration is historical; use the maintained signed-host protocol and the release-specific, independently verified rollback plan instead. This page alone does not approve a production credential migration.
2. Install the current pinned dependency set from [DEPENDENCIES.md](DEPENDENCIES.md) into a staging environment. The following migration description records the original pass 3 transition; apply all migrations required by the selected current portal. Build the frontend. Run migrations through `0005_mirrorrole_stationcredential`; it adds tables without approving hosts, electing mirrors, or changing existing labels/DNS ownership.
3. Create/configure the vault, restart staging Django, and verify that ordinary host responses contain no passwords. Do not enable request-body capture in reverse proxies, Django debug output, tracing, or APM. Run production with DEBUG disabled. TLS verification remains required.
4. Provision one test beacon's persistent key, compare/approve its fingerprint, export its current station-admin login privately, and verify masked/reveal behavior. If the central vault is missing or unreadable, a heartbeat containing a login is rejected with a sanitized 503; ordinary heartbeats without this extension still work. Correct the vault configuration before enabling fleet-wide export.
5. Grant a test consumer only `download` on a test collection. Provision the public verifier keyring independently. Test token expiry, permitted download, and denied operations against the fixture. This is not a live mirror acceptance test.
6. Select one test provider. Without the optional installed application/adapter it should be blocked, not ready. After the mirror project implements MIRROR-STARTUP-CONTRACT.md, test start, all-process observation, serving probe, reboot/retry, network loss/lease expiry, and removal while retaining archive files.
7. Roll out to other hosts only after staging acceptance. The current independently maintained host-deploy must install these local packages, preserve identity state on reinstall, export credentials through its trusted connection, and use the configuration extension described above. Do not replace the independently maintained host-deploy owner with an archived historical deployment fixture.
8. Before rolling back the controller, remove all provider roles while online and confirm stops (or wait for lease expiry with a functioning lease-aware mirror application). Keep archive data and vault keys. Remove the new beacon configuration fields and restore compatible packages together. Leave the additive database tables in place unless a separately reviewed data rollback is intended.

Stock `deployment/signed-identity/host-discover.service` deliberately has no project-control privileges. A local administrator must configure the project, box-control/root-control authorization, service access to the project state, and the application's read-only intent/credential mounts before enabling the optional adapter. Do not grant broad root access or use the host's `/` as an implicit rootfs to make an incomplete deployment appear ready.
