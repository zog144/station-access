# Update: production HTTPS origin and browser/proxy acceptance (2026-10-13)

The previous October 11 sections below are historical deployment preflight
evidence, not a statement that the October 13 isolated rehearsal failed. The
October 13 rehearsal established separate station/archive grants and persistent
storage, copied-data login/download, archive ownership and scoped lease
withdrawal. It did **not** establish final production nginx/443 acceptance,
automatic boot/role recovery, new observer mTLS provisioning or final migration.

## Reviewed station HTTPS origin binding

\`zog.station_access.production_composition\` now accepts the additional
operator-supplied \`--public-origin\` argument. It must be a canonical, complete
HTTPS origin with an actual DNS name and optionally an explicit port, **without**
path, query, fragment, user information or wildcard. Example:

\`\`\`sh
python -m zog.station_access.production_composition \
  --station-template integration/production/station-access/application.py \
  --archive-template dependencies/zog144/archive-mirror/integration/production/archive-mirror/application.py \
  --output-directory /path/to/new-reviewed-output \
  --station-view sha256:<exact-reviewed-station-view-digest> \
  --archive-view sha256:<exact-reviewed-archive-view-digest> \
  --public-origin https://<verified-external-dns-hostname>
\`\`\`

Use actual immutable digests and the host-deploy-approved DNS name, **not**
angle-bracket placeholders. Review the intended certificate SAN and existing
front-door TLS route before supplying that name. The renderer binds the
station **web** environment to the exact values:

| Setting | Bound value | Why |
| --- | --- | --- |
| \`STATION_ACCESS_ALLOWED_HOSTS\` | Selected hostname, without port | Match browser Host |
| \`STATION_ACCESS_CSRF_TRUSTED_ORIGINS\` | Exact \`https://hostname[:port]\` | Browser CSRF origin |
| \`STATION_ACCESS_SECURE_COOKIES\` | \`1\` | Secure session and CSRF cookies |
| \`STATION_ACCESS_TRUST_PROXY\` | \`1\` | Honor proxy-provided HTTPS scheme |

No other proxy headers, credentials or host-source paths are added. The archive
processes are not given these station web settings. The status records
\`public_origin_binding="explicit"\`. An omitted origin remains available for
disposable source-only rendering and is **unbound**, not a production-ready
candidate. Every renderer result, including the explicit-origin variant,
retains \`safe_to_cut_over=false\`.

**Critical proxy boundary:** station Waitress must listen only on a private
loopback or otherwise controller-isolated interface reachable solely by the
approved reverse proxy. The proxy must terminate and validate TLS, preserve
the reviewed public \`Host\`, **discard/overwrite** all client-supplied
\`X-Forwarded-Proto\` values with its own single observed scheme, and deny
direct untrusted requests to the backend. Configuring
\`STATION_ACCESS_TRUST_PROXY=1\` while exposing backend HTTP to untrusted
clients would let them spoof scheme/CSRF security. Avoid wildcard hosts and
public permissive CORS. The origin parameter alone does not configure nginx,
publish certificates, or authorize 443 traffic.

## Browser/recovery acceptance owner checklist

Through the approved private path to the candidate, test TLS with normal
certificate and hostname verification; an HTTPS \`-k\` check is insufficient.
Exercise both authenticated admin and ordinary/anonymous sessions; logout;
Archives list/detail/filter/pagination/notices and no misleading missing
license/observations; source/rootfs metadata; authorized download and denial
for a different collection; desktop and narrow mobile display at the same
published frontend revision. Keep redacted screenshot evidence distinct from
synthetic fixtures. Confirm both archive programs actually serve under their
controller-owned grant, only on elected role and valid lease, and stop safely
on withdrawal without affecting the station portal. Confirm the protected
compiler observer certificate is accessible only to station, the read-only
owner-ledger result is not conflated with live process health, and the server
trusts the verified current client fingerprint.

A source-only Django HTTPS/CSRF test exercises the intended session and
cookie settings. It does **not** verify deployed nginx, network isolation,
real TLS certificates, browser layout or live download authorization.
After source gates, host-deploy/Work must rehearse separate application and
controller restarts and carefully coordinate a host reboot once compiler idle
and ownership are re-confirmed. Retained grants/mounts/database/certificates
must be re-observed; runtime IDs need not remain constant.

Final maintenance-window migration/fencing and any traffic switch remain
host-deploy owner operations; a stale checkpoint must not overwrite new
production writes during rollback. The code here never switches nginx or
adopts a compiler host.

---

# Station-access production cutover — blocked host bindings (2026-10-11)

**Historical evidence basis:** an independently retained, revision-bound private source and host-binding handoff from October 11, 2026. Its original host-specific details are not part of a public installation contract; repeat preflight against the actual approved deployment environment.

The isolated application was verified, but **production port-443 cutover is not
authorized by this source-only pass**. The original nginx and station-access
writer must remain untouched. The toolchain host deployment and adopted workspace
are owned by host-deploy, not this repository/chat.

## What is missing

- box-control permits application-owned writable mounts, immutable software
  mounts and specially derived workspace mounts. It does **not** allow programs
  to nominate arbitrary host paths.
- root-control independently rejects extra read-only paths and writable sources
  outside owned STATE. Circumventing it through transient systemd unit edits,
  symlinks, a broad /run bind or a copied lease is forbidden.
- host-discover's `mirror-intent.json` is periodically atomically replaced;
  mount its **parent directory**, never the file inode. Preserve the current
  authoritative host-discover process and its credential ownership.
- The historical `compiler_gateway:create_gateway` is not compatible with
  `zog.*` imports and must not regain direct write ownership over the adopted
  compiler workspace.
- Production archive/store, station database/secrets and managed runtime must
  have deliberate separate durable storage and startup/reboot policies.

## Accepted upstream host-directory capability contract

Since the handoff was published, **box-control** introduced the narrow
administrator-owned host binding contract at
`box-control/catalogue/host-capabilities.md`, head
`7d1bcdd695a5764d65ba2739749c9a7d005386e7`. **root-control** independently
validates it at head `b84abe526a0aa7b5b3a1e42c6c9675ccd66f52b5`.
The policy file is root-owned `/etc/zog/host-bindings.json` (not writable by
group/other), selecting an exact project, application and program. Application
specifications never choose the host source. The binding is read-only for an
entire **directory**, not a single mutable lease inode. Root-control
independently revalidates the policy, source inode/device, identity and mount
inventory before starting. Cleanup never owns the host source.

For this cutover the example accepted grant is `mirror-live`, targeted at
`/run/zog-host/mirror-live` for the `station-access` **scheduler** program,
*not* the web program. Its source must be an administrator-provisioned,
least-privilege host-discover export directory. Never grant access to all of
host-discover's identity/credential state.

This upstream contract supports read-only directory bindings only. **It does
not support host socket bindings, an authenticated compiler gateway, or
writable host-owned archive store binds.** Those production dependencies still
block an actual cutover. No source-level CI run proves a real host was changed,
and this consumer preflight cannot manufacture those missing privileges.

Expected production resources, with deployment-specific paths deliberately
bound by the host owner rather than station-access source:

| Capability | Consumer guest destination | Policy |
| --- | --- | --- |
| `host-discover-intent` | `/run/zog-host/mirror-live` | Read-only **host capability directory**, scheduler only; renewals visible |
| `host-controller-observation` | *Not yet provisioned* | Future authenticated host-deploy gateway; no socket-capability support yet |
| `archive-data` | `/var/lib/archive-mirror/store` | Application-owned persistent volume; explicit data migration |
| `station-data` | `/var/lib/station-access` | Persistent volume; migration/copy and single-writer fence |

The gateway must respect the actual owner-approved, durably retained workspace
identity and ownership epoch. Their concrete production values are kept in
private host-deploy/owner records, not this public source example. Read-only compiler observation and
authorized mutations must be separate actions; no new direct EC2/SSM writer is
implied by socket connectivity. A future gateway must validate connected
credentials (including SO_PEERCRED) and caller scopes. Do not reuse the existing
host-discover-only peer-UID970 gateway as a general-purpose station endpoint.

## Consumer-side preflight now provided

Run **inside the candidate application mount namespace** with an operator
prepared JSON policy (no secret bytes):

```sh
python -m zog.station_access.production_cutover --policy /var/lib/station-access/cutover-policy.json
```

The consumer checks directory presence/non-symlink paths and access permissions,
reopens the host-discover intent by name on each read so atomic renewal is
visible, verifies its host identity/lease expiry, and detects a present Unix
gateway socket without claiming peer authorization. It emits only bounded status
strings: never intent content, credential bytes or absolute backing paths.
The policy explicitly rejects the old `compiler_gateway` factory and legacy
direct socket control.

**Every result deliberately returns `safe_to_cut_over: false`**: source-side
resource visibility is neither kernel mount integrity verification, gateway
peer authentication, nor host-deploy adoption/ownership authorization. Real
cutover readiness requires those external proofs and a single-writer gate.

## Work-side acceptance and rollback

After upstream capability support, verify on the adopted host through its
existing host-deploy workspace only. Preserve the untouched protected backup
`/var/backups/zog/station-cutover-20261011`; it is not an automatic rollback
image after new writes. First rehearse the complete candidate with copied
application state and archive metadata on an isolated listener. Confirm
authoritative read-only bind inventories and kernel mount observation, host
intent renewal, signed archive collection authorization, current host-deploy
ownership and compiler read-only observation, and bootstrap/reboot persistence.

For an actual cutover, stop the old writer briefly, take a fresh consistent
SQLite backup and migrate that *new* copy, start one candidate writer, check
authenticated readiness, and only then change nginx. If a pre-acceptance check
fails, restore traffic without attempting a stale database rollback after
new writes. Explicitly coordinate controller ownership and maintenance
window with host-deploy. No launch, migration, nginx change or host writer
action is performed by this repository pass.

## Acceptance sequence remaining after upstream source publication

Do not interpret the host-binding sources landing in box-control/root-control as
the cutover being fixed on the toolchain host. The host-discover exported mirror
directory must first be implemented and provisioned. Its producer must retain
atomic replacements and lease/host identity validation; station-access must not
be given the entire enrollment credential tree. The compiler control path must
be a separate authenticated host-deploy-owned gateway whose consumer is
namespaced and restricted, not a direct old bootstrap socket. A separate durable
archive store migration and controller-on-boot unit test are also necessary.
The original host-deploy owner must conduct the isolated rehearsal and 443
maintenance window; this station-access source chat cannot claim those results.

## Producer export source acceptance

host-discover now implements the optional
`mirror_live_export_directory` producer configuration at commit
`b56a47898fca5ede7b132734aa8017123c215386`, documented in
the maintained [host-discover live-export contract](https://github.com/zog144/host-discover/blob/0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80/docs/host-discover/HOST-LIVE-EXPORT.md). Its GitHub Actions
`38162395252` passed. When enabled, it publishes only
`mirror-intent.json` and `mirror-candidates.json` to a dedicated
host-discover-owned 0750 directory under `/run/zog-host-export/` or
`/var/lib/zog-host-export/`, with atomic 0640 child replacement.
It rejects unsafe directories, and does not export host identity keys,
archive bearer credentials or station login secrets.

Proposed operator staging (these are **deployment inputs**, not actions
performed by this source change):

```json
{
  "schema": 1,
  "bindings": [
    {
      "project": "/root/zog-station-production",
      "application": "station-access",
      "program": "scheduler",
      "capability": "mirror-live",
      "source": "/run/zog-host-export/mirror-live"
    }
  ]
}
```

The project root above is an **illustrative placeholder**. The adopted
host-deploy workspace must supply its exact production controller project
and verify expected and kernel-observed binding identities. The web
program receives no host grant. Provision ownership/group permissions
without broadening host-discover's general credential directory.

The station-access preflight policy must point its
`host_discover_credentials` *guest destination* to
`/run/zog-host/mirror-live`, not to the host source or to
`/var/lib/host-discover/credentials`. A valid intent lease is not
authentication for the compiler gateway or permission to cut over.

**Still blocked:** authentic host-deploy-controlled compiler RPC and
namespaced adapter, durable archive-data and station-data migration,
controller boot management, and real-host cutover/restart/rollback acceptance.

## Exact-pin CI acceptance (2026-10-11)

GitHub Actions run 38162462421 (historical private CI/verification evidence; not distributed with public documentation)
passed all three jobs at source commit `f7dde49b9b11efa0f3b3ad6664aecd985577708f`:
263 host-registry tests (one skipped in the ordinary suite), 158 station-access
tests, and 24 archive-inventory tests (one skipped in the ordinary suite).
The two exceptional privileged/provider fixtures passed in their dedicated
steps. Frontend and Python wheel/namespace jobs passed; Django reported no
migration drift. The combined pins include host-discover live export,
box-control host capabilities, and root-control validation.

This is source/fixture acceptance, **not** kernel mount, owner gateway, actual
archive store migration, or HTTPS port-443 cutover acceptance.
