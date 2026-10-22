# Read-only host-deploy compiler RPC — station-access consumer

**Contract:** `host-deploy-compiler-rpc-v1`.
**Reviewed producer:** `zog144/host-deploy` commit
`1f0098e9484c64f73f07d7c975239b9b42d0cd8f`;
[compiler-owner-rpc.md](https://github.com/zog144/host-deploy/blob/24be4cd3488ace40488256c3ea4a9cf4408b3130/docs/host-deploy/guide/compiler-owner-rpc.md).

The client is `zog.station_access.compiler_rpc.CompilerObserver`. It is a
separate, read-only HTTP observer and **not** a replacement for the trusted
local `box_control` library used to manage user Workspace runtimes.
Do not import the historical `compiler_gateway:create_gateway`. Do not give
station-access the old bootstrap socket, direct EC2/SSM credentials, a generic
command runner, or another writable gateway ledger.

## Operator-owned private station state

Provision these files inside the application's **persistent station-data**
mount, all owned by the station web process UID (not the read-only
host-discover mirror export):

```text
/var/lib/station-access/compiler-rpc/          # 0700
    configuration.json                        # 0600
    server-ca.pem                             # 0600 or 0644
    client-cert.pem                           # 0600 or 0644
    client-key.pem                            # 0600
```

Example `configuration.json` (examples only; do not deploy unreviewed
identities or paste real keys):

```json
{
  "schema": "zog-station-compiler-rpc-client-v1",
  "endpoint": "https://compiler-rpc.owner.example:9443/v1/compiler/rpc",
  "workspace_id": "00000000-0000-4000-8000-000000000001"
}
```

The workspace UUID above is a synthetic example, never a deployment or ownership instruction. No other configuration keys are allowed. The browser cannot provide or change
this configuration. The actual endpoint hostname **must** be present in the
server's verified certificate SAN. CA trust is explicitly configured and
verified against the RPC host; the client certificate and key are presented
by Python's TLS layer, which requires TLS 1.2+. Files and containing
directories cannot be symlinks and the key/config must be private.

The station process consumes the fixed files relative to
`STATION_ACCESS_STATE_DIRECTORY`. The server's separate trusted configuration
pins the actual adopted host-deploy ownership epoch, EC2 instance, AWS account,
region and gateway ledger; none of those are supplied by station/browser
requests. The client checks that the returned owner `workspace_id` matches
its private configuration but **does not return the value to browsers**.

The host-deploy HTTPS process lives outside the station box-control
application; a network/firewall route from that application's **network
namespace** to the owner-host listener must be established by host-deploy.
Do not assume station's `127.0.0.1` is the host's loopback. A read-only
`mirror-live` host capability gives a directory only; it is not a socket or
network route. TLS files belong in persistent station-owned data and are not
sourced from this host capability.

## Isolated command-line acceptance probe

After the host-deploy owner service and station candidate are provisioned,
run **inside the candidate application's network namespace**:

```sh
python -m zog.station_access.compiler_rpc \
  --state-directory /var/lib/station-access
```

The program makes only a `compiler.status` observation using the same
fixed mTLS private-state configuration as Django. It emits bounded JSON with
`safe_to_cut_over=false`, never a writer authorization or proof of live EC2
compiler health. A nonzero exit is an unavailable/unsafe observation.
This supersedes the legacy `production_cutover` v1 Unix socket presence
diagnostic for the compiler side; the latter remains a fail-closed historical
compatibility probe and must not be used to assess the new HTTPS listener.

## HTTP observation contract

Only authenticated active station-access **superusers** may call:

```http
GET /api/compiler/status/
GET /api/compiler/dispatches/<canonical-32-hex-request-id>/
```

No HTTP POST, browser-selectable workspace ID, epoch, compiler source, SSM
document, AWS account/region, command or host path is exposed. GETs produce
server-side HTTPS POSTs to exactly `/v1/compiler/rpc` with:

```json
{"schema":"host-deploy-compiler-rpc-v1","operation":"compiler.status","parameters":{}}
```

or `dispatch.status` with exactly one canonical request ID. No mutation
methods are available in the client or the web API. The remote certificate
allowlist must give the station observer **only**
`compiler.status` and `dispatch.status`. A future separate station request
admission/dispatch control design requires new review and credentials; never
reuse the observer certificate for `dispatch.prepare`, `dispatch.submit`
or `dispatch.observe`.

Successful compiler JSON response:

```json
{
  "schema": "host-deploy-compiler-rpc-v1",
  "state": "observed",
  "ownership": "owned",
  "compiler": "registered",
  "evidence_basis": "owner-ledger",
  "live_host_health": "not-observed"
}
```

This is owner ledger visibility, **not** live compiler systemd/SSM health.
Dispatch output contains only `schema`, `state`, `request_id`,
`admission`, `dispatch`, `completion`, `phase`, `evidence_basis`.
No raw request operation, binding digest, ledger contents, source paths, SSM
results or secret material is returned.

Responses are always `Cache-Control: no-store`. The client enforces a
4-KiB outbound request cap and 8-KiB response cap, fixed URL path, no redirects,
no ambient proxy, a four-second connect/read timeout, strict result schema
validation and allowlisted error categories. Failures return bounded
`{"schema":"host-deploy-compiler-rpc-v1","state":"unavailable","error":"…"}`:
403 for `not-authorized`; 409 for missing/different owner,
epoch mismatch or uncertainty; 503 for transport/configuration failures;
400 for invalid operation/request ID. Raw exception messages are never
rendered in HTML or returned in JSON.

## CI versus real-host acceptance

The consumer suite uses a **real local loopback TLS server** signed by an
isolated test CA, whose listener requires a client certificate, while Django
tests enforce superuser authorization, fixed parameters and sanitization.
This validates client-side mTLS and the wire shape in CI; it does not prove
that the adopted host-deploy server has been deployed, trusted, routed or
firewall-reachable from a box-control application's isolated namespace.

Host-deploy Work acceptance must: confirm original ownership/adoption/epoch
and active writer; bring up one reviewed `host-deploy-compiler-rpc.service`
without new gateway writer or re-adoption; bind reachable HTTPS, firewall and
server/client certificate trust; provision the station observer identity into
copied private application state; launch an isolated station candidate and
validate successful `compiler.status`, `dispatch.status`, expired/mismatched
epoch, invalid cert and unauthorized mutation attempts; restart each service
and prove identities remain owned. This source pass does not change nginx,
DNS, production SQLite/archive storage, or the protected backups. Production
443 cutover remains a separate single-writer maintenance window.


## Dedicated production observer certificate and trust transition (2026-10-13)

This is a host-deploy **owner/provisioning** operation, not an instruction for
station-access to mint a client CA or to read the compiler owner's private
files. The earlier isolated acceptance client key **must not** be reused, and
its CA signing private key was discarded. Do not silently replace the current
server trust store or revoke other approved clients during the rollout.

1. The adopted host-deploy owner verifies the retained compiler workspace,
   exact owner epoch, active writer, existing server SAN/CA set, and every
   currently approved client fingerprint/scope. Record a redacted baseline.
2. Through a reviewed, protected issuer, generate a **new** production station
   observer keypair and short-lived client certificate with clientAuth EKU.
   If the existing client issuer cannot sign, explicitly add a newly approved
   issuer to the RPC server's **client** trust bundle alongside the old one,
   before authorizing the new certificate. Keep unrelated approved clients
   trusted until their own reviewed transition completes.
3. Add the new certificate's SHA-256 **DER fingerprint** to the owner-host
   allowlist with *only* \`compiler.status\` and \`dispatch.status\` permissions.
   This exact allowlist is authoritative; mere CA validity never confers
   compiler mutation or observer permissions. New credentials are not archive
   credentials, browser tokens or a delegated generic host capability.
4. Provision the reviewed endpoint, adopted 32-hex workspace ID, validated
   server CA, public client certificate and private client key under the
   **station application** grant's own persistent
   \`/var/lib/station-access/compiler-rpc/\` tree. Configuration/key mode 0600;
   directory mode 0700; certificate/CA mode 0600 or 0644. Ensure all files
   are owned by the real station process UID. Never place them in immutable
   software/rootfs, host-export, source control, environment values, URLs,
   nginx, archive storage or log records. Replace a complete candidate bundle
   under a fenced provisioner transaction; a partial bundle is a blocked state.
5. From the actual application network namespace run:

   \`\`\`sh
   python -m zog.station_access.compiler_rpc --state-directory /var/lib/station-access
   \`\`\`

   Then authenticate as a real station superuser and check
   \`GET /api/compiler/status/\` and an already-admitted
   \`GET /api/compiler/dispatches/<request-id>/\`. An observer success means
   the RPC owner ledger reports \`owned\`/\`registered\` for the configured
   workspace; it does **not** establish compiler process health or prove
   that the host's previously adopted epoch is current independently.
   Host-deploy must correlate its authoritative ledger/epoch before claiming
   acceptance. The station API intentionally does not disclose epoch or
   workspace identity to browsers.
6. Negative acceptance: missing private key, server name mismatch, untrusted
   or expired client certificate, CA-valid but *unallowlisted* fingerprint,
   wrong-role client certificate, absent owner/epoch mismatch, unavailable
   network/timeout and restart. Any failed check must remain unavailable
   or denied without a local direct-writer fallback. The source tests cover
   the bounded observer behavior; they cannot attest the real host policy.

**Rotation:** stage the replacement cert and add its fingerprint/scope before
switching the station bundle. Revalidate from the real application namespace,
then explicitly revoke the former station fingerprint. Remove retired trust
roots only after all separately approved clients have migrated.
**Revocation:** remove the compromised fingerprint promptly, fence the
affected station observer, issue a distinct replacement, and re-probe; do not
treat client certificate expiry or TLS failure as healthy. Never regenerate
the host-deploy owner epoch, re-adopt the compiler or replay old dispatches
as part of an observer rotation. Log only safe certificate fingerprints,
issuance/expiry dates and redacted evidence, never keys or PEM bodies.

The existing consumer continues to use its fixed, private
\`zog-station-compiler-rpc-client-v1\` format. No new browser-selected trust,
epoch or mutation interface is introduced by this handoff.
