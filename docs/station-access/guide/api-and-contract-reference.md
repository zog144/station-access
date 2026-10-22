# API and contract reference

## Which interface is intended for which caller?

Station-access exposes **several distinct interfaces**, not one API with interchangeable authorization:

| Interface | Caller | Authentication and authority | Side effects |
|---|---|---|---|
| Browser/session and administrator REST APIs | React UI and authorized human administrators | Django session, user/Workspace ownership, CSRF for writes; superuser-only areas | Some explicit, reviewed lifecycle/credential/deployment operations |
| Workspace API `zog-workspace-api-v1` | Independent `tool-serve` or machine reader | One-time scoped bearer grant and exact Workspace UUID/owner snapshot | **GET-only**, no lifecycle, command, VNC grant or controller reconciliation |
| Compiler observer REST + owner RPC | Authenticated station superuser via Django | Separate station-owned TLS client identity; host-deploy server mTLS allowlist and exact owner epoch | Read-only owner-ledger observations; no compiler dispatch mutation |
| Signed host enrollment/heartbeat | Host-discover/host-identify sender | HTTPS plus host RFC 9421/Ed25519 signature and explicit approved Host key | May durably update accepted Host observations; not user-session authority |
| Archive grant and mirror metadata | Approved host or administrator | Exact archive JWT operation/collection scope versus separate admin session | Read-only inventory does not authorize arbitrary archive downloads or provider mutation |

A browser VNC/websockify grant, machine-client bearer token, host enrollment key and compiler mTLS certificate are **not interchangeable**. All externally visible responses must distinguish recorded data from an actually observed live service, and must not leak controller paths, TLS keys, journal selectors or cloud secrets.

## Read-only Workspace API: exact v1 boundary

The independent endpoint prefix is **`/api/agent/v1/`**. The maintained [Workspace Agent API contract](../WORKSPACE-AGENT-API.md) and its [JSON Schema 2020-12](../contracts/workspace-agent-v1.schema.json) define the exact response/error envelopes.

| GET endpoint (after prefix) | Required scope | Returned evidence |
|---|---|---|
| `capabilities/` | Any valid grant | Actual supported scopes and unavailable operations |
| `workspaces/?limit=20&after=0` | `workspace:read` | Authorized ordered Workspace identities, desired/expected/observed states |
| `workspaces/{uuid}/` | `workspace:read` | Stable UUID/number, mutable name and recorded status |
| `workspaces/{uuid}/applications/` | `applications:read` | Authorized catalogue and bound membership |
| `workspaces/{uuid}/runtimes/{runtime_id}/` | `runtimes:read` | Exact historical software/rootfs binding and advisory observation |
| `workspaces/{uuid}/runtimes/{runtime_id}/logs/` | `logs:read` | Identity-bound, bounded journald entries and cursor |

An operator issues a one-time `zog_agent_v1_` bearer grant via `manage.py agent_grant`; its secret is displayed once and only a hash is stored. Current v0.1.1 contracts require **both the selected Workspace UUID and its owner identity at issuance**, so an ownership transfer invalidates old grants, including service-bound grants. Revocation, expiry, account/workspace ownership and method scope are rechecked server-side on every call. At most 32 exact Workspace UUIDs per grant, maximum 30-day lifetime; no wildcard/write/VNC/shell scope. Browser session cookies do not replace the `Authorization: Bearer` requirement.

Workspace pagination uses a bounded decimal offset over authorized ordered results (limits 1–50); it can be stale if membership changes. Log pagination uses a separate opaque invocation/cursor token (limit 1–100 and token up to 4096 characters). An expired log cursor is HTTP 410, not an empty successful page. Unavailable, partial, busy or unknown controller evidence must be represented as such rather than fabricated zero counts, a healthy service or a completed lifecycle action.

Workspace API endpoints **never** call `ensure_workspace_ready`, launch, stop, reconcile, repair, kernel mount inspection or VNC grant creation. They are suitable for a read-only `tool-serve` consumer; they are not yet a generalized AI command execution API. Review the [seven example envelopes](../contracts/examples/) and independent HTTP/schema acceptance in [Workspace Agent API](../WORKSPACE-AGENT-API.md).

## Browser workspaces and controller integration

Session-authenticated Workspace CRUD, application launch/termination, logs and provenance are separate from the machine-client contract. Station-access authorizes owner/application/runtime before calling trusted local box-control. A launched generation and runtime are immutable historical facts; fresh systemd/process/mount observations have their own evidence/time basis. Client-provided PIDs, unit names or filesystem source paths are never general controller selectors.

The [portal](../PORTAL.md), [controller adapter](../BOX-CONTROL-ADAPTER.md), [workspace/VNC lifecycle](../VNC-WORKSPACES.md), [runtime logs](../BOX-CONTROL-LOGS.md) and [provenance](../WORKSPACE-PROVENANCE.md) record exact source contract boundaries. A browser disconnect does not automatically cancel a durable operation. Only a reviewed explicit mutation route may cause an application lifecycle transition.

## Host, archives and provenance REST APIs

The signed host v1 protocol is a *machine identity/ingestion* contract: approval binds the exact Ed25519 fingerprint to the immutable Host UUID; an authenticated heartbeat can update accepted Host observations. A matching public IP or AWS instance claim alone does not authorize enrollment, registry publication or archive access. See [signed host protocol](../SIGNED-HOST-PROTOCOL.md), [host generation](../HOST-GENERATION-AND-EXPORT.md) and [host registry matching](../REGISTRY-REMOVAL-MATCHING.md).

Administration's archive metadata endpoints are `GET /api/archives/mirrors/` and `GET /api/archives/items/`, both **superuser-only**, bounded and tied to complete immutable observation snapshots. An expired/superseded snapshot is a refresh-required state, not a guessed next page; a successful list is not a new live-host scan. Separate `POST /api/archives/reports/<host UUID>/` ingestion has its own authenticated sender/observation boundary, not browser list permission. See [archives API](../ARCHIVES-API.md) and [archive issuer authorization](../ARCHIVE-AUTHORIZATION.md).

Generation Detail uses `GET /api/archives/generations/<generation>/` with its exact mirror/snapshot/collection/rootfs-digest binding. It never presents a source archive as an installed generation or interprets missing notices as zero unresolved packages. Workspace provenance is `GET /api/workspaces/<workspace-uuid>/provenance/` with owner-scoped immutable runtime history. See [generation evidence](../GENERATION-PROVENANCE.md), [Workspace provenance](../WORKSPACE-PROVENANCE.md) and [host-generation export](../HOST-GENERATION-AND-EXPORT.md).

## Compiler status: separate mTLS observer

Authenticated station **superusers** may read `GET /api/compiler/status/` or `GET /api/compiler/dispatches/<canonical-32-hex-request-id>/`. The Django server uses its protected persistent-state `CompilerObserver` identity to make a server-side HTTPS/mTLS **POST** to the host-deploy owner RPC at the configured exact route `/v1/compiler/rpc`. Only `compiler.status` and `dispatch.status` operations are in this station client's method scope.

The server certificate/hostname must be verified, the client private key must not be sourced from a read-only host-export capability, and the host-deploy RPC pins the adopted owner/workspace/epoch. Results report bounded **owner-ledger observations**, not necessarily live SSM/systemd compiler health. Failed auth, wrong epoch, changed owner or transport uncertainty fails closed. Browser users cannot specify the compiler workspace, raw command, AWS instance or RPC method.

No observer certificate grants `dispatch.prepare`, `dispatch.submit` or `dispatch.observe`. See the [station compiler consumer contract](../COMPILER-OWNER-RPC.md) and exact reviewed [host-deploy RPC producer](https://github.com/zog144/host-deploy/blob/24be4cd3488ace40488256c3ea4a9cf4408b3130/docs/host-deploy/guide/compiler-owner-rpc.md). Source CI proves the mTLS client/loopback shape, not live routed acceptance or production port-443 cutover.

## Contract use and regression obligations

1. Read the **exact pinned version** and owner for the intended API; browser routes, Workspace v1 and compiler RPC v1 have separate schemas and permissions.
2. Validate closed input schemas, identity binding, scope/ownership and pagination **before** reading or dispatching privileged data.
3. Preserve read-only semantics and evidence basis for GETs; do not let a generic tool adapter invent mutation requests.
4. Use the component's checked-in JSON Schema/examples for machine Workspace clients. Unknown response fields containing secrets/host identifiers must fail schema validation, not be forwarded.
5. Keep `Cache-Control: no-store` on sensitive/observational responses and sanitize errors; do not log bearer credentials, private keys, host state paths or SSM payloads.
6. Report explicit test tiers: local Django fixtures, independent loopback HTTP/schema, mTLS test server and live deployed HTTPS/host-owner acceptance are **different**.
7. Do not infer live deployment or full tool-serve acceptance from source-only changes. The consumer must validate the actual installed service separately.

### Canonical source references

- [Workspace API HTTP, grants, examples, CI and independent client](../WORKSPACE-AGENT-API.md)
- [Workspace v1 machine-readable schema](../contracts/workspace-agent-v1.schema.json)
- [Compiler read-only mTLS consumer](../COMPILER-OWNER-RPC.md)
- [Portal/session and local controller integration](../PORTAL.md), [adapter](../BOX-CONTROL-ADAPTER.md)
- [Archives metadata and archive authorization](../ARCHIVES-API.md), [issuer](../ARCHIVE-AUTHORIZATION.md)
- [Signed Host identities](../SIGNED-HOST-PROTOCOL.md)
- [Generation provenance](../GENERATION-PROVENANCE.md) and [Workspace provenance](../WORKSPACE-PROVENANCE.md)

This chapter is a routing/reference synthesis; it does not replace the exact API schema or publish a new protocol.
