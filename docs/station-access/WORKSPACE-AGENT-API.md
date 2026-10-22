# Workspace API 0.1 — read-only machine-client contract

**Contract:** `zog-workspace-api-v1` — path prefix `/api/agent/v1/`.

This is an independent HTTP client interface for future `tool-serve` consumers;
the existing React/browser/session APIs are untouched. All endpoints accept
**GET only**, never create a desktop or application runtime, and never mutate
controller state. HTTP uses the server's ordinary HTTPS deployment configuration.
The VNC/websockify grant is *not* a Workspace API credential.

## Provisioning credentials

A local operator with station-access Django database access issues a scoped
credential with the management command (example; replace UUID and account):

```bash
python manage.py agent_grant issue --username alice --workspace 11111111-1111-4111-8111-111111111111 --scope workspace:read --scope applications:read --scope runtimes:read --scope logs:read --hours 24

python manage.py agent_grant issue --service tool-serve --workspace 11111111-1111-4111-8111-111111111111 --scope workspace:read --scope runtimes:read --hours 24

python manage.py agent_grant revoke <grant-uuid>
```

The newly issued `zog_agent_v1_<grant-uuid>.<secret>` bearer token is printed
**once**. Only its SHA-256 digest is stored; no endpoint reveals the secret
later. Operator must transfer the secret securely, without logging it,
placing it in source control, or putting it in a URL. Expiration and revocation
are verified on every API call. Maximum lifetime is 30 days; at most 32 exact
Workspace UUIDs may be granted per credential. User-bound grants additionally
respect current Workspace ownership and disabled-user state. Service-bound
grants require explicit privileged issuance and exact UUID allowlisting.
Changing the owner or deleting the Workspace prevents continued access.

`Authorization: Bearer <token>` must be provided even if a browser session
cookie is present. OAuth may later supply the same internal principal/grant
scopes; bearer tokens are the initial local-development authentication mechanism.

Scopes: `workspace:read`, `applications:read`, `runtimes:read`,
`logs:read`; a log-only grant may read bounded logs but not runtime metadata.
No wildcard/write/shell/VNC scopes exist.

## Endpoints

| GET | Required scope | Result |
| --- | --- | --- |
| `capabilities/` | Any valid grant | Enabled scopes, unsupported functions |
| `workspaces/?limit=20&after=0` | `workspace:read` | Accessible Workspace UUIDs, desired/expected/observed |
| `workspaces/{uuid}/` | `workspace:read` | Immutable identity and mutable display name/state |
| `workspaces/{uuid}/applications/?limit=20&after=0` | `applications:read` | Scoped catalogue and controller-backed membership |
| `workspaces/{uuid}/runtimes/{runtime_id}/` | `runtimes:read` | Immutable runtime identity, recorded software/rootfs, advisory observed state |
| `workspaces/{uuid}/runtimes/{runtime_id}/logs/?limit=50&cursor=...` | `logs:read` | Bounded invocation-scoped journald records |

Example:

```http
GET /api/agent/v1/workspaces/?limit=20&after=0 HTTP/1.1
Authorization: Bearer <one-time-token>
Accept: application/json
```

Response (representative IDs/states, not a live observation):

```json
{
  "schema": "zog-workspace-api-v1",
  "items": [{
    "id": "11111111-1111-4111-8111-111111111111",
    "name": "Research", "number": 2,
    "desired": {"running": false, "basis": "station-access-persisted"},
    "expected_launched": {"runtime_id": null, "instance_id": null,
      "launch_pending": false, "basis": "station-access-persisted"},
    "recorded_updated_at": "2026-10-10T18:00:00+00:00",
    "observed": {"status": "not-requested", "basis": "not-probed",
      "observed_at": null}
  }],
  "pagination": {"limit": 20, "next_cursor": null, "has_more": false},
  "state_source": "persisted-and-advisory-observation"
}
```

The decimal `after` cursor is a bounded offset into the *authorized*
ordered results and may become stale when Workspace membership changes. Page
size is 1–50. Log cursors are independent opaque tokens from the journald
reader, capped at 4096 characters; log page size is 1–100. A log cursor expired
in upstream storage is HTTP 410; do not synthesize a continuation.

Every response (including errors) has `Cache-Control: no-store` and
`X-Content-Type-Options: nosniff`. Error envelope:

```json
{"schema":"zog-workspace-api-v1",
 "error":{"code":"observation_unavailable","retryable":true}}
```

Errors: `authentication_required` (401), `insufficient_scope` (403),
`not_found` (404, including foreign Workspace/runtime), `invalid_pagination`
or `invalid_log_query` (400), `log_cursor_expired` (410),
`inspection_busy`, `observation_unavailable` and `logs_unavailable` (503,
retryable). Upstream internal paths or exceptions are never copied into errors.

## Evidence, privacy, and side effects

A Workspace name is presentation only, not identity. Desired state and
expected-launched runtime IDs are persisted evidence, not live system state.
When controller observation is unavailable, `basis: not-probed` is preserved
rather than reporting a healthy desktop. Runtime `expected_launched` keeps
the exact rootfs generation, software view/artifacts and binding digests;
`observed` is a separate advisory systemd snapshot (or unavailable).
Kernel mount observations are **unsupported in this scoped API** and remain
administrator-only in the browser/API.

A controller's incomplete/legacy workspace membership is explicitly
`unavailable`; no arbitrary runtime IDs are accepted as members. The
application catalogue for a service principal includes only names established
from the explicit workspace binding; user principals additionally see their
authorized application catalogue. An unverified/busy membership request fails
closed, without invoking readiness/reconciliation.

No request uses `ensure_workspace_ready`, launch, stop, VNC grant issuance,
host mutation, automatic repair, or arbitrary shell execution. Controller
root paths, VNC credentials, host PIDs/cgroups and cross-user identifiers are
not included in returned runtime data.

## Consumer handoff — tool-serve

`tool-serve` can store the one-time bearer credential securely and send these
versioned GETs as an ordinary independent HTTP client. Every tool should
advertise and enforce the scopes from `capabilities/` and return the structured
uncertainty/errors unchanged. Do not translate `unavailable` into an empty or
healthy result, reuse a VNC grant, or add lifecycle actions in this 0.1 pass.
Any later OAuth issuer must map to the same explicit scopes and Workspace UUID
allowlist and preserve server-side revocation/expiration semantics.

Acceptance requires Python/Django integration and the cross-repository
GitHub Actions suite; real host HTTP smoke acceptance remains separate.

## Acceptance and independent consumer status (October 10, 2026)

GitHub Actions 38089932495 (historical private CI/verification evidence; not distributed with public documentation)
passed three CI jobs on `unstable`: 263 host-registry tests (one ordinary-suite
privileged skip), 138 station-access tests, 24 archive-inventory tests (one
ordinary-suite optional-provider skip); both special cases passed in their
dedicated CI steps. The frontend production build and tests, Python component
wheel/namespace, and Django no-migration-drift checks passed. Dedicated
`tests.station_access.test_agent_api` cases cover independent bearer HTTP
calls, principal and Workspace authorization, grant revocation/expiry, denied
foreign runtime IDs, read-only operation, busy/unavailable evidence, historical
software identity, log bounds/cursors, and VNC credential isolation.

This is **CI and fixture-level HTTP acceptance**. Deployed-host HTTPS testing
with a real Workspace and the separate `tool-serve` MCP consumer remains
future integration work. The `tool-serve` program should consume the v1
contract without introducing a second runtime controller.


## Workspace API 0.1.1 — HTTP and schema acceptance

The independent transport client at
`tests/station_access/workspace_agent_http_client.py` uses Python's standard
`urllib` to send real TCP HTTP requests to Django's test server. It requires
**no Django imports** and never prints bearer credentials. The
`tests.station_access.test_agent_http` acceptance cases cover authentication,
cross-Workspace isolation, scoped service credentials, revocation/expiry,
owner transfers, authoritative controller runtime binding, bounded log cursors,
partial/unavailable observations, and read-only GET behavior.

The machine-readable JSON Schema 2020-12 definition is published at
`docs/contracts/workspace-agent-v1.schema.json` and includes endpoint-to-response
definition mappings. Seven example responses are available in
`docs/contracts/examples/`. The test suite uses a pinned JSON Schema validator
to check both the examples and actual loopback HTTP response shapes. Unknown
fields (such as arbitrary host PIDs, backing paths or credential secrets) are
rejected by the schema instead of being silently forwarded to `tool-serve`.

**Security note:** Workspace API grants are now bound to both exact UUIDs and
the Workspace owner IDs present at issuance. Changing ownership invalidates
those grants (including service-bound grants) until an operator explicitly
issues new ones. Grants created by older versions without ownership snapshots
fail closed after migration 0006 and must be reissued. Similarly, a
station-access persisted runtime ID without a matching authoritative controller
Workspace binding is not accepted by runtime/log endpoints. Legacy ambiguous
runtime references are unavailable rather than assumed authorized.

These are local independently connected HTTP regression tests, not deployed
HTTPS/EC2 acceptance. The future `tool-serve` consumer may reuse the documented
schemas and samples without creating a second lifecycle controller.

## Workspace API 0.1.1 acceptance (October 11, 2026)

GitHub Actions 38140737906 (historical private CI/verification evidence; not distributed with public documentation)
passed all three jobs: 263 host-registry tests (one skip in the standard
suite), 149 station-access tests, and 24 archive-inventory tests (one
optional-provider skip). Both exceptional cases passed their dedicated
privileged/provider CI steps. Frontend/build, component wheel/namespace,
and Django no-migration-drift checks all passed.

Six new independent HTTP tests use a *real loopback socket*, a threaded Django
live test server and a separate urllib-only consumer; they do not use Django's
in-process test Client. Three JSON Schema validation tests check the published
2020-12 contract and examples, including rejection of undocumented sensitive
fields. Live HTTP response envelopes are validated against the same schema.

**Operational follow-up:** reissue any older machine grants that predate the
ownership-snapshot migration; they fail closed. A real deployed HTTPS smoke
run and separate `tool-serve` MCP client acceptance are still pending.
