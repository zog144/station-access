# Workspace lifecycle and recovery

New workspaces are dormant. Creation allocates a workspace number only. First use
allocates display/port values, persists running intent, and creates a launch request.
Workspace identity and allocation survive server replacement.

One per-workspace host-local `flock`, plus an in-process lock, serializes requests and
reconciliation across Django workers. The allocation lock serializes numbering and
display reservations; database uniqueness also protects numbers and endpoints.
No database transaction spans a call into box-control. This pass supports one host
and one shared state directory; it is not a distributed-lock design.

Launch sequence:

1. Persist endpoint and typed parameter values.
2. Obtain a controller request ID and commit it with `launch_pending=True`.
3. Call box-control with the recorded parameters and identity.
4. Persist exact runtime identity and clear pending state.
5. On connection demand, check current runtime facts and a bounded RFB banner.

A lost launch reply is recovered from a matching retained runtime (including its
parameter values), or retried with the original request ID. If the identity expired
and no evidence remains, the workspace faults rather than issuing a new request.
Missing previously-bound runtime evidence also blocks replacement. A proven terminal
runtime can be replaced with a fresh request ID and the existing endpoint assignment.

Stop commits stopped intent first and invalidates grants. A pending launch is resolved
through `cancel_application_launch`: this cancels an unstarted request or returns the
accepted runtime for exact termination. Recovery may first finish an already accepted
controller operation under the existing durability rules. Cancellation does not issue
a new launch. Ambiguous controller recovery remains blocked.

Endpoint changes and runtime replacement invalidate readiness, increment endpoint
revision, and revoke outstanding grants. Grant resolution rechecks current runtime,
active user, ownership, runtime identity and endpoint revision. Closing a viewer has
no effect on desired-running state.

`require_workspace_number` is the shared authorized first-use function for graphical
application integration. An RFB banner is a preliminary server gate; X11 authentication
and cross-program socket/mount plumbing still require the image-build integration pass.

Migration preserves existing identities/endpoints. Legacy pending launches without
recorded parameters require explicit recovery using the original controller; this pass
does not guess bindings for them. Admin cannot directly edit lifecycle fields or delete
workspace rows, avoiding orphaned runtimes. Workspace deletion is not implemented.


## Read-only readiness diagnostics (candidate)

`GET /api/workspaces/<id>/readiness/` now includes an advisory, read-only
`diagnostics` projection with five stable conditions:
`accepted-runtime`, `desktop-readiness`, `x11-authorization`,
`rfb-availability`, `browser-grant`. Each has a bounded
`confirmed | failed | unknown` status, allowlisted code, locally authored
explanation and evidence source. There are no private paths, raw controller
errors, token digests, mutable grant actions or launch/recovery side effects.

The accepted runtime requires a current matching controller identity and
running state, not a saved runtime ID. Desktop readiness additionally requires
a current matching controller access observation and the saved endpoint
revision's ready state. The older controller desktop access check is **aggregate**: it does not return
independently authenticated X11 authorization and RFB observations. Those two
conditions remain **unknown** without the separately reviewed current stage
contract, even when the combined desktop status is `ready`. Do not derive
separate successes from a saved socket pathname or a synthetic test fixture.

`browser-grant` is confirmed only for an unexpired, nonrevoked DB grant
matching the exact user, runtime, endpoint and revision **after** the current
desktop probe succeeds. A valid grant is *not* proof the browser successfully
connected. The panel labels previous successful observations as stale/unknown
after polling failure; no previous success is reused as a live observation.
The candidate box-control/root-control stage diagnostics supply independent
X11/RFB observations without changing authority or granting recovery powers.

The API remains authorized by the existing Workspace ownership check.
It neither mints a grant, restarts a desktop, nor empowers a diagnostic
consumer (including future Skiff) to act on an observation as authorization.
Native source/transport verification is still a separate acceptance gate.


## Candidate independent X11/RFB stage evidence (2026-11-02)

Selected immutable **source-only** companions: box-control PR #17 at
759085385f5a297c7e9f9f11bfbae487b146a600 and root-control PR #25 at
dedf5d8f1b6c51aa81fe6ceb342a978f3af11566. These are not
accepted production revisions. The public-companion-pins.json production
selection remains unchanged.

The optional read-only controller method returns stage proof only for the
current selected Workspace desktop, boot, incarnation and runtime. Root-control
independently verifies the current X11 authorization cookie and bounded RFB
greeting, checks peer identity and rechecks the selected runtime/authority
snapshot. Box-control validates the complete evidence schema and timestamp,
then reselects the desktop after probing. Station further requires exact
Workspace/runtime, nonempty boot/incarnation identity, 64-character opaque
endpoint identity, a five-second freshness window and allowlisted per-stage
statuses/codes. It rechecks the selected runtime and saved station endpoint
revision after the optional stage call. When aggregate desktop access was
confirmed, it also rechecks that endpoint. Stage evidence remains separately
useful when aggregate desktop access is unavailable (for example RFB fails)
while browser-grant readiness remains unknown. The five-stage API never passes private socket paths,
X11 cookie bytes, RFB greeting bytes, raw errors, or unbounded messages.

A current failed RFB observation may coexist with confirmed X11 authorization.
If the controller has no method, the boot or authority rotated, the runtime
was replaced, or any evidence is missing/stale/malformed, the stage status
remains UNKNOWN. The aggregate desktop-ready flag alone NEVER implies
X11 or RFB confirmation. Diagnostics grant no authority to launch,
recover or deliver capabilities. Real native probes remain separately gated.


## Draft viewer + diagnostics source composition (2026-11-03)

A source-only CI lane checks out the **exact immutable PR #19 viewer commit**
`62716629d1b7882f4c9d2ff6014bb1d697bd733f` and overlays only its
`VncSessionProvider`, `PersistentVncSessions`, `VncPage` and local viewer CSS
onto this PR #20's readiness/diagnostic source. The dedicated
`frontend/integration/workspace-viewer-readiness.test.tsx` suite runs
without VNC, noVNC, X11 or RFB servers. It neither merges the source
branches nor promotes either as a production companion pin. If the
PR #19 viewer head changes, its integration pin and tests must be reviewed
and rerun; the previous result does not cover new viewer bytes.

**Separation of concerns:**

- Existing established iframe sessions remain mounted when a new read-only
  diagnostic changes from confirmed to failed/unknown or controller inspection
  becomes unavailable. This avoids treating controller outage or a reported
  RFB failure as implicit authority to disconnect a potentially usable local
  Workspace. Neither persisted viewer state nor a diagnostic proves that a
  live browser WebSocket is still connected.
- Diagnostic `browser-grant: confirmed` describes a currently observed
  saved DB grant after controller checks. It is **not** an authorization
  token, cannot reconnect a closed iframe and cannot override the server's
  grant endpoint. Stale/failed observations likewise never mint a grant.
- Closing a browser viewer discards its session URL, not its local fit/zoom
  preferences or the remote Workspace. A subsequent explicit Connect must
  call the server-side `vncGrant` endpoint again; failure keeps the iframe
  closed and a fresh successful response provides a new URL. A late
  pre-close response is fenced by the per-Workspace pending-grant epoch.
- A successful, **explicit** desktop stop is different from an advisory
  observation: the owning Workspace page closes its iframe after the stop
  completes, while preserving local zoom and never automatically relaunching
  a desktop or issuing a replacement grant. Stop uncertainty remains visible
  for operator review.
- Controller status failure makes the readiness panel's Connect/Stop controls
  unavailable based on current observation. The viewer's separate Connect
  request, if explicitly invoked, still must pass its independent
  server-side grant authorization; read-only status cannot grant or revoke
  it. Browser-side iframe retention is not evidence of current authorization.

The integration lane covers these transitions and ownership boundaries
using synthetic API fixtures only. Exact runtime/boot/stage and endpoint
identity verification remains in the Python/controller source lane.
Native browser, authority, X11/RFB and recovery acceptance is still NO-GO.
