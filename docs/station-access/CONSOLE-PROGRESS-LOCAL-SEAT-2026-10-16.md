# Station-access — console-first progress and local-seat display design

**Date:** 2026-10-16
**Owner:** station-access Regular implementation
**Source status:** read-only remote consumer and fixture preview; no runtime admission.
**Contracts:** box-control `zog-application-progress-v1` and
`zog-local-session-capabilities-v1`.
**Design boundary:** console-first installation progress is owned by the
installer and its authenticated controller observers. Historical private
handoff material is intentionally excluded from the public source tree.
**Controller review:** `box-control/docs/box-control/CONSOLE-PROGRESS-LOCAL-SEAT-2026-10-16.md`.

## Product behavior

Administration → Setup readiness includes **Application build and runtime
progress**. The panel is available only to a logged-in station superuser.
It is a consumer, not an installer or controller. It provides an explicit
**Refresh controller progress** action and bounded **Next bounded page**
action; merely visiting the page starts no download, build, service,
reconciliation, login manager or polling timer.

A first-boot terminal can show host-welcome even when station-access is not
installed, configured or listening. This browser panel consequently says
**Not checked** before its first user-requested observation. A missing
socket, denied observer identity, older controller, stale evidence, bad
reply or failed root-runtime inspection becomes **Controller progress
unavailable**, *not* build success, stopped host, or an absent application
request. All evidence and errors remain bounded and redacted.

### Preview storyboard

```text
Setup readiness
  [Refresh observations]                  (existing station setup)
  Local station / Central registry ...    (existing checks)

Application build and runtime progress
  [Refresh controller progress]
  Controller observation: 2026-...        (only from authenticated source)
  Installation: not independently observed
  Software publication: not independently observed
  Controller records:
    Unassociated build command — building / uncertain
      "Build command outcome needs reconciliation"
      build job: <opaque validated job identity>
    Application runtime: firefox — launching / running
      "Application programs were observed active on this boot"
      selected view: sha256:<validated view>
      (neither publication nor browser rendering is established)
  [Next bounded page]                      (if producer has more)
  Local login and graphical seat:
    Local seat support: Not implemented
    Physical seat: unavailable; virtual seat: unavailable
    Login role: not-authorized
  Remote VNC desktops are NOT local login / greetd sessions
```

This is illustrative UI, *not evidence that a Firefox runtime or build
exists*. A genuine controller build row has `application=null`,
`attempt_id=null`, `stage_id=null`, `package=null` and
`command_index=null`; station must not guess which application a build
job belongs to. The image-build owner must separately provide an
authenticated attempt→stage→package→command→job association and verified
software-publication record. A terminal build command `succeeded`
proves **only that command phase**; it does not prove verified
publication, installation success, a rendering browser, or a greetd
login.

### Remote workspace and local console are distinct

Existing retained `zog-workspace-v1` and VNC/TurboVNC sessions are remote
workspace resources. Their `DISPLAY`, Xauthority, endpoints, runtime IDs
and session lifetime remain unchanged. Neither the progress UI nor
`zog-local-session-capabilities-v1` may treat a VNC desktop as
`seat0`, a VT, logind, PAM authentication, local greeter, virtual seat
or a physical monitor. The current local-session producer explicitly
says `supported=false`, `status=not-implemented`,
`login_role=not-authorized`; station does not expose a greetd start,
login command, session selector, seat number or password input.

An offline console and an intentionally headless installation remain
valid. An optional X11/Wayland/greetd/browser stack being absent does
not block base host readiness. The controller producer cannot attest
`not-requested` merely from no build rows: only the installer/intent
authority may say an application was not requested.

## Transport and permissions

**API:** authenticated superuser-only GET
`/api/setup/application-progress/`. Supported optional query fields:
`after_build` (validated lowercase 32-character job ID) and
`after_runtime` (validated controller runtime ID); each bounded
separately by the box-control client. No POST or custom project path,
socket path, host ID, program name, logfile, build-operation verb,
username or permission selector is accepted.

**Producer:** `zog.box_control.application_progress_client.ApplicationProgressClient`.
The socket and expected controller project-owner UID are pinned in
reviewed station deployment settings:

- `STATION_ACCESS_APPLICATION_PROGRESS_ENABLED=1` only after the owner
  installs the approved observer socket ACL and service
- `STATION_ACCESS_APPLICATION_PROGRESS_SOCKET` exact protected absolute
  AF_UNIX path
- `STATION_ACCESS_APPLICATION_PROGRESS_CONTROLLER_UID` existing nonroot
  controller project-owner numeric UID (not root or a globally assumed
  `regular` account)

The strict client authenticates the peer via `SO_PEERCRED`, validates
the bounded length, `zog-application-progress-v1` envelope, producer
field/status/message vocabulary, timestamp freshness and 4+4 item
page before the Django adapter projects user-safe data. Socket
ancestor permissions and listener activation are **owner provisioning**
requirements; application settings must never be copied from a
browser-provided request or untrusted response.

The station adapter returns
`zog-station-application-progress-view-v1` with
`read_only=true`, `availability=observed|unavailable`,
`observed_at`, `snapshot_id`, `boot_id`, null host and installation
IDs, `items`, independent `page` cursors, and an independent
`local_session` observation. Installation and publication state are
`unobserved` until independent authenticated producers join. It
copies only accepted opaque controller IDs and enumerated labels:
no argv, environment, log text, raw evidence_ref, source path,
hostname, credentials or workspaces. Ordinary users receive HTTP 403,
anonymous users 401; failures never expose private socket or project
paths. The response is no-store.

**Readiness integration:** the panel has its own manual controller
observation, independent from existing `/api/setup/readiness/`. A
regular setup refresh deliberately does not synchronously invoke the
up-to-12-second privileged read transport or trigger repeated
4-runtime observation. This prevents automatic refresh storms.
Each new page is a separate controller snapshot and must not be
conflated with an atomic multi-store checkpoint.

## Mapping and exact source mismatches

| Field/claim | Current controller producer | Station presentation |
| --- | --- | --- |
| Build `application` | null | **Unassociated build command** |
| Build phase/state | `queued/building`; phase outcome | Show exactly; `succeeded` is only command outcome |
| Build `progress` | null | No bar or percentage; no ETA |
| `attempt_id/stage_id/package/command_index` | null | No image-build linkage inferred |
| Runtime `application`, `runtime_id` | Validated name and ID | Controller runtime, not local seat |
| Runtime selected software view | Optional pinned digest | Record only, not verified publication |
| `host_id`, `installation_id` | null | Never manufacture host-install authority |
| Local session capabilities | `supported=false` | Explicitly not implemented |
| Selected optional graphical install request | Not a field | Neither `not-requested` nor `in-progress` inferred |
| Observed success with previous boot, pruned job | Uncertain/unknown | Never green, never recompute terminal outcome |
| Page IDs and cursors | Unique non-atomic page | Bounded navigation; not a durable progress history |

The current station dependency manifest pins **box-control
`d913e70585ab241696ebf771b93a398d5337217c`**, which predates the
read-only application-progress client. To enable the real adapter, the
box-control owner and station-access integration owner must advance the
pin to an audited controller revision containing both broker and strict
client; do not bump a large dependency invisibly while the public
repository migration and CI are incomplete. Until then the source
consumer **fails closed** with unavailable status. The newer controller
source documents current capabilities in
`docs/box-control/CONSOLE-PROGRESS-LOCAL-SEAT-2026-10-16.md`.

## Source and native acceptance

Fixture tests:
`python tools/test-backend.py tests.host_registry.test_application_progress`
and `npm test --prefix frontend -- --run`. The React preview verifies
not-checked first boot, source unavailability, missing/pruned job,
failed/uncertain state, phase success without publication and manual
page navigation; Django verifies administrator gating, unknown IDs,
bounded cursors, no raw errors, and no untrusted progress labels.
This is **not** a live socket or reboot/PAM test.

Native acceptance belongs to host-install/host-deploy Work. Verify
installed listener UID/DAC/SELinux and current boot, wrong-peer denial,
controller runtime observation timeout, real image-build publication
mapping, getty fallback, post-reboot unresolved jobs and a headless
installation. Later use a disposable virtual X11 stack, then separately
review greetd PAM/logind and a physical seat. No local login role,
graphical application or production traffic switch is authorized.
