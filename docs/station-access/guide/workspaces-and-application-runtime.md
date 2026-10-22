# Workspaces and application runtime

## One identity, multiple state perspectives

A Workspace has a stable UUID and a non-reused integer number; a user-facing name may change without changing identity. A Workspace is not equivalent to a transient graphical process or to any one attached application. The controller owns immutable runtime/request IDs; station-access persists desired desktop intent and known runtime binding, then may present a separately **observed** systemd or RFB status. A currently selected application spec must never be substituted for the software/rootfs a historical runtime actually launched.

The browser Workspace listing supports management and access decisions. Its VNC area is for the viewer; provenance and administrative actions can live on the selection page rather than crowding the live desktop.

## A lazy graphical seat, not implicit execution

New Workspace creation is dormant. First use can persist display/endpoint assignment and a durable controller request ID, then explicitly request a desktop runtime. A lost response is resolved using that same ID and persisted parameters, not a second guessed launch. Desktop readiness requires the accepted runtime and live RFB observation; the RFB banner alone is not proof of all X11 authorization and mount readiness.

The documented controller workspace profile is `host-shared`. This permits desktop and clients to use the host's initial network namespace and **must not be advertised as network isolation**. Desktop DISPLAY, Xauthority, VNC socket and controller-owned mount bindings are not arbitrary caller parameters. A client attaches to a desktop with an exact Workspace identity; stopping a client leaves the desktop separate. Consult [Workspace lifecycle](../VNC-WORKSPACES.md), [controller adapter](../BOX-CONTROL-ADAPTER.md) and [websockify boundary](../WEBSOCKIFY.md).

## Stop, cancellation and recovery

The portal persists stop intent and revokes viewer grants before resolving pending launch cancellation or exact-runtime termination. A pending operation can already have a controller-accepted runtime; recovery inspects it and applies the existing controller's idempotency and cleanup rules. Missing bound evidence or an expired request identity with no authoritative result must block replacement rather than silently launch another desktop.

Closing a viewer does not change desired-running state. Workspace and endpoint identity survive UI navigation and portal restarts, subject to the actual controller retention and host reboot outcomes. The dated [Workspace lifecycle](../VNC-WORKSPACES.md) document includes historical feature limits; use currently installed controller source and tests to establish availability of later CRUD or network capabilities.

## Workspace applications and machine clients

The Applications panel lists only authorized application declarations and attached runtime history; browsing is a read, not a launch. Explicit launch may be separately gated by installed desktop/proxy acceptance and deployment policy. The [Workspace API](../WORKSPACE-AGENT-API.md), intended as a read-only `tool-serve` consumer surface, uses GET endpoints, bounded pagination and scoped bearer grants. It does not launch a desktop, write controller state or provide an arbitrary command interface. Desired, expected-launched and observed fields retain distinct evidence bases; unknown live state is not reported as healthy.

## Runtime and build logs

Logs come from recorded program identity and invocation-scoped journald cursors, not raw user-supplied unit queries. Pages are bounded; stale cursors and unavailable identities are distinct from an empty stream. Log reads never trigger lifecycle recovery, and administrator build logs are not exposed as general user logs. See [box-control logs integration](../BOX-CONTROL-LOGS.md).

## Inspection versus authorization

Administrator-only application software inspection validates immutable view/artifact metadata from the trusted local project without publishing, mounting or changing anything. Historical runtimes report their **expected-launched** software and rootfs binding rather than today's selected view. Kernel mount observation is a different, manually refreshed administrative source; an immutable manifest or a preflight result is not live kernel evidence.

### Source contracts

- [Portal runtime and workspace operation](../PORTAL.md)
- [Workspace lifecycle and recovery](../VNC-WORKSPACES.md)
- [Workspace API and tool-serve handoff](../WORKSPACE-AGENT-API.md)
- [Application software inspection](../APPLICATION-SOFTWARE.md)
- [Invocation-bound logs](../BOX-CONTROL-LOGS.md)
- [Workspace provenance](../WORKSPACE-PROVENANCE.md)
