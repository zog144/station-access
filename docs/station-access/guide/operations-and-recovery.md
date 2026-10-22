# Operations and recovery

## Evidence before action

Station-access distinguishes **configured intent**, **persisted expected-launched state**, **recent observation**, and **unknown/unavailable evidence**. An administrator opening Setup readiness, a Workspace card, an archive list or a log viewer should not accidentally issue a privileged mutation. The [readiness model](../SETUP-READINESS.md) intentionally avoids one misleading "everything ready" boolean because optional services and live checks vary by deployment.

The web server consumes controller, archive, host-inventory and provider results through narrow adapters. Browser sessions are not direct systemd/AWS access. State-changing operations require authenticated authority, request identities, exact targets and deliberate confirmation where applicable.

## Workspace and application recovery

A Workspace retains a stable UUID, number, intent and endpoint revision independent of the transient desktop process. An interrupted desktop launch is correlated by the **original box-control request ID** and the exact launch parameters/runtime binding. Retrying with a different ID while the first outcome is unknown risks duplicate work. A stopped, proven terminal runtime can be replaced only under the controller's normal admission and cleanup rules.

Stop persists stopped intent and invalidates viewer grants; pending launches are cancelled or resolved with the controller before terminating the exact accepted runtime. Viewer closure does not stop the desktop, and a desktop's restart does not imply its former GUI clients have recovered. See [workspace lifecycle](../VNC-WORKSPACES.md) and [portal application operation](../PORTAL.md).

## Journal and runtime inspection

Runtime logs are bounded invocation-scoped journald reads with opaque, identity-bound cursors. `cursor-unavailable` is not the same as empty history, and inability to inspect the recorded invocation must remain visible. These reads never reconcile lifecycle state. Administrator build logs are a separately authorized surface; [box-control logs](../BOX-CONTROL-LOGS.md) describes filtering and retention gaps.

Application software inspection verifies immutable selected views and artifact inventory but does not mount, launch, repair or reclaim software. Preflight checks are advisory. Historical launched runtime metadata must come from retained runtime references rather than resolving today's application declaration; manually refreshed kernel mount observations require their own evidence source. See [application software inspection](../APPLICATION-SOFTWARE.md).

## Archive, registry and host recovery

An archive inventory represents a completed immutable observation from a specified mirror/snapshot; a failed or stale observation cannot be treated as an empty or healthy catalogue. Pagination tied to a superseded snapshot requires restarting from the new snapshot rather than fabricating continuation. A signed mirror role or archive token does not mean the service has been installed or is reachable. See [archive metadata API](../ARCHIVES-API.md) and [mirror startup handoff](../MIRROR-STARTUP-CONTRACT.md).

Host enrollment and DNS reconciliation require current approved key identity, accepted signed report, matching provider/AWS inventory and an exact desired revision. Merely saving registry credentials or DNS targets does not establish ownership, write authority or successful reconciliation. Read-only provider diagnostics must remain read-only. See [signed host protocol](../SIGNED-HOST-PROTOCOL.md), [DNS evidence](../DNS-EVIDENCE.md), and [registries/deployments](../REGISTRIES-DEPLOYMENTS.md).

## Durable state and production migration

A production upgrade must preserve station database/secrets, separately owned archive content, host identity/lease sources and historical workflow records. Use a frozen, validated copy and never deploy two mutable owners against the same backing volume. The [station/archive state migration procedure](../PRODUCTION-STATE-MIGRATION.md) is an operator-controlled offline step and requires complete external host-deploy acceptance before actual traffic cutover.

If evidence is uncertain, preserve existing production services, stop new mutation admission and inspect the exact prepared operation/SSM/controller record. Do not reset an uncertainty marker or replay a remote command merely to make the UI appear healthy.

## Operator checklist

1. Record the exact deployed revision, state directory, published application view, controller project and ownership epoch.
2. Inspect readiness and any pending operations without mutation; distinguish live observation from stored intent.
3. Preserve backups, checkpoint signatures/digests and current writer/lease identity.
4. Repair the owning subsystem rather than granting station-access a direct bypass.
5. Test startup/reboot, lease renewal, immutable mounts, data consistency and rollback in isolation.
6. Authorize production cutover explicitly only after the accepted evidence is complete.

This guide organizes current contracts. Dated individual reports describe specific historical source and CI passes, not unconditional live deployment status.
