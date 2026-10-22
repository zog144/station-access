"""Administrator-only DNS reconciliation observation adapter.

The station owns host evidence, reviewed destination selection and authorization.
Only the network-register engine inspects provider inventory and reasons about
existing ownership. No planning, reservation, preparation, apply or DNS write.
"""
import fcntl
import os
from pathlib import Path
from contextlib import contextmanager
from zog.network_register.contracts import NetworkError

from .dns_cutover import controller_state, load_review
from .dns_evidence import owner_authorized
from .dns_shared import open_runtime
from .dns_destinations import runtime as additional_runtime, authorize as authorize_additional
from .models import DnsAssignment, DnsDestination, AdditionalDnsAssignment


@contextmanager
def _inspection_lock(config):
    """Use the central writer lock without creating a state file from GET."""
    root = Path(config["state_directory"])
    if (not root.is_dir() or root.is_symlink() or
            not (root / "network-register").is_dir()):
        raise NetworkError("storage")
    fd = os.open(root / "controller.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if controller_state(config)["writer"] not in ("shared", "paused"):
            raise NetworkError("permission")
        yield root


def inspect(config, host_id, *, actor_id, binding_id=None,
            collector=None, provider_factory=None):
    """Return the immutable, non-binding network-register schema-1 preview.

    Input is *only* a host and an optional existing destination identifier.
    DNS names, addresses, revisions, operation IDs and credentials are always
    loaded from station-owned records/evidence; not supplied by the browser.
    """
    if not config:
        raise NetworkError("storage")
    resource = str(host_id)
    # The controller lock serializes against the central writer. Unlike
    # refresh_intent/reconcile, this function never saves an assignment,
    # operation, reservation, identity, or provider record.
    with _inspection_lock(config) as root:
        if binding_id is None:
            # Refuse even provider authority reads for a different administrator.
            state = controller_state(config)
            reviewed = load_review(root, state["review_id"])
            if reviewed["selection"]["owner_user_id"] != actor_id:
                raise NetworkError("permission")
            owner_authorized(actor_id)
            selected, source, engine = open_runtime(
                config, root, collector=collector, provider_factory=provider_factory)
            if selected.owner_user_id != actor_id:
                raise NetworkError("permission")
            owner_authorized(selected.owner_user_id)
            if resource not in selected.host_ids:
                raise NetworkError("not-found")
            row = DnsAssignment.objects.get(host_id=host_id)
        else:
            destination = DnsDestination.objects.get(pk=binding_id, enabled=True)
            authorize_additional(destination, actor_id)
            selected, source, engine = additional_runtime(
                destination, root, collector=collector,
                provider_factory=provider_factory)
            if resource not in selected.host_ids:
                raise NetworkError("not-found")
            row = AdditionalDnsAssignment.objects.get(
                binding=destination, host_id=host_id, phase="ready")
        # Preview must derive the current verified address, never trust a
        # possibly stale projection from the last writer pass. Disabled
        # publication is explicit unpublication; missing/stale signed host
        # evidence blocks rather than silently becoming a delete.
        source.use_observed_address = True
        c, b = selected.connection, selected.binding
        evidence = source.host(c.owner_id, b.id, resource)
        if evidence.desired_revision != row.revision:
            raise NetworkError("conflict")
        if evidence.desired is None and row.enabled:
            raise NetworkError("permission")
        preview = engine.preview(
            c.owner_id, c.owner_id, b.id, resource, evidence.desired,
            evidence.desired_revision, delete=evidence.desired is None)
        # Engine rechecks authority and ledger after external provider reads.
        # A changed Django intent during that read must not return a candidate.
        row.refresh_from_db()
        if row.revision != evidence.desired_revision or row.enabled != evidence.publish_enabled:
            raise NetworkError("conflict")
        return preview.to_dict()
