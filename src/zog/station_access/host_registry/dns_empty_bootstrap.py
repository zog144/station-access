"""Explicit, zero-record shared DNS owner bootstrap for a fresh isolated station.

No legacy migration, A record, hostname grant, signer or cloud-identity changes.
The pinned provider credential is only resolved through the station vault.
"""
import fcntl
import json
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from django.conf import settings
from zog.network_register.contracts import NetworkError
from zog.network_register.ledger import digest
from zog.network_register.state import save
from zog.network_register.store import SqliteStateStore
from . import dns_setup
from .dns_evidence import owner_authorized, selection
from .dns_cutover import legacy_binding, controller_state
from .identity import locked as identity_locked
from .models import (
    ProviderCredential, DnsAssignment, AdditionalDnsAssignment,
    DnsDestination, ManagedDns01Hostname, CertificateAssignment,
    SecurityAudit,
)

REVIEW_SECONDS = 600
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
REVIEW_ID = re.compile(r"[0-9a-f]{64}\Z")


class EmptyBootstrapError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _paths():
    # A deployment must explicitly bind this fixed configuration filename.
    # Never accept browser/operator-provided state/ledger/configuration paths.
    state = Path(settings.STATE_DIRECTORY)
    root = state / "dns-controller"
    config = root / "configuration.json"
    if not getattr(settings, "HOST_DNS_CONFIGURATION", "") or (
            Path(settings.HOST_DNS_CONFIGURATION) != config):
        raise EmptyBootstrapError("protected-config-path-required")
    st = os.lstat(state)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or state.is_symlink()):
        raise EmptyBootstrapError("unsafe-station-state")
    return root, config


def _directory(path, *, create=False):
    if create:
        try:
            path.mkdir(mode=0o700)
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            pass
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
        raise EmptyBootstrapError("unsafe-dns-state")


@contextmanager
def _guard(*, create=False):
    root, config_path = _paths()
    _directory(root, create=create)
    from .dns_controller_lock import initialize_lock, writer_lock
    if create and not root.joinpath("controller.lock").exists() and not (
            root / "controller-lock-identity.json").exists():
        # Initial provisioning is permitted only in a genuinely empty
        # protected namespace. Do not write a new lock into foreign state.
        if any(root.iterdir()):
            raise EmptyBootstrapError("foreign-controller-state")
        # No automatic post-establishment lock recreation. A partially
        # written identity is a permanent operator-inspection stop.
        initialize_lock(root)
    with writer_lock(root):
        yield root, config_path


def _fresh_database():
    # This is exclusively for a *new* empty controller. Existing legacy
    # assignments and historic name reservations require normal migration.
    return not any(model.objects.exists() for model in (
        DnsAssignment, AdditionalDnsAssignment, DnsDestination,
        ManagedDns01Hostname, CertificateAssignment,
    ))


def _allowed_files(root, *, committed=False):
    allowed = {"controller.lock", "controller-lock-identity.json"}
    allowed.update(p.name for p in root.glob("dns-review-*.json"))
    if committed:
        allowed.update({"controller.json", "configuration.json", "empty-bootstrap.json",
                        "network-register"})
        allowed.update(p.name for p in root.glob("dns-ledger-*.sqlite3"))
    if set(p.name for p in root.iterdir()) != allowed:
        raise EmptyBootstrapError("foreign-controller-state")


def _load_review(root, review_id):
    if type(review_id) is not str or not REVIEW_ID.fullmatch(review_id):
        raise EmptyBootstrapError("invalid-review")
    try:
        data = _read_file(root / ("dns-review-" + review_id + ".json"), None)
    except (OSError, ValueError, UnicodeError):
        raise EmptyBootstrapError("review-unavailable") from None
    if (type(data) is not dict or digest(data) != review_id
            or data.get("kind") != "empty-shared-dns-bootstrap"
            or data.get("schema") != 1
            or data.get("legacy") != [] or not isinstance(data.get("selection"), dict)
            or type(data.get("expires_at")) is not int):
        raise EmptyBootstrapError("invalid-review")
    return data


def _config(data, state_root):
    s = data["selection"]
    return dict(domain=s["zone_name"], suffix=s["prefix"],
                account_id=data["account_id"],
                state_directory=str(state_root),
                # Legacy token fallback is deliberately not a credential source.
                token_file=str(state_root / "unavailable-legacy-token"))


def _selection_valid(data):
    s = data["selection"]
    if (type(s) is not dict or s.get("host_ids") != []
            or s.get("binding_id") != data.get("binding_id")
            or s.get("zone_name") != data.get("zone_name")
            or s.get("zone_id") != data.get("zone_id")
            or s.get("credential_id") != data.get("credential_id")
            or s.get("credential_revision") != data.get("credential_revision")
            or s.get("owner_user_id") != data.get("owner")):
        raise EmptyBootstrapError("invalid-review")
    selected = selection(s, allow_empty=True)
    if (selected.connection.provider != "cloudflare"
            or selected.connection.account_ref != data.get("account_id")
            or selected.binding.prefix != data.get("prefix")):
        raise EmptyBootstrapError("invalid-review")
    return selected


def _provider_check(data, *, collector=None, provider_factory=None):
    selected = _selection_valid(data)
    label = data["prefix"].split(".", 1)[0]
    current = dns_setup.candidate(
        data["owner"], data["credential_id"], data["credential_revision"],
        data["zone_id"], label, binding_id=data["binding_id"],
        provider_factory=provider_factory)
    if current != data["selection"]:
        raise EmptyBootstrapError("review-changed")
    dns_setup.validate(current, collector=collector, provider_factory=provider_factory)
    return selected


def review(*, owner, credential_id, credential_revision, zone_id, prefix_label,
           collector=None, provider_factory=None):
    owner_authorized(owner)
    if not isinstance(prefix_label, str) or not LABEL.fullmatch(prefix_label):
        raise EmptyBootstrapError("invalid-prefix")
    if type(credential_revision) is not int or credential_revision < 1:
        raise EmptyBootstrapError("invalid-credential-revision")
    with _guard(create=True) as (root, config_path):
        _allowed_files(root)
        if config_path.exists() or (root / "empty-bootstrap.json").exists() or (
                root / "controller.json").exists() or (root / "network-register").exists():
            raise EmptyBootstrapError("controller-already-initialized")
        if not _fresh_database():
            raise EmptyBootstrapError("existing-dns-ownership")
        credential = ProviderCredential.objects.get(pk=credential_id)
        if credential.provider != "cloudflare" or credential.revision != credential_revision:
            raise EmptyBootstrapError("credential-mismatch")
        selected = dns_setup.candidate(
            owner, credential_id, credential_revision, zone_id, prefix_label,
            provider_factory=provider_factory)
        if (selected["zone_name"] == selected["prefix"]
                or selected["host_ids"] != []):
            raise EmptyBootstrapError("invalid-selection")
        dns_setup.validate(selected, collector=collector, provider_factory=provider_factory)
        value = dict(schema=1, kind="empty-shared-dns-bootstrap",
                     nonce=str(uuid.uuid4()), owner=owner,
                     credential_id=str(credential_id), credential_revision=credential_revision,
                     account_id=credential.account_id, zone_id=selected["zone_id"],
                     zone_name=selected["zone_name"], prefix=selected["prefix"],
                     binding_id=selected["binding_id"], selection=selected, legacy=[],
                     expires_at=int(time.time()) + REVIEW_SECONDS)
        key = digest(value)
        save(root / ("dns-review-" + key + ".json"), value)
        return dict(review_id=key, expires_at=value["expires_at"],
                    account_id=value["account_id"], zone_id=value["zone_id"],
                    zone_name=value["zone_name"], prefix=value["prefix"],
                    owner=owner, credential_id=value["credential_id"],
                    credential_revision=value["credential_revision"],
                    writer="uninitialized", provider_writes=0, write_permission="unverified")


def _read_file(path, expected):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
                raise EmptyBootstrapError("unsafe-controller-file")
            raw = os.read(fd, 65537)
            if len(raw) > 65536:
                raise EmptyBootstrapError("controller-state-conflict")
            value = json.loads(raw)
            if expected is not None and value != expected:
                raise EmptyBootstrapError("controller-state-conflict")
            return value
        finally:
            os.close(fd)
    except (OSError, ValueError, UnicodeError):
        raise EmptyBootstrapError("controller-state-unavailable") from None


def _exclusive_json(path, value):
    if path.exists():
        _read_file(path, value)
        return
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise EmptyBootstrapError("controller-state-conflict") from None
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        # Never silently delete a possibly durable partial state.
        raise


def _ledger_identity(path, *, expected=None):
    """Check the *existing* SQLite inode before the generic store can open it.

    The directory is service-owned 0700 and callers hold controller.lock.
    Refuse symlinks, hardlinks, wrong UID/mode, path swaps, and a different
    saved inode. This check never invokes SQLite and never creates a file.
    """
    path = Path(path)
    _directory(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            current = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                    or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1
                    or not stat.S_ISREG(current.st_mode)
                    or current.st_uid != st.st_uid
                    or stat.S_IMODE(current.st_mode) != 0o600
                    or current.st_nlink != 1
                    or (st.st_dev, st.st_ino) != (current.st_dev, current.st_ino)):
                raise EmptyBootstrapError("unsafe-controller-ledger")
            identity = dict(device=st.st_dev, inode=st.st_ino)
            if expected is not None and (type(expected) is not dict
                    or set(expected) != {"device", "inode"}
                    or identity != expected):
                raise EmptyBootstrapError("ledger-file-identity-changed")
            # Recheck the path while our O_NOFOLLOW descriptor is still open.
            again = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISREG(again.st_mode)
                    or (again.st_dev, again.st_ino) !=
                       (st.st_dev, st.st_ino)):
                raise EmptyBootstrapError("ledger-file-identity-changed")
            return identity
        finally:
            os.close(fd)
    except OSError:
        raise EmptyBootstrapError("missing-or-unsafe-controller-ledger") from None


def _ready_ledger_identity(root, state, reviewed):
    """Authenticate saved bootstrap review and marker *without* opening SQLite."""
    if (reviewed.get("kind") != "empty-shared-dns-bootstrap"
            or reviewed.get("legacy") != []):
        raise EmptyBootstrapError("invalid-review")
    key = state["review_id"]
    data = _load_review(root, key)
    if reviewed != data:
        raise EmptyBootstrapError("review-mismatch")
    marker = _read_file(root / "empty-bootstrap.json", None)
    if (type(marker) is not dict or marker.get("schema") != 1
            or marker.get("kind") != "empty-shared-dns-bootstrap"
            or marker.get("review_id") != key or marker.get("stage") != "ledger-ready"
            or marker.get("owner") != data["owner"]
            or set(marker) != {"schema", "kind", "owner", "review_id",
                               "stage", "ledger_identity"}):
        raise EmptyBootstrapError("controller-state-conflict")
    return marker["ledger_identity"]


def preopen_runtime_ledger(root, state, reviewed):
    """Reject foreign ledger inode before SqliteStateStore/__init__/connect."""
    expected = _ready_ledger_identity(root, state, reviewed)
    _ledger_identity(root / ("dns-ledger-" + state["review_id"] + ".sqlite3"),
                     expected=expected)
    return expected


def _static_ledger(store, key, data, *, empty):
    """Exact static owner attestation; empty before writer activation only."""
    selected = _selection_valid(data)
    conn = asdict(selected.connection)
    binding = json.loads(json.dumps(asdict(selected.binding)))
    with store.transaction():
        db = store._db()  # Inspect keys as well as values: no foreign rows.
        rows = db.execute("SELECT kind, key, value FROM objects").fetchall()
        values = {}
        for kind, name, raw in rows:
            try:
                values[(kind, name)] = json.loads(raw)
            except (ValueError, TypeError):
                raise EmptyBootstrapError("invalid-controller-ledger") from None
        required = {
            ("meta", "schema"): {"version": 1},
            ("meta", "cutover"): {"review_id": key},
            ("meta", "empty-bootstrap"): {"review_id": key},
            ("connection", selected.connection.id): conn,
            ("binding", selected.binding.id): binding,
        }
        if any(values.get(k) != v for k, v in required.items()):
            raise EmptyBootstrapError("controller-ledger-conflict")
        if empty:
            # Includes unknown history kinds, allocations, receipts and meta.
            if values != required:
                raise EmptyBootstrapError("foreign-controller-history")
        else:
            # Legitimately admitted membership/operation/record history is
            # allowed, but additional connection or binding ownership is not.
            static = {k: v for k, v in values.items()
                      if k[0] in ("connection", "binding")}
            wanted = {k: v for k, v in required.items()
                      if k[0] in ("connection", "binding")}
            if static != wanted:
                raise EmptyBootstrapError("foreign-controller-ownership")


def verify_runtime(root, state, reviewed, store):
    """Recheck the original SQLite identity and static owner after readback."""
    expected = _ready_ledger_identity(root, state, reviewed)
    _ledger_identity(store.path, expected=expected)
    data = _load_review(root, state["review_id"])
    _static_ledger(store, state["review_id"], data, empty=False)
    _ledger_identity(store.path, expected=expected)


def _ledger(root, key, data, *, allow_create, empty=True, expected_identity=None):
    path = root / ("dns-ledger-" + key + ".sqlite3")
    if not path.exists() and not allow_create:
        raise EmptyBootstrapError("missing-controller-ledger")
    if path.exists() or path.is_symlink():
        before = _ledger_identity(path, expected=expected_identity)
    else:
        before = None
    # Refusal above occurs before the first transaction or sqlite3.connect.
    store = SqliteStateStore(path, create=before is None)
    if before is not None:
        _ledger_identity(path, expected=before)
    if before is None:
        before = _ledger_identity(path)
        # SqliteStateStore creates meta/schema in its initial transaction.
        selected = _selection_valid(data)
        with store.transaction():
            if any(store.all(kind) for kind in (
                    "connection", "binding", "record", "operation", "reservation",
                    "adoption", "membership-operation", "name-receipt",
                    "allocation", "membership")):
                raise EmptyBootstrapError("foreign-ledger")
            store.write("connection", selected.connection.id, asdict(selected.connection))
            store.write("binding", selected.binding.id,
                        json.loads(json.dumps(asdict(selected.binding))))
            store.write("meta", "cutover", {"review_id": key})
            store.write("meta", "empty-bootstrap", {"review_id": key})
    _static_ledger(store, key, data, empty=empty)
    if _ledger_identity(path) != before:
        raise EmptyBootstrapError("ledger-file-identity-changed")
    return store


def commit(*, owner, review_id, collector=None, provider_factory=None):
    owner_authorized(owner)
    with _guard() as (root, config_path):
        data = _load_review(root, review_id)
        if data["owner"] != owner:
            raise EmptyBootstrapError("wrong-review-owner")
        selected = _selection_valid(data)
        marker_path = root / "empty-bootstrap.json"
        marker = dict(schema=1, kind="empty-shared-dns-bootstrap",
                      review_id=review_id, owner=owner)
        existing = marker_path.exists()
        if not existing:
            _allowed_files(root)
            if (not _fresh_database() or config_path.exists() or
                    (root / "controller.json").exists() or
                    (root / "network-register").exists()):
                raise EmptyBootstrapError("existing-dns-ownership")
            if int(time.time()) > data["expires_at"]:
                raise EmptyBootstrapError("review-expired")
            stage = "reserved"
        else:
            try:
                raw = _read_file(marker_path, None)
            except (OSError, ValueError, UnicodeError):
                raise EmptyBootstrapError("controller-state-unavailable") from None
            if (not isinstance(raw, dict) or
                    {k: raw.get(k) for k in marker} != marker or
                    raw.get("stage") not in ("reserved", "creating-ledger", "ledger-ready")
                    or set(raw) != (set(marker) | {"stage"} |
                                   ({"ledger_identity"} if raw.get("stage") == "ledger-ready" else set()))):
                raise EmptyBootstrapError("controller-state-conflict")
            stage = raw["stage"]
        # Always recheck credential, active zone, delegation and complete
        # inventory BEFORE publishing or reopening an accepted controller.
        _provider_check(data, collector=collector, provider_factory=provider_factory)
        if not existing:
            _exclusive_json(marker_path, dict(marker, stage=stage))
        store_path = root / ("dns-ledger-" + review_id + ".sqlite3")
        if stage == "reserved":
            if store_path.exists() or config_path.exists() or (root / "controller.json").exists():
                raise EmptyBootstrapError("controller-state-conflict")
            # Persist intent BEFORE filesystem creation. If the subsequent
            # ledger is missing, this is uncertain/lost history, not a reason
            # to reinitialize it under the same identity.
            stage = "creating-ledger"
            save(marker_path, dict(marker, stage=stage))
            (root / "network-register").mkdir(mode=0o700)
            _directory(root / "network-register")
            _ledger(root, review_id, data, allow_create=True)
            stage = "ledger-ready"
            save(marker_path, dict(marker, stage=stage,
                                   ledger_identity=_ledger_identity(store_path)))
        else:
            _directory(root / "network-register")
            _ledger(root, review_id, data, allow_create=False,
                    empty=not (root / "controller.json").exists(),
                    expected_identity=(raw["ledger_identity"]
                                       if stage == "ledger-ready" else None))
            if stage == "creating-ledger":
                # Only a complete exact empty ledger may advance from the
                # uncertain creating stage; retain the original inode.
                stage = "ledger-ready"
                save(marker_path, dict(marker, stage=stage,
                                       ledger_identity=_ledger_identity(store_path)))
            elif raw["ledger_identity"] != _ledger_identity(store_path):
                raise EmptyBootstrapError("ledger-file-identity-changed")
        config = _config(data, root)
        _exclusive_json(config_path, config)
        ctrl = dict(schema=2, binding=legacy_binding(config), writer="shared",
                    review_id=review_id, stage="active")
        with identity_locked():
            owner_authorized(owner)
            # A second writer or an intervening name/record allocation must
            # not turn a reviewed empty controller into a false empty owner.
            if not (root / "controller.json").exists() and not _fresh_database():
                raise EmptyBootstrapError("existing-dns-ownership")
            if not SecurityAudit.objects.filter(
                    action="dns-empty-bootstrap", details__review_id=review_id).exists():
                SecurityAudit.objects.create(
                    actor="operator:" + str(owner), action="dns-empty-bootstrap",
                    details=dict(review_id=review_id, zone_id=data["zone_id"],
                                 zone_name=data["zone_name"], prefix=data["prefix"],
                                 provider_writes=0))
        _exclusive_json(root / "controller.json", ctrl)
        if controller_state(config) != ctrl:
            raise EmptyBootstrapError("controller-readback-failed")
        return dict(writer="shared", review_id=review_id, owner=owner,
                    zone_name=data["zone_name"], prefix=data["prefix"],
                    credential_id=data["credential_id"],
                    credential_revision=data["credential_revision"],
                    configuration=str(config_path), provider_writes=0,
                    replayed=existing)


def inspect(*, owner, review_id):
    """Read-only durable inspection; missing state always blocks."""
    owner_authorized(owner)
    with _guard() as (root, config_path):
        data = _load_review(root, review_id)
        if data["owner"] != owner:
            raise EmptyBootstrapError("wrong-review-owner")
        marker = dict(schema=1, kind="empty-shared-dns-bootstrap",
                      review_id=review_id, owner=owner)
        state_marker = _read_file(root / "empty-bootstrap.json", None)
        if (type(state_marker) is not dict
                or set(state_marker) != set(marker) | {"stage", "ledger_identity"}
                or any(state_marker.get(k) != v for k, v in marker.items())
                or state_marker["stage"] != "ledger-ready"):
            raise EmptyBootstrapError("controller-state-conflict")
        config = _config(data, root)
        _read_file(config_path, config)
        if state_marker["ledger_identity"] != _ledger_identity(
                root / ("dns-ledger-" + review_id + ".sqlite3")):
            raise EmptyBootstrapError("ledger-file-identity-changed")
        _ledger(root, review_id, data, allow_create=False, empty=False,
                expected_identity=state_marker["ledger_identity"])
        if controller_state(config) != dict(
                schema=2, binding=legacy_binding(config),
                writer="shared", review_id=review_id, stage="active"):
            raise EmptyBootstrapError("controller-state-conflict")
        return dict(writer="shared", review_id=review_id, owner=owner,
                    zone_name=data["zone_name"], prefix=data["prefix"],
                    credential_id=data["credential_id"],
                    credential_revision=data["credential_revision"],
                    provider_writes=0, write_permission="unverified")
