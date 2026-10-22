"""Observation-only, owner-bound host-deploy compiler RPC consumer.

Only compiler.status and dispatch.status exist here. No generic send/call or
mutation method is exported. The key/certificate/configuration must reside in
station-access-owned *persistent* private storage, never a host-export mount.
Browser input can only supply an exact already-admitted request ID for
read-only dispatch status; it cannot choose endpoint, workspace, epoch or host.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import stat
from pathlib import Path
from urllib.parse import urlsplit

CONTRACT = "host-deploy-compiler-rpc-v1"
CONFIG_SCHEMA = "zog-station-compiler-rpc-client-v1"
MAX_REQUEST = 4096
MAX_RESPONSE = 8192
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_STATE = re.compile(r"[a-z][a-z0-9-]{0,48}\Z")
ERRORS = frozenset({
    "not-owned", "ownership-epoch-mismatch", "unavailable", "uncertain",
    "not-authorized", "invalid-operation",
})


class CompilerRPCUnavailable(Exception):
    """A bounded, safe status category only; never raw network/SSL exceptions."""

    def __init__(self, category="unavailable"):
        self.category = category if category in ERRORS else "unavailable"
        super().__init__(self.category)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate field")
        value[key] = item
    return value


def _decode(data):
    return json.loads(data, object_pairs_hook=_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))


def _private_directory(path):
    path = Path(path)
    if not path.is_absolute() or str(path) == "/" or ".." in path.parts:
        raise CompilerRPCUnavailable()
    current = Path("/")
    for piece in path.parts[1:]:
        current = current / piece
        try:
            meta = current.lstat()
        except OSError:
            raise CompilerRPCUnavailable() from None
        if not stat.S_ISDIR(meta.st_mode):
            raise CompilerRPCUnavailable()
    st = path.stat()
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise CompilerRPCUnavailable()
    return path


def _regular(path, *, maximum, secret):
    try:
        st = path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != os.geteuid()
                or (stat.S_IMODE(st.st_mode) & (0o077 if secret else 0o022))
                or st.st_size <= 0 or st.st_size > maximum):
            raise CompilerRPCUnavailable()
    except OSError:
        raise CompilerRPCUnavailable() from None
    return path


def _endpoint(value):
    if not isinstance(value, str) or len(value) > 512 or "\\" in value or any(c.isspace() for c in value):
        raise CompilerRPCUnavailable()
    try:
        parts = urlsplit(value)
        port = parts.port or 443
    except ValueError:
        raise CompilerRPCUnavailable() from None
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment
            or parts.path != "/v1/compiler/rpc" or not 1 <= port <= 65535
            or parts.netloc.endswith(":")):
        raise CompilerRPCUnavailable()
    return parts.hostname, port


def _safe_state(value):
    return value if isinstance(value, str) and SAFE_STATE.fullmatch(value) else None


class CompilerObserver:
    def __init__(self, *, host, port, workspace_id, ca, cert, key, timeout=4):
        if not isinstance(workspace_id, str) or not HEX32.fullmatch(workspace_id):
            raise CompilerRPCUnavailable()
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 10:
            raise CompilerRPCUnavailable()
        self._host, self._port, self._workspace_id = host, port, workspace_id
        self._ca, self._cert, self._key = str(ca), str(cert), str(key)
        self._timeout = timeout

    @classmethod
    def from_state_directory(cls, state_directory):
        # No caller-selected config path; all files are in one station-owned
        # persistent data subtree. Even an admin HTTP user cannot change it.
        state = Path(state_directory)
        if state.is_symlink():
            raise CompilerRPCUnavailable()
        home = _private_directory(state / "compiler-rpc")
        config = _regular(home / "configuration.json", maximum=4096, secret=True)
        ca = _regular(home / "server-ca.pem", maximum=65536, secret=False)
        cert = _regular(home / "client-cert.pem", maximum=65536, secret=False)
        key = _regular(home / "client-key.pem", maximum=65536, secret=True)
        try:
            # Open with NOFOLLOW and check identity again after opening:
            # avoid racing a changed sensitive configuration.
            fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(4097)
                if (os.fstat(stream.fileno()).st_ino != config.stat().st_ino
                        or len(data) > 4096):
                    raise CompilerRPCUnavailable()
            value = _decode(data)
        except (OSError, ValueError, UnicodeError):
            raise CompilerRPCUnavailable() from None
        if (type(value) is not dict or set(value) != {"schema", "endpoint", "workspace_id"}
                or value["schema"] != CONFIG_SCHEMA):
            raise CompilerRPCUnavailable()
        host, port = _endpoint(value["endpoint"])
        return cls(host=host, port=port, workspace_id=value["workspace_id"],
                   ca=ca, cert=cert, key=key)

    def _request(self, operation, parameters):
        # Caller cannot supply any operation/parameters other than these two.
        if operation == "compiler.status" and parameters == {}:
            pass
        elif operation == "dispatch.status" and (type(parameters) is dict
                and set(parameters) == {"request_id"} and
                type(parameters["request_id"]) is str and
                HEX32.fullmatch(parameters["request_id"])):
            pass
        else:
            raise CompilerRPCUnavailable("invalid-operation")
        body = json.dumps({"schema":CONTRACT, "operation":operation,
                           "parameters":parameters}, separators=(",", ":")).encode()
        if len(body) > MAX_REQUEST:
            raise CompilerRPCUnavailable("invalid-operation")
        connection = None
        try:
            # Fresh context; platform CA store is not silently used as an
            # alternate trust source for the configured owner RPC.
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=self._ca)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=self._cert, keyfile=self._key)
            # http.client makes no use of HTTP(S)_PROXY and never redirects.
            connection = http.client.HTTPSConnection(self._host, self._port,
                                                     timeout=self._timeout, context=ctx)
            connection.request("POST", "/v1/compiler/rpc", body=body, headers={
                "Content-Type":"application/json",
                "Accept":"application/json",
                "Connection":"close",
            })
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE or response.getheader("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                raise CompilerRPCUnavailable()
            message = _decode(raw)
            if type(message) is not dict or message.get("schema") != CONTRACT:
                raise CompilerRPCUnavailable()
            status = message.get("status")
            if status == "completed" and response.status == 200:
                if set(message) != {"schema", "status", "result"} or type(message["result"]) is not dict:
                    raise CompilerRPCUnavailable()
                return message["result"]
            if (status in ERRORS and response.status in (400, 403, 404, 409, 503)
                    and set(message) == {"schema", "status"}):
                raise CompilerRPCUnavailable(status)
            raise CompilerRPCUnavailable()
        except CompilerRPCUnavailable:
            raise
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException,
                ValueError, UnicodeError, TypeError):
            raise CompilerRPCUnavailable() from None
        finally:
            if connection:
                connection.close()

    def compiler_status(self):
        result = self._request("compiler.status", {})
        if (set(result) != {"workspace_id", "ownership", "compiler", "visibility"}
                or result["workspace_id"] != self._workspace_id
                or result["ownership"] != "owned" or result["compiler"] != "registered"
                or result["visibility"] != "owner-ledger"):
            raise CompilerRPCUnavailable("not-owned")
        # Do not echo the host-deploy workspace/epoch/compiler target in HTTP.
        return {"schema": CONTRACT, "state": "observed", "ownership": "owned",
                "compiler": "registered", "evidence_basis": "owner-ledger",
                "live_host_health": "not-observed"}

    def dispatch_status(self, request_id):
        if type(request_id) is not str or not HEX32.fullmatch(request_id):
            raise CompilerRPCUnavailable("invalid-operation")
        result = self._request("dispatch.status", {"request_id": request_id})
        if set(result) != {"request", "dispatch"}:
            raise CompilerRPCUnavailable()
        request = result["request"]
        dispatch = result["dispatch"]
        if (type(request) is not dict or
                set(request) != {"request_id", "operation", "admission", "dispatch", "completion"}
                or request["request_id"] != request_id or
                type(dispatch) is not dict or
                set(dispatch) != {"phase"} and set(dispatch) != {"phase", "binding_sha256", "submitted"}):
            raise CompilerRPCUnavailable()
        if "binding_sha256" in dispatch and (type(dispatch["binding_sha256"]) is not str
                or not HEX64.fullmatch(dispatch["binding_sha256"])):
            raise CompilerRPCUnavailable()
        if "submitted" in dispatch and type(dispatch["submitted"]) is not bool:
            raise CompilerRPCUnavailable()
        observed = {key:_safe_state(request[key]) for key in ("admission", "dispatch", "completion")}
        phase = _safe_state(dispatch["phase"])
        if None in (*observed.values(), phase):
            raise CompilerRPCUnavailable()
        # Do not expose raw operation payload, content digests, SSM IDs, paths.
        return {"schema": CONTRACT, "state": "observed",
                "request_id": request_id, "admission": observed["admission"],
                "dispatch": observed["dispatch"], "completion": observed["completion"],
                "phase": phase, "evidence_basis": "owner-ledger"}


def main(argv=None):
    """Isolated read-only mTLS acceptance probe; never grants cutover approval."""
    import argparse
    parser = argparse.ArgumentParser(description="Read-only host-deploy owner RPC observation")
    parser.add_argument("--state-directory", required=True,
                        help="Prepared station application-owned persistent state")
    args = parser.parse_args(argv)
    try:
        value = CompilerObserver.from_state_directory(args.state_directory).compiler_status()
        report = {"schema":CONTRACT,"state":value["state"],
                  "evidence_basis":value["evidence_basis"],"compiler":value["compiler"],
                  "live_host_health":"not-observed","safe_to_cut_over":False}
        print(json.dumps(report,sort_keys=True))
        return 0
    except CompilerRPCUnavailable as error:
        print(json.dumps({"schema":CONTRACT,"state":"unavailable",
                          "error":error.category,"safe_to_cut_over":False},sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
