"""Transport-only Workspace API consumer; no Django or Zog imports.

Future tool-serve acceptance may use this example client with an issued scoped
grant. It intentionally never prints or stores Authorization headers.
"""
from __future__ import annotations

import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import urlencode


class WorkspaceApiClient:
    def __init__(self, base_url, bearer, *, timeout=5):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("HTTP(S) endpoint required")
        self.base_url = base_url.rstrip("/")
        self._bearer = bearer
        self.timeout = timeout

    def get(self, path, query=None):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Only absolute relative API paths are allowed")
        if "?" in path or "#" in path:
            raise ValueError("Supply query parameters separately")
        suffix = ("?" + urlencode(query)) if query else ""
        request = Request(self.base_url + path + suffix, headers={
            "Accept": "application/json",
            "Authorization": "Bearer " + self._bearer,
        }, method="GET")
        try:
            response = urlopen(request, timeout=self.timeout)
        except HTTPError as exc:
            response = exc
        with response:
            body = response.read(262145)
            if len(body) > 262144:
                raise ValueError("Unbounded Workspace API response")
            document = json.loads(body)
            if not isinstance(document, dict) or document.get("schema") != "zog-workspace-api-v1":
                raise ValueError("Unexpected Workspace API response")
            return response.status, document, dict(response.headers)
