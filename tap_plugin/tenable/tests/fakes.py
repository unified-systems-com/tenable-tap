"""Test doubles for the Tenable transport: a fake adapter and envelope builders. No socket is opened."""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import requests
from requests.adapters import BaseAdapter

from tap_plugin.tenable.credential import Credential, credential_from_envelope

ACCESS = "accessKEY0123456789abcdef"
SECRET = "secretKEY0123456789abcdef"
ADMIN_ACCESS = "adminACCESS0123456789abc"
ADMIN_SECRET = "adminSECRET0123456789abc"
BASE = "https://sc.example:443"


def ok(payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    """A Security Center envelope around ``payload``."""
    body = json.dumps({"type": "regular", "response": payload, "error_code": 0, "error_msg": "", "warnings": [], "timestamp": 0}).encode()
    return status, body, {"content-type": "application/json", **(headers or {})}


def raw(status: int, body: bytes | str = b"", headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    return status, body.encode() if isinstance(body, str) else body, {"content-type": "application/json", **(headers or {})}


SYSTEM = ok({"version": "6.4.0", "buildID": "202401010000", "uuid": "abc"})


@dataclass
class Sent:
    method: str
    path: str
    params: dict[str, str]
    body: Any
    headers: dict[str, str]


@dataclass
class FakeAdapter(BaseAdapter):
    """Answers by (method, path); each route is a list of replies used in order (the last repeats) or a callable."""

    routes: dict[tuple[str, str], Any] = field(default_factory=dict)
    sent: list[Sent] = field(default_factory=list)
    raise_on: dict[tuple[str, str], list[Exception]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__()
        self.routes.setdefault(("GET", "/rest/system"), [SYSTEM])

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        parts = urlsplit(str(request.url))
        body = json.loads(request.body) if request.body else None
        self.sent.append(Sent(str(request.method), parts.path, dict(parse_qsl(parts.query)), body, dict(request.headers)))
        key = (str(request.method), parts.path)
        pending = self.raise_on.get(key)
        if pending:
            raise pending.pop(0)
        route = self.routes.get(key)
        if route is None:
            reply = raw(404, json.dumps({"error_code": 404, "error_msg": "not found"}))
        elif callable(route):
            reply = route(self.sent[-1])
        else:
            reply = route.pop(0) if len(route) > 1 else route[0]
        status, content, headers = reply
        response = requests.Response()
        response.status_code = status
        response.headers.update(headers)
        response.raw = io.BytesIO(content)
        response.url = str(request.url)
        response.request = request
        return response

    def close(self) -> None:
        pass

    def paths(self) -> list[str]:
        return [f"{s.method} {s.path}" for s in self.sent]


def envelope_payload(key: str = "sc-one", **data: Any) -> dict[str, Any]:
    base = {"base_url": BASE, "access_key": ACCESS, "secret_key": SECRET, "network_name": "corp"}
    base.update(data)
    return {"scope": "tenable", "key": key, "kind": "tenable_sc_credential", "description": "test envelope", "data": {k: v for k, v in base.items() if v is not None}}


def admin_payload(key: str = "sc-one-admin", for_key: str = "sc-one", **data: Any) -> dict[str, Any]:
    base = {"base_url": BASE, "access_key": ADMIN_ACCESS, "secret_key": ADMIN_SECRET, "for_key": for_key}
    base.update(data)
    return {"scope": "tenable", "key": key, "kind": "tenable_sc_admin_credential", "description": "test admin envelope", "data": base}


def write_envelope(root: Path, payload: dict[str, Any]) -> Path:
    path = root / f"{payload['key']}.secret.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)
    return path


def credential(**data: Any) -> Credential:
    from tap.runtime_secrets import parse_secret_envelope

    payload = envelope_payload(**data)
    return credential_from_envelope(parse_secret_envelope(payload, Path(f"/nonexistent/{payload['key']}.secret.json")))


def no_sleep() -> Callable[[float], None]:
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)

    sleep.slept = slept  # type: ignore[attr-defined]
    return sleep
