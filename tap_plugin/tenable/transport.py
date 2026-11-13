"""The guarded transport: pyTenable over a session that can only send what the allowlist names.

req-tenable-transport. pyTenable's ``TenableSC`` is the client. Every request it makes leaves through
:class:`GuardedSession`, whose ``send`` refuses anything that is not on :data:`ALLOWLIST`, before
anything is sent. The guard lives in ``send``, so remounting an adapter does not get round it. It
refuses:

- a URL outside the instance's ``/rest/`` root, or one whose path decodes to a dot segment;
- a method-and-path pair not on the list, or one this client's role may not send (the
  administrator client reads inventory only, req-tenable-connection-11);
- a GET whose ``fields`` parameter is not the exact pinned value, or which carries a parameter
  the operation does not name (req-tenable-transport-8);
- an analysis body whose ``type`` is not ``vuln``, whose source type is not one the plugin
  reads, or which lacks ``acceptRiskStatus=all`` (req-tenable-transport-2, -9);
- a per-request override of certificate verification, client certificate or proxies
  (req-tenable-transport-6);
- any redirect (req-tenable-transport-3);
- a response over the size cap, or one still arriving past the read's deadline
  (req-tenable-transport-10).

pyTenable's own retry loop is switched off (``retries=0``, an empty error map), so it never
sleeps on a ``Retry-After`` it was sent. :class:`SecurityCenterClient` retries instead, bounded in
count and in total time, and honours ``Retry-After`` up to a cap (req-tenable-transport-4). JSON
is parsed with a depth ceiling and refuses ``NaN`` and ``Infinity``.

No message built here contains a key. Errors name ``tenable:<key>``, an operation and a class
of failure, and the keys sit only in the session's ``X-APIKey`` header, which pyTenable sets.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import requests
from requests.adapters import BaseAdapter, HTTPAdapter

from tap_plugin.tenable.credential import AdminCredential, Credential, Keys
from tap_plugin.tenable.identity import canonical_root

MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 120.0
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (2.0, 5.0)
MAX_RETRY_AFTER = 60
TOTAL_BUDGET_SECONDS = 300.0

#: The analysis source types the plugin reads (req-tenable-mitigation, req-tenable-scan-result).
SOURCE_TYPES = frozenset({"cumulative", "patched", "individual"})

#: The filter every analysis body carries (req-tenable-transport-9).
ACCEPT_ALL = {"filterName": "acceptRiskStatus", "operator": "=", "value": "all"}

#: Security Center error codes that mean the request was malformed, not that it was refused.
INVALID_REQUEST_CODES = frozenset({"146"})

#: The longest error message kept from a response.
MAX_ERROR_MSG = 4000

#: Field names no pinned list may name (req-tenable-transport-8).
FORBIDDEN_FIELDS = frozenset({"password", "username", "cert", "accessKey", "secretKey", "fingerprint", "encryptionPassword"})

# Response headers that can carry a credential or a session; never kept.
_DROPPED_HEADERS = frozenset({"set-cookie", "authorization", "proxy-authorization", "x-apikey", "x-securitycenter"})

_ID = r"[0-9]{1,18}"

#: Who may send an operation: the main credential, the administrator credential, or both.
MAIN = "main"
ADMIN = "admin"


@dataclass(frozen=True)
class Operation:
    """One permitted request: a method, a path under ``/rest``, and exactly what it may carry.

    ``fields`` is the one ``fields`` value a GET must carry, or None where the read takes no
    ``fields`` parameter at all (``/system``, ``/status``, ``/feed``: none returns a secret field).
    ``pinned`` are further parameters that must have exactly these values when present, and ``free``
    names parameters that may carry a digits-only value (a time bound).
    """

    name: str
    method: str
    path: str
    roles: frozenset[str]
    fields: str | None = None
    pinned: dict[str, str] = field(default_factory=dict)
    free: frozenset[str] = frozenset()

    @property
    def pattern(self) -> re.Pattern[str]:
        return re.compile("^" + self.path.replace("{id}", _ID) + "$")


def _fields(*names: str) -> str:
    return ",".join(names)


#: The plugin's one definition of "read" (req-tenable-transport). A change here is a spec change.
ALLOWLIST: tuple[Operation, ...] = (
    Operation("analysis", "POST", "/rest/analysis", frozenset({MAIN})),
    Operation("system", "GET", "/rest/system", frozenset({MAIN, ADMIN})),
    Operation("status", "GET", "/rest/status", frozenset({MAIN})),
    Operation("feed", "GET", "/rest/feed", frozenset({MAIN})),
    Operation(
        "repository_list",
        "GET",
        "/rest/repository",
        frozenset({MAIN}),
        fields=_fields(
            "id", "uuid", "name", "description", "type", "dataFormat", "vulnCount", "lastSyncTime", "lastVulnUpdate",
            "activeVulnsLifetime", "passiveVulnsLifetime", "complianceVulnsLifetime", "mitigatedVulnsLifetime",
        ),
    ),
    Operation("current_user", "GET", "/rest/currentUser", frozenset({MAIN}), fields=_fields("id", "role", "group", "organization")),
    Operation("current_organization", "GET", "/rest/currentOrganization", frozenset({MAIN}), fields=_fields("id", "zones")),
    Operation(
        "plugin_list",
        "GET",
        "/rest/plugin",
        frozenset({MAIN}),
        fields=_fields("id", "name", "family", "type", "modifiedTime"),
        free=frozenset({"startOffset", "endOffset", "since"}),
    ),
    Operation(
        "plugin",
        "GET",
        "/rest/plugin/{id}",
        frozenset({MAIN}),
        fields=_fields(
            "id", "name", "description", "family", "type", "cpe", "xrefs", "dependencies", "requiredPorts", "requiredUDPPorts",
            "riskFactor", "solution", "seeAlso", "synopsis", "checkType", "exploitAvailable", "exploitEase", "exploitFrameworks",
            "baseScore", "temporalScore", "cvssVector", "cvssV3BaseScore", "cvssV3TemporalScore", "cvssV3Vector",
            "cvssV4BaseScore", "cvssV4Vector", "vprScore", "vprContext", "epssScore", "pluginPubDate", "pluginModDate",
            "patchPubDate", "patchModDate", "vulnPubDate", "modifiedTime", "agent", "seolDate", "stigSeverity",
        ),
    ),
    Operation("plugin_family_list", "GET", "/rest/pluginFamily", frozenset({MAIN}), fields=_fields("id", "name", "type", "count")),
    Operation(
        "scan_result_list",
        "GET",
        "/rest/scanResult",
        frozenset({MAIN}),
        fields=_fields(
            "id", "name", "description", "status", "initiator", "owner", "repository", "scan", "importStatus", "importStart",
            "importFinish", "dataFormat", "resultType", "resultSource", "running", "errorDetails", "importErrorDetails",
            "totalIPs", "scannedIPs", "completedIPs", "completedChecks", "totalChecks", "startTime", "finishTime",
            "scanDuration", "agentScanUUID", "details", "downloadAvailable",
        ),
        pinned={"timeCompareField": "finishTime"},
        free=frozenset({"startTime", "endTime"}),
    ),
    Operation("scan_result", "GET", "/rest/scanResult/{id}", frozenset({MAIN}), fields=_fields("id", "progress")),
    Operation(
        "accept_risk_rule_list",
        "GET",
        "/rest/acceptRiskRule",
        frozenset({MAIN}),
        fields=_fields(
            "id", "repository", "organization", "user", "plugin", "hostType", "hostValue", "port", "protocol", "expires",
            "status", "comments", "createdTime", "modifiedTime",
        ),
    ),
    Operation(
        "recast_risk_rule_list",
        "GET",
        "/rest/recastRiskRule",
        frozenset({MAIN}),
        fields=_fields(
            "id", "repository", "organization", "user", "plugin", "hostType", "hostValue", "port", "protocol", "expires",
            "status", "comments", "createdTime", "modifiedTime", "newSeverity", "order",
        ),
    ),
    Operation(
        "asset_list",
        "GET",
        "/rest/asset",
        frozenset({MAIN}),
        fields=_fields(
            "id", "uuid", "name", "description", "type", "definedIPs", "definedDNSNames", "rules", "combinations", "tags",
            "createdTime", "modifiedTime",
        ),
    ),
    Operation(
        "scanner_list",
        "GET",
        "/rest/scanner",
        frozenset({MAIN, ADMIN}),
        fields=_fields(
            "id", "name", "description", "ip", "port", "status", "enabled", "version", "type", "agentCapable",
            "loadedPluginSet", "numScans", "numHosts", "serverUUID", "zones",
        ),
    ),
    Operation(
        "passive_scanner_list",
        "GET",
        "/rest/passivescanner",
        frozenset({MAIN, ADMIN}),
        fields=_fields("id", "name", "description", "ip", "port", "status", "enabled", "version", "loadedPluginSet", "zones"),
    ),
    Operation(
        "zone_list",
        "GET",
        "/rest/zone",
        frozenset({MAIN, ADMIN}),
        fields=_fields("id", "uuid", "name", "description", "ipList", "createdTime", "modifiedTime", "scanners"),
    ),
    Operation("organization_list", "GET", "/rest/organization", frozenset({ADMIN}), fields=_fields("id", "zones")),
)

OPERATIONS = {op.name: op for op in ALLOWLIST}


class TransportError(Exception):
    """Base of every error this module raises. None of them is a requests exception, so pyTenable never catches one."""


class Refused(TransportError):
    """A request the allowlist does not permit; refused before anything was sent."""


class RedirectRefused(TransportError):
    """The server answered with a redirect, which is never followed."""


class ResponseTooLarge(TransportError):
    """The response is over the size cap."""


class UnboundedResponse(TransportError):
    """The body is JSON this transport refuses: nested past the depth cap, or carrying NaN or Infinity."""


class DeadlineExceeded(TransportError):
    """A read was still arriving past its deadline."""


class Transient(TransportError):
    """A connection error or a timeout; retried by the client, never by pyTenable."""


class ReadFailed(TransportError):
    """A permitted read that did not succeed. ``status`` is the last HTTP status, or None."""

    def __init__(self, message: str, *, status: int | None = None, error_code: Any = None, error_msg: str | None = None, attempts: int = 0) -> None:
        super().__init__(message)
        self.status = status
        self.error_code = error_code
        #: Security Center's error message, keys replaced and bounded. Never part of ``str()``.
        self.error_msg = error_msg
        self.attempts = attempts

    @property
    def refused(self) -> bool:
        """Whether the instance refused the read as not permitted: not visible, never "none".

        Security Center answers 403 for invalid parameters too (error_code 146, documented in
        pyTenable's examples), and that is a bad request, not a refusal.
        """
        return self.status == 401 or (self.status == 403 and str(self.error_code) not in INVALID_REQUEST_CODES)


def _plain(path: str) -> bool:
    """True when ``path`` holds no dot segment, backslash or control character, however it is encoded."""
    text = path
    for _ in range(4):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    else:
        return False
    if any(ord(ch) < 32 or ch == "\\" for ch in text):
        return False
    return all(segment not in (".", "..") for segment in text.split("/"))


def match(method: str, path: str) -> Operation | None:
    """The allowlisted operation for this method and path, or None."""
    for op in ALLOWLIST:
        if op.method == method and op.pattern.match(path):
            return op
    return None


def check_params(op: Operation, query: str) -> None:
    """Refuse a query string that is not exactly what ``op`` permits."""
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=bool(query))
    except ValueError:
        raise Refused(f"{op.name}: the query string is malformed") from None
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise Refused(f"{op.name}: a query parameter is repeated")
    params = dict(pairs)
    if op.fields is None:
        if "fields" in params:
            raise Refused(f"{op.name}: takes no fields parameter")
    elif params.get("fields") != op.fields:
        raise Refused(f"{op.name}: the fields parameter must be exactly the pinned list")
    for name, value in params.items():
        if name == "fields":
            continue
        if name in op.pinned:
            if value != op.pinned[name]:
                raise Refused(f"{op.name}: {name} must be {op.pinned[name]}")
        elif name in op.free:
            if not re.fullmatch(r"[0-9]{1,20}", value):
                raise Refused(f"{op.name}: {name} must be digits")
        else:
            raise Refused(f"{op.name}: parameter {name} is not permitted")
    missing = [name for name in op.pinned if name not in params]
    if missing:
        raise Refused(f"{op.name}: {', '.join(missing)} must be sent")


def check_analysis_body(body: bytes | str | None) -> dict[str, Any]:
    """Refuse an analysis body that is not a vuln query carrying ``acceptRiskStatus=all``."""
    if body is None:
        raise Refused("analysis: the body is empty")
    try:
        data = json.loads(body)
    except ValueError:
        raise Refused("analysis: the body is not JSON") from None
    if not isinstance(data, dict) or data.get("type") != "vuln":
        raise Refused("analysis: only type vuln is permitted")
    if data.get("sourceType") not in SOURCE_TYPES:
        raise Refused("analysis: sourceType must be cumulative, patched or individual")
    query = data.get("query")
    if not isinstance(query, dict) or query.get("type") != "vuln":
        raise Refused("analysis: the query must be a vuln query")
    filters = query.get("filters")
    if not isinstance(filters, list) or ACCEPT_ALL not in filters:
        raise Refused("analysis: every query must carry acceptRiskStatus=all")
    return data


class GuardedSession(requests.Session):
    """A session that can send only the allowlisted reads of one Security Center root.

    ``role`` is ``main`` or ``admin``. ``verify`` is pinned at construction: a request that asks for
    anything else is refused, never overridden. ``deadline`` is a monotonic time the client sets
    before each attempt; a body still arriving after it is abandoned.
    """

    def __init__(self, instance_key: str, verify: bool | str, role: str, *, max_bytes: int = MAX_RESPONSE_BYTES, clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__()
        self.trust_env = False
        self.verify = verify
        self._root = instance_key.rstrip("/")
        self._pinned_verify = verify
        self._role = role
        self._max_bytes = max_bytes
        self._clock = clock
        self.deadline: float | None = None

    def get_adapter(self, url: str) -> BaseAdapter:
        if not url.lower().startswith(("https://", "http://")):
            raise Refused("a request that is not http or https is refused")
        return super().get_adapter(url)

    def authorize(self, request: requests.PreparedRequest) -> Operation:
        """The operation ``request`` is, or Refused. Sends nothing."""
        parts = urlsplit(str(request.url))
        root = urlsplit(self._root)
        try:
            origin = canonical_root(f"{parts.scheme}://{parts.netloc}")
        except ValueError:
            raise Refused("a request outside the configured Security Center root is refused") from None
        if origin != f"{root.scheme}://{root.netloc}":
            raise Refused("a request outside the configured Security Center root is refused")
        if parts.fragment or not parts.path.startswith(root.path + "/rest/") or not _plain(parts.path):
            raise Refused("a request outside the configured Security Center root is refused")
        path = parts.path[len(root.path):]
        method = str(request.method or "").upper()
        if method != request.method:
            raise Refused("a method must be sent in upper case")
        op = match(method, path)
        if op is None:
            raise Refused(f"{method} {path} is not on the allowlist")
        if self._role not in op.roles:
            raise Refused(f"{op.name} may not be sent by the {self._role} client")
        if method == "GET":
            check_params(op, parts.query)
            if request.body:
                raise Refused(f"{op.name}: a GET carries no body")
        else:
            if parts.query:
                raise Refused(f"{op.name}: takes no query string")
            check_analysis_body(request.body)
        return op

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        self.authorize(request)
        if kwargs.get("verify", self._pinned_verify) != self._pinned_verify:
            raise Refused("certificate verification cannot be overridden per request")
        if kwargs.get("cert") is not None:
            raise Refused("a client certificate cannot be supplied per request")
        if kwargs.get("proxies"):
            raise Refused("proxies cannot be supplied per request")
        kwargs.update(verify=self._pinned_verify, cert=None, proxies={}, allow_redirects=False, stream=True)
        try:
            response = super().send(request, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise Transient(type(exc).__name__) from None
        try:
            if 300 <= response.status_code < 400:
                raise RedirectRefused(f"a {response.status_code} redirect is refused and not followed")
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > self._max_bytes:
                raise ResponseTooLarge(f"the response declares {declared} bytes, over the {self._max_bytes}-byte cap")
            chunks: list[bytes] = []
            size = 0
            try:
                for chunk in _arrivals(response):
                    if self.deadline is not None and self._clock() > self.deadline:
                        raise DeadlineExceeded("the response was still arriving at the read's deadline")
                    size += len(chunk)
                    if size > self._max_bytes:
                        raise ResponseTooLarge(f"the response is over the {self._max_bytes}-byte cap")
                    chunks.append(chunk)
            except (requests.ConnectionError, requests.Timeout) as exc:
                raise Transient(type(exc).__name__) from None
            except requests.RequestException as exc:
                raise Transient(type(exc).__name__) from None
            response._content = b"".join(chunks)
            response._content_consumed = True
        finally:
            response.close()
        # Checked here, before pyTenable parses anything, so its own read at connect is bounded too.
        _refuse_unbounded(response.content)
        for name in [k for k in response.headers if k.lower() in _DROPPED_HEADERS]:
            del response.headers[name]
        return response


def _arrivals(response: requests.Response) -> Iterator[bytes]:
    """Yield the body as it arrives, one read at a time, so a trickling peer cannot outlive the deadline."""
    raw = response.raw
    reader = getattr(raw, "read1", None)
    if reader is None:
        yield from response.iter_content(65536)
        return
    while True:
        try:
            data = reader(65536, decode_content=True)
        except TypeError:  # a plain file-like object (as in tests) takes no decode_content
            data = reader(65536)
        if not data:
            return
        yield data


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _depth(value: Any, limit: int) -> int:
    """The nesting depth of ``value``, stopping once it passes ``limit``."""
    stack = [(value, 1)]
    deepest = 0
    while stack:
        item, depth = stack.pop()
        deepest = max(deepest, depth)
        if deepest > limit:
            return deepest
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return deepest


def _refuse_unbounded(body: bytes) -> None:
    """Raise UnboundedResponse for JSON past the depth cap or carrying a constant; a body that is not JSON passes."""
    try:
        parse_json(body)
    except json.JSONDecodeError:
        return
    except ValueError as exc:
        raise UnboundedResponse(f"the response is not bounded JSON ({exc})") from None


def parse_json(body: bytes) -> Any:
    """Parse a response body, refusing NaN, Infinity and nesting past :data:`MAX_JSON_DEPTH`."""
    try:
        data = json.loads(body, parse_constant=_no_constants)
    except RecursionError:
        raise ValueError(f"nested deeper than {MAX_JSON_DEPTH} levels") from None
    if _depth(data, MAX_JSON_DEPTH) > MAX_JSON_DEPTH:
        raise ValueError(f"nested deeper than {MAX_JSON_DEPTH} levels")
    return data


@dataclass(frozen=True)
class Reply:
    """One successful read. ``data`` is the parsed body; headers exclude anything that can carry a credential."""

    operation: str
    status: int
    body: bytes = field(repr=False)
    data: Any = field(repr=False)
    headers: dict[str, str] = field(repr=False)
    elapsed_ms: int
    attempts: int

    @property
    def response(self) -> Any:
        """The documented ``response`` member of Security Center's envelope, or None."""
        return self.data.get("response") if isinstance(self.data, dict) else None


def _guarded_sc_class() -> type:
    """``TenableSC`` with its error map emptied, so it raises on every non-2xx and never retries itself."""
    from tenable.sc import TenableSC

    class _GuardedSC(TenableSC):  # type: ignore[misc, valid-type]
        _base_error_map: dict[int, Any] = {}
        _error_map: dict[int, Any] = {}

    return _GuardedSC


class SecurityCenterClient:
    """Reads of one Security Center instance, through pyTenable and the guarded session.

    ``role`` selects the credential: ``main`` uses the envelope's own keys; ``admin`` uses its
    administrator envelope and may send only the inventory reads. Construct with ``connect=False``
    to build the session without the request pyTenable makes on construction (``GET /rest/system``).
    """

    def __init__(
        self,
        credential: Credential,
        *,
        role: str = MAIN,
        transport: BaseAdapter | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        max_bytes: int = MAX_RESPONSE_BYTES,
        timeout: tuple[float, float] = (CONNECT_TIMEOUT, READ_TIMEOUT),
        max_attempts: int = MAX_ATTEMPTS,
        budget: float = TOTAL_BUDGET_SECONDS,
    ) -> None:
        if role == ADMIN:
            if credential.admin is None:
                raise ValueError(f"{credential.qualified}: no administrator envelope")
            source: Credential | AdminCredential = credential.admin
            keys: Keys = credential.admin.keys
        elif role == MAIN:
            source, keys = credential, credential.keys
        else:
            raise ValueError(f"unknown role {role!r}")
        self.qualified = source.qualified
        self.role = role
        self._sleep = sleep
        self._clock = clock
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._budget = budget
        self._session = GuardedSession(credential.instance_key, source.verify, role, max_bytes=max_bytes, clock=clock)
        adapter = transport if transport is not None else HTTPAdapter(max_retries=0)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)  # NOSONAR S5332: plain http is the operator's choice (req-tenable-connection-9); every run warns
        self._keys = keys
        self._url = credential.instance_key
        self._verify = source.verify
        self._sc: Any = None
        self.version: str | None = None

    def __repr__(self) -> str:
        return f"SecurityCenterClient(qualified={self.qualified!r}, role={self.role!r})"

    def connect(self) -> None:
        """Construct pyTenable's client. pyTenable reads ``GET /rest/system`` here, unauthenticated, for the version.

        A Security Center that reports a version below 5.13 is refused by pyTenable (no API keys);
        that surfaces as ReadFailed naming the floor. Any other failure is ReadFailed too.
        """
        from tenable.errors import APIError

        self._session.deadline = self._clock() + self._budget
        try:
            self._sc = _guarded_sc_class()(
                url=self._url,
                access_key=self._keys.access_key,
                secret_key=self._keys.secret_key,
                ssl_verify=self._verify,
                session=self._session,
                retries=0,
                backoff=0,
                timeout=self._timeout,
                vendor="unified-systems-com",
                product="tenable-tap",
                build="0",
                error_func=_error_message,
            )
        except TransportError as exc:
            raise ReadFailed(f"{self.qualified}: connecting failed: {type(exc).__name__}") from None
        except APIError as exc:
            raise ReadFailed(f"{self.qualified}: connecting failed with HTTP {exc.code}", status=exc.code) from None
        except ConnectionError:
            raise ReadFailed(f"{self.qualified}: Security Center reports a version below 5.13, which has no API keys") from None
        except Exception as exc:  # pyTenable parses the system read itself; any failure there is a failed connect
            raise ReadFailed(f"{self.qualified}: connecting failed: {type(exc).__name__}") from None
        finally:
            self._session.deadline = None
        self.version = self._sc._version

    def close(self) -> None:
        self._session.close()

    def get(self, name: str, *, path_id: str | None = None, params: dict[str, str] | None = None) -> Reply:
        """GET the allowlisted operation ``name``; its pinned ``fields`` are added here."""
        op = OPERATIONS[name]
        path = op.path.replace("{id}", path_id) if path_id is not None else op.path
        if "{id}" in path or (path_id is not None and not re.fullmatch(_ID, path_id)):
            raise Refused(f"{name}: a path id must be digits")
        query = dict(params or {})
        if op.fields is not None:
            query["fields"] = op.fields
        query.update(op.pinned)
        return self._call(op, "GET", path.removeprefix("/rest/"), params=query)

    def analysis(self, body: dict[str, Any]) -> Reply:
        """POST one analysis query. The body must already carry ``acceptRiskStatus=all``."""
        check_analysis_body(json.dumps(body))
        return self._call(OPERATIONS["analysis"], "POST", "analysis", json=body)

    def _call(self, op: Operation, method: str, path: str, **kwargs: Any) -> Reply:
        from tenable.errors import APIError

        if self._sc is None:
            self.connect()
        started = self._clock()
        last_status: int | None = None
        last_code: Any = None
        last_msg: str | None = None
        reason = "not attempted"
        for attempt in range(1, self._max_attempts + 1):
            remaining = self._budget - (self._clock() - started)
            if remaining <= 0:
                break
            self._session.deadline = self._clock() + remaining
            self._sc._timeout = (min(self._timeout[0], remaining), min(self._timeout[1], remaining))
            retry_after: str | None = None
            try:
                response = self._sc._req(method, path, box=False, conv_json=False, **kwargs)
            except Transient as exc:
                reason = str(exc)
            except DeadlineExceeded as exc:
                reason = str(exc)
                break
            except Refused:
                raise
            except (RedirectRefused, ResponseTooLarge, UnboundedResponse) as exc:
                raise ReadFailed(f"{self.qualified}: {op.name}: {exc}", attempts=attempt) from None
            except APIError as exc:
                last_status = exc.code
                last_code, last_msg = self._error_detail(exc.response)
                reason = f"HTTP {exc.code}" + (f", error_code {last_code}" if last_code is not None else "")
                if exc.code != 429 and not 500 <= exc.code < 600:
                    raise ReadFailed(f"{self.qualified}: {op.name} failed: {reason}", status=exc.code, error_code=last_code, error_msg=last_msg, attempts=attempt) from None
                retry_after = exc.response.headers.get("retry-after")
            except RecursionError:
                raise ReadFailed(f"{self.qualified}: {op.name}: the response is nested too deeply", attempts=attempt) from None
            except (KeyError, TypeError, ValueError) as exc:
                # pyTenable reads error_code from every JSON body and fails on one without it.
                raise ReadFailed(f"{self.qualified}: {op.name}: the response is not a Security Center envelope ({type(exc).__name__})", attempts=attempt) from None
            else:
                return self._reply(op, response, started, attempt)
            finally:
                self._session.deadline = None
            if attempt == self._max_attempts:
                break
            delay = self._delay(retry_after, attempt)
            if self._clock() - started + delay >= self._budget:
                reason = f"{reason}; retrying would pass the {self._budget:.0f}-second budget"
                break
            self._sleep(delay)
        raise ReadFailed(f"{self.qualified}: {op.name} failed: {reason}", status=last_status, error_code=last_code, error_msg=last_msg, attempts=self._max_attempts)

    def _reply(self, op: Operation, response: requests.Response, started: float, attempt: int) -> Reply:
        try:
            data = parse_json(response.content)
        except ValueError as exc:
            raise ReadFailed(f"{self.qualified}: {op.name}: the response is not bounded JSON ({exc})", status=response.status_code, attempts=attempt) from None
        code, message = self._error_detail(response)
        if code is not None:
            raise ReadFailed(f"{self.qualified}: {op.name} failed: error_code {code}", status=response.status_code, error_code=code, error_msg=message, attempts=attempt)
        return Reply(
            operation=op.name,
            status=response.status_code,
            body=response.content,
            data=data,
            headers={k.lower(): v for k, v in response.headers.items()},
            elapsed_ms=int((self._clock() - started) * 1000),
            attempts=attempt,
        )

    def _error_detail(self, response: requests.Response) -> tuple[Any, str | None]:
        """Security Center's ``error_code`` and ``error_msg`` from a body, the message with the keys replaced and bounded."""
        try:
            data = parse_json(response.content)
        except ValueError:
            return None, None
        if not isinstance(data, dict) or data.get("error_code") in (None, 0, "0"):
            return None, None
        message = data.get("error_msg")
        if isinstance(message, str):
            # Redact before truncating: a key straddling the limit would otherwise survive as a fragment.
            message, _ = self._keys.redact(message)
            message = message[:MAX_ERROR_MSG]
        else:
            message = None
        return data["error_code"], message

    @staticmethod
    def _delay(retry_after: str | None, attempt: int) -> float:
        if retry_after is not None and retry_after.strip().isdigit():
            return float(min(int(retry_after.strip()), MAX_RETRY_AFTER))
        return BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)]


def _error_message(resp: requests.Response, **_: Any) -> str:
    """The message pyTenable logs for an error response: the status only.

    pyTenable's default logs the whole response body at ERROR on every non-2xx, and a body can
    echo request input. This plugin records failures itself, without bodies.
    """
    return f"HTTP {resp.status_code}"
