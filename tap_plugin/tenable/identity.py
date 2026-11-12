"""Identity derivations shared by the Tenable models and the collector.

Every key part a model stores is derived here, once, so a model can check that its stored key says
what its stored columns say (req-grid-entity-natural-key: a key rests only on facts the model
carries). Nothing here does I/O.

Spec: specs/spec-tenable-v0.md (req-tenable-scanner-run-2, req-tenable-connection-5,
req-tenable-findings-1, -11, -12).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from urllib.parse import urlsplit

#: The default port for each scheme a Security Center root may use.
DEFAULT_PORTS = {"https": 443, "http": 80}

#: Free text from Tenable is kept whole up to this many UTF-8 bytes (req-tenable-findings-10, -13).
FREE_TEXT_CEILING_BYTES = 4 * 1024 * 1024

#: The hostUniqueness names a host key may be built from, and the stored column each one reads
#: (req-tenable-findings-12). `uuid` is the agent UUID, stored as `agent_uuid`.
HOST_UNIQUENESS_COLUMNS = {
    "repositoryID": "repository_id",
    "ip": "ip",
    "dnsName": "dns_name",
    "netbiosName": "netbios_name",
    "macAddress": "mac_address",
    "uuid": "agent_uuid",
    "hostUUID": "host_uuid",
}


class UnkeyableError(ValueError):
    """A record that cannot be given a key: it is counted and not stored (req-tenable-findings-3)."""


def canonical_root(base_url: str) -> str:
    """The canonical root of a Security Center base URL, which is the instance key.

    The scheme and host are lower-cased, the port is always written (the scheme's default when
    omitted), and the path is kept as configured without a trailing slash, so one console has one
    key however its URL is spelled. A spelling that could name the same console another way is
    refused rather than guessed at: userinfo, a query or a fragment, a scheme other than http or
    https, port 0, a host with a trailing dot, and a path with empty, `.`, `..` or percent-encoded
    segments (req-tenable-connection-5).
    """
    parts = urlsplit(base_url)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ValueError("base_url scheme must be http or https")
    if parts.username is not None or parts.password is not None:
        raise ValueError("base_url must not carry userinfo")
    if parts.query or parts.fragment:
        raise ValueError("base_url must not carry a query or fragment")
    host = (parts.hostname or "").lower()
    if not host:
        raise ValueError("base_url must name a host")
    if host.endswith("."):
        raise ValueError("base_url host must not end with a dot")
    segments = parts.path.rstrip("/").split("/")[1:]
    if any(segment in ("", ".", "..") for segment in segments) or "%" in parts.path:
        raise ValueError("base_url path must not hold empty, dot or percent-encoded segments")
    if parts.port == 0:
        raise ValueError("base_url port must not be 0")
    port = DEFAULT_PORTS[scheme] if parts.port is None else parts.port
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}{parts.path.rstrip('/')}"


def _sha256_of(value: object) -> str:
    return hashlib.sha256(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def uniqueness_names(host_uniqueness: str | None) -> list[str]:
    """The sorted, de-duplicated names of a hostUniqueness list, refused when empty or unknown."""
    names = sorted({name.strip() for name in (host_uniqueness or "").split(",") if name.strip()})
    if not names:
        raise UnkeyableError("hostUniqueness is empty")
    unknown = [name for name in names if name not in HOST_UNIQUENESS_COLUMNS]
    if unknown:
        raise UnkeyableError(f"hostUniqueness names unknown fields: {', '.join(unknown)}")
    return names


def host_key(host_uniqueness: str | None, columns: Mapping[str, str | None]) -> str:
    """The observed host's key: the sha256 of the named fields' values, with the repository always in.

    `columns` maps stored column names (`repository_id`, `ip`, ...) to their values. Every field the
    list names must be present and non-empty, and the repository id is hashed in whether or not
    the list names it, so equal addresses in two repositories never become one host.
    """
    names = set(uniqueness_names(host_uniqueness)) | {"repositoryID"}
    pairs = []
    for name in sorted(names):
        value = columns.get(HOST_UNIQUENESS_COLUMNS[name])
        if value is None or value == "":
            raise UnkeyableError(f"hostUniqueness names {name}, which the record does not carry")
        pairs.append([name, value])
    return _sha256_of(pairs)


def assertion_key(repository_id: str, host_key_value: str, plugin_id: str, port: str, protocol: str) -> str:
    """A result's key: the sha256 of `[repository_id, host_key, plugin_id, port, protocol]`."""
    parts = [repository_id, host_key_value, plugin_id, port, protocol]
    if any(part is None or part == "" for part in parts):
        raise UnkeyableError("an assertion key part is missing")
    return _sha256_of(parts)


def text_within_ceiling(value: str | None) -> bool:
    """Whether free text fits the ceiling; null is unobserved and always fits."""
    return value is None or len(value.encode("utf-8")) <= FREE_TEXT_CEILING_BYTES
