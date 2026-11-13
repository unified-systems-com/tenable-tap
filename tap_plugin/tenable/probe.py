"""The probe: what the instance is, and what this credential can see, read before any data (req-tenable-probe).

The probe reads the system and status endpoints, the credential's own user and organisation,
the plugin feed's update times and the repository list, in that order, through the guarded
transport. Every read is optional except the repository list, because the scope walk needs it.
An optional read the instance refuses leaves its fields ``None`` and the run continues
(req-tenable-probe-2). The result is plain data the scan run records. It holds no user name or
contact detail, only ids (req-tenable-probe-4).

Nothing here writes to the grid, so the observation command uses it unchanged.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from tap_plugin.tenable import compat
from tap_plugin.tenable.credential import Credential
from tap_plugin.tenable.transport import ReadFailed, SecurityCenterClient

#: Repository data formats whose results are read (req-tenable-probe).
READ_FORMATS = frozenset({"IPv4", "IPv6", "agent", "universal"})
#: Formats known and deliberately not read in v0, with the reason.
SKIPPED_FORMATS = {"mobile": "mobile repositories are not read in v0"}


class ProbeError(Exception):
    """The run cannot continue: the repository list is unreadable, or the version is below the floor."""


@dataclass
class Repository:
    """One repository as the probe listed it, with how the run treats it."""

    id: str
    name: str | None
    data_format: str | None
    fields: dict[str, Any] = field(repr=False)
    treatment: str = "read"  # read | not_read | unknown_format
    reason: str | None = None


@dataclass
class Probe:
    """What one probe found. ``None`` is unobserved, never a pass or an empty answer."""

    instance_key: str
    version: str | None = None
    build_id: str | None = None
    verdict: str = compat.UNREADABLE
    status_read: bool | None = None
    user_id: str | None = None
    role_id: str | None = None
    organization_id: str | None = None
    group_id: str | None = None
    zone_ids: list[str] | None = None
    feed: dict[str, dict[str, Any]] | None = None
    feed_stale: bool | None = None
    repositories: list[Repository] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    not_read: dict[str, str] = field(default_factory=dict)

    def credential_view(self) -> dict[str, Any]:
        """The credential's view, compared run to run: a change blocks resolution by absence (req-tenable-probe-4)."""
        return {
            "role_id": self.role_id,
            "organization_id": self.organization_id,
            "group_id": self.group_id,
            "repository_ids": sorted(r.id for r in self.repositories),
        }

    def record(self) -> dict[str, Any]:
        """The probe as the scan run stores it."""
        out = asdict(self)
        out["repositories"] = [
            {"id": r.id, "name": r.name, "data_format": r.data_format, "treatment": r.treatment, "reason": r.reason} for r in self.repositories
        ]
        return out


def _string(value: Any) -> str | None:
    """A value Security Center returned as a string, or ``None``. Numbers are kept in their written form."""
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    return str(value)


def _id_of(value: Any) -> str | None:
    """The ``id`` of a nested object Security Center returns, such as ``{"id": "3", "name": ...}``; the name is dropped."""
    return _string(value.get("id")) if isinstance(value, dict) else None


def _read(client: SecurityCenterClient, probe: Probe, name: str) -> Any:
    """One optional read; a failure is recorded on the probe and returns ``None``."""
    try:
        return client.get(name).response
    except ReadFailed as exc:
        probe.not_read[name] = "refused" if exc.refused else str(exc).split(": ", 1)[-1]
        return None


def _feed(probe: Probe, response: Any, stale_days: int, now: float) -> None:
    """Record each feed's update time and Security Center's own stale flag, and whether any is past the threshold."""
    if not isinstance(response, dict):
        probe.not_read.setdefault("feed", "the response is not an object")
        return
    feeds: dict[str, dict[str, Any]] = {}
    stale = False
    dated: set[str] = set()
    for name, entry in response.items():
        if not isinstance(entry, dict):
            continue
        updated = _string(entry.get("updateTime"))
        feeds[name] = {"update_time": updated, "stale": _string(entry.get("stale")), "update_running": _string(entry.get("updateRunning"))}
        if name not in ("active", "passive"):
            continue
        if str(entry.get("stale", "")).lower() == "true":
            stale = True
        if updated and updated.isdigit() and int(updated) > 0:
            dated.add(name)
            if now - int(updated) > stale_days * 86400:
                stale = True
    probe.feed = feeds
    if stale:
        probe.feed_stale = True
        probe.warnings.append("FEED_STALE")
    elif dated == {"active", "passive"}:
        probe.feed_stale = False
    else:
        # Read, but without a readable update time for both: freshness is unobserved, never fresh
        # (req-tenable-probe-5). The read itself succeeded, so it is not "not read".
        probe.feed_stale = None


def _repositories(probe: Probe, response: Any) -> None:
    if not isinstance(response, list):
        raise ProbeError("the repository list is not a list")
    for item in response:
        if not isinstance(item, dict) or not (_string(item.get("id")) or "").isdigit():
            raise ProbeError("a repository entry has no numeric id")
        data_format = _string(item.get("dataFormat"))
        repo = Repository(id=str(item["id"]), name=_string(item.get("name")), data_format=data_format, fields=dict(item))
        if data_format in READ_FORMATS:
            pass
        elif data_format in SKIPPED_FORMATS:
            repo.treatment, repo.reason = "not_read", SKIPPED_FORMATS[data_format]
        else:
            repo.treatment, repo.reason = "unknown_format", "the dataFormat is not one this plugin knows"
        probe.repositories.append(repo)


def run(client: SecurityCenterClient, credential: Credential, *, now: float) -> Probe:
    """Probe one instance. Raises ProbeError when the run must end before any data read."""
    probe = Probe(instance_key=credential.instance_key)
    probe.warnings.extend(credential.warnings())
    system = _read(client, probe, "system")
    if isinstance(system, dict):
        probe.version = _string(system.get("version"))
        probe.build_id = _string(system.get("buildID"))
    if probe.version is None:
        # pyTenable read /system before authenticating (5.22 and later show the version only when authenticated).
        probe.version = client.version
    found = compat.verdict(probe.version)
    probe.verdict = found.verdict
    if found.warning:
        probe.warnings.append(found.warning)
    if found.below_floor:
        raise ProbeError(f"Security Center {probe.version} is below the {compat.load()['hard_floor']} floor: it has no API-key authentication")
    probe.status_read = _read(client, probe, "status") is not None
    user = _read(client, probe, "current_user")
    if isinstance(user, dict):
        probe.user_id = _string(user.get("id"))
        probe.role_id = _id_of(user.get("role"))
        probe.group_id = _id_of(user.get("group"))
        probe.organization_id = _id_of(user.get("organization"))
    organization = _read(client, probe, "current_organization")
    if isinstance(organization, dict):
        probe.organization_id = probe.organization_id or _string(organization.get("id"))
        zones = organization.get("zones")
        probe.zone_ids = [z for z in (_id_of(zone) for zone in zones) if z is not None] if isinstance(zones, list) else None
    feed = _read(client, probe, "feed")
    if feed is not None:
        _feed(probe, feed, credential.feed_stale_days, now)
    try:
        repositories = client.get("repository_list").response
    except ReadFailed as exc:
        raise ProbeError(f"the repository list could not be read: {str(exc).split(': ', 1)[-1]}") from None
    _repositories(probe, repositories)
    return probe
