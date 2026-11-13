"""Read one Security Center instance and record what it returns, in a fixed order (req-tenable-observe).

This is an instrument, not the collector. It reads only through the guarded transport's allowlist
and writes nothing to the grid. By default it saves SHAPES only: for each response, the status, the
names of headers that cannot carry a credential, and the field names, types and counts, with no
values. ``--record-bodies`` also saves each body, with either key replaced wherever it appears, under
an owner-only directory outside any repository. The report prints shapes, counts, statuses and the
assumptions ledger. It never prints a body, a key, or a host or asset name: an instance is named by
its envelope key, and its address appears only in the owner-only ``shapes.json``.

    python -m tap_plugin.tenable.observe --list
    python -m tap_plugin.tenable.observe --key <envelope key> [--record-bodies] [--dry-run]

A step whose prerequisite is missing is recorded as *not read* with the reason, never as empty.
"""

from __future__ import annotations

import argparse
import contextvars
import io
import json
import os
import re
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO, cast

from requests.adapters import BaseAdapter

from tap_plugin.tenable import analysis, compat
from tap_plugin.tenable import probe as probe_module
from tap_plugin.tenable.credential import Credential, discover
from tap_plugin.tenable.identity import HOST_UNIQUENESS_COLUMNS
from tap_plugin.tenable.transport import ADMIN, ALLOWLIST, ReadFailed, Reply, SecurityCenterClient

LEDGER_PATH = Path(__file__).resolve().parent / "observe_assumptions.json"
RECORDINGS_DIRNAME = ".tenable-recordings"
PAGE = 50
SHAPE_ITEMS = 200
SETTLED, CONTRADICTED, NOT_REACHED = "settled", "contradicted", "not reached"

# The tools whose field names (never values) the report lists.
FIELD_TOOLS = ("sumip", "listservices", "listos", "listsoftware")


@dataclass
class Line:
    step: str
    operation: str
    status: str
    elapsed_ms: int | None = None
    records: int | None = None
    note: str = ""


@dataclass
class Context:
    credential: Credential
    client: SecurityCenterClient
    admin: SecurityCenterClient | None
    out_dir: Path | None
    record_bodies: bool
    lines: list[Line] = field(default_factory=list)
    shapes: dict[str, Any] = field(default_factory=dict)
    ledger: dict[str, tuple[str, str]] = field(default_factory=dict)
    operations_read: dict[str, str] = field(default_factory=dict)
    plugin_rank: list[tuple[str, int]] = field(default_factory=list)
    filter_names: list[str] = field(default_factory=list)
    uniqueness: dict[str, Counter[str]] = field(default_factory=dict)
    redactions: int = 0
    counter: int = 0
    probe: probe_module.Probe | None = None


#: The run's key redaction, applied by ``safe`` before it truncates, so a key cut at the limit
#: cannot leave a fragment that the final redaction of the report would no longer match.
_redact: contextvars.ContextVar[Callable[[str], tuple[str, int]] | None] = contextvars.ContextVar("tenable_observe_redact", default=None)


def safe(text: Any, limit: int = 160) -> str:
    """Printable characters only, keys replaced, bounded: nothing an instance returns can reach the terminal raw."""
    text = str(text)
    redact = _redact.get()
    if redact is not None:
        text = redact(text)[0]
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in text)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def shape(value: Any, depth: int = 0) -> Any:
    """The structure of a JSON value with every value removed: field names, types and list lengths."""
    if depth > 12:
        return "..."
    if isinstance(value, dict):
        return {str(k): shape(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        merged: dict[str, Any] = {}
        kinds: set[str] = set()
        for item in value[:SHAPE_ITEMS]:
            if isinstance(item, dict):
                for k, v in item.items():
                    merged.setdefault(str(k), shape(v, depth + 1))
            else:
                kinds.add(type(item).__name__)
        out: dict[str, Any] = {"list": len(value)}
        if merged:
            out["items"] = merged
        if kinds:
            out["item_types"] = sorted(kinds)
        return out
    return type(value).__name__


def write_private(path: Path, text: str) -> None:
    """Create ``path`` owner-only from the first byte."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def _inside_repository(path: Path) -> bool:
    return any((parent / ".git").exists() for parent in (path, *path.parents))


def _out_dir(credential: Credential, root: Path | None) -> Path:
    """An owner-only directory for this run, refused inside any git repository (req-tenable-observe-2, -7)."""
    base = (root or Path.home()) / RECORDINGS_DIRNAME
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    slug = re.sub(r"[^a-z0-9]+", "-", credential.key.lower()).strip("-")[:40] or "instance"
    out = base / f"{slug}-{stamp}"
    if _inside_repository(out.parent if out.parent.exists() else base.parent):
        raise SystemExit(f"refusing to record inside a git repository: {base}")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    out.mkdir(mode=0o700)
    return out


def _save(ctx: Context, step: str, reply: Reply | None, failure: ReadFailed | None) -> None:
    """Record one response's shape, and with --record-bodies its redacted body."""
    ctx.counter += 1
    record: dict[str, Any] = {"step": step}
    if reply is not None:
        record.update(status=reply.status, operation=reply.operation, header_names=sorted(reply.headers), shape=shape(reply.data))
    else:
        record.update(status=failure.status if failure else None, failed=safe(str(failure).split(": ", 1)[-1]) if failure else None)
    ctx.shapes[f"{ctx.counter:03d}-{step}"] = record
    if ctx.out_dir is None:
        return
    if ctx.record_bodies and reply is not None:
        body, count = ctx.credential.redact_bytes(reply.body)
        ctx.redactions += count
        write_private(ctx.out_dir / f"{ctx.counter:03d}-{re.sub(r'[^a-z0-9]+', '-', step.lower())}.json", body.decode("utf-8", "replace"))


def fetch(ctx: Context, step: str, operation: str, *, client: SecurityCenterClient | None = None, path_id: str | None = None, params: dict[str, str] | None = None) -> Reply | None:
    """One GET; a failure is a not-read line, never an empty answer."""
    client = client or ctx.client
    try:
        reply = client.get(operation, path_id=path_id, params=params)
    except ReadFailed as exc:
        reason = "refused (not visible to this credential)" if exc.refused else safe(str(exc).split(": ", 1)[-1])
        ctx.lines.append(Line(step, operation, "not read", note=reason))
        ctx.operations_read.setdefault(operation, f"not read: {reason}")
        _save(ctx, step, None, exc)
        return None
    records = len(reply.response) if isinstance(reply.response, list) else None
    ctx.lines.append(Line(step, operation, f"HTTP {reply.status}", reply.elapsed_ms, records))
    ctx.operations_read[operation] = "read"
    _save(ctx, step, reply, None)
    return reply


def query(ctx: Context, step: str, body: dict[str, Any]) -> tuple[Reply | None, ReadFailed | None]:
    """One analysis query; returns the reply or the failure, and records either."""
    try:
        reply = ctx.client.analysis(body)
    except ReadFailed as exc:
        ctx.lines.append(Line(step, "analysis", "not read", note="refused" if exc.refused else safe(str(exc).split(": ", 1)[-1])))
        _save(ctx, step, None, exc)
        return None, exc
    results = reply.response.get("results") if isinstance(reply.response, dict) else None
    ctx.lines.append(Line(step, "analysis", f"HTTP {reply.status}", reply.elapsed_ms, len(results) if isinstance(results, list) else None))
    ctx.operations_read["analysis"] = "read"
    _save(ctx, step, reply, None)
    return reply, None


def results_of(reply: Reply | None) -> list[dict[str, Any]]:
    response = reply.response if reply is not None else None
    results = response.get("results") if isinstance(response, dict) else None
    return [r for r in results if isinstance(r, dict)] if isinstance(results, list) else []


def mark(ctx: Context, assumption: str, verdict: str, note: str = "") -> None:
    ctx.ledger[assumption] = (verdict, note)


def repo_filter(repository_id: str) -> dict[str, Any]:
    return analysis.flt("repositoryIDs", repository_id)


class _RecordingClient:
    """The probe's view of the client: each read it makes is saved like any other step's."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx

    @property
    def version(self) -> str | None:
        return self._ctx.client.version

    def get(self, name: str, path_id: str | None = None, params: dict[str, str] | None = None) -> Reply:
        try:
            reply = self._ctx.client.get(name, path_id=path_id, params=params)
        except ReadFailed as exc:
            _save(self._ctx, f"probe {name}", None, exc)
            raise
        _save(self._ctx, f"probe {name}", reply, None)
        return reply


def step_probe(ctx: Context) -> bool:
    try:
        ctx.probe = probe_module.run(cast(SecurityCenterClient, _RecordingClient(ctx)), ctx.credential, now=time.time())
    except probe_module.ProbeError as exc:
        ctx.lines.append(Line("probe", "repository_list", "not read", note=safe(exc)))
        return False
    for name in ("system", "status", "current_user", "current_organization", "feed"):
        ctx.operations_read[name] = f"not read: {ctx.probe.not_read[name]}" if name in ctx.probe.not_read else "read"
    ctx.operations_read["repository_list"] = "read"
    ctx.lines.append(Line("probe", "probe", "done", note=f"version {safe(ctx.probe.version)} ({ctx.probe.verdict}); {len(ctx.probe.repositories)} repositories"))
    feed = ctx.probe.feed or {}
    if "feed" in ctx.probe.not_read:
        mark(ctx, "feed-shape", NOT_REACHED, "feed not read")
    elif all(feed.get(k, {}).get("update_time") for k in ("active", "passive")):
        mark(ctx, "feed-shape", SETTLED)
    else:
        mark(ctx, "feed-shape", CONTRADICTED, f"feed entries: {', '.join(sorted(feed)) or 'none'}")
    lifetimes = ("activeVulnsLifetime", "passiveVulnsLifetime", "complianceVulnsLifetime", "mitigatedVulnsLifetime")
    if ctx.probe.repositories:
        present = all(all(name in r.fields for name in lifetimes) for r in ctx.probe.repositories)
        mark(ctx, "repository-lifetimes", SETTLED if present else CONTRADICTED)
    mark(ctx, "director-detection", NOT_REACHED, "no documented signal in the probe's reads; needs a recording from such a deployment")
    return True


def step_findings(ctx: Context) -> None:
    """A first page per readable repository: identity fields, presence of documented fields, the output wrapper."""
    assert ctx.probe is not None
    version = ctx.probe.version
    pages = 0
    seen_fields: Counter[str] = Counter()
    wrapper = Counter[bool]()
    compliance = False
    with_uuid: set[tuple[str, str, str]] = set()
    without_uuid: set[tuple[str, str, str]] = set()
    for repo in ctx.probe.repositories:
        if repo.treatment != "read":
            ctx.lines.append(Line(f"findings repo {repo.id}", "analysis", "not read", note=repo.reason or repo.treatment))
            continue
        reply, _ = query(ctx, f"findings repo {repo.id}", analysis.body("vulndetails", "cumulative", start=0, end=PAGE, filters=[repo_filter(repo.id)], version=version))
        records = results_of(reply)
        if reply is None:
            continue
        pages += 1
        total = reply.response.get("totalRecords") if isinstance(reply.response, dict) else None
        if total is not None and str(total).isdigit() and int(total) > PAGE:
            mark(ctx, "paging-offsets", SETTLED if len(records) <= PAGE else CONTRADICTED, f"asked for {PAGE}, got {len(records)} of {total}")
        lists = ctx.uniqueness.setdefault(f"{repo.data_format}", Counter())
        for record in records:
            seen_fields.update(record.keys())
            hu = record.get("hostUniqueness", record.get("uniqueness"))
            lists[str(hu)] += 1
            text = record.get("pluginText")
            if isinstance(text, str) and text:
                wrapper[text.lstrip().startswith("<plugin_output>")] += 1
                compliance = compliance or "<cm:compliance-" in text
            socket = (str(record.get("pluginID")), str(record.get("port")), str(record.get("ip")))
            (with_uuid if record.get("hostUUID") else without_uuid).add(socket)
    if pages == 0:
        for name in ("host-uniqueness", "host-uniqueness-per-format", "last-mitigated", "vuln-uuid", "cve-on-finding", "plugin-output-wrapper", "agent-uuid-field", "host-uuid-stability"):
            mark(ctx, name, NOT_REACHED, "no repository page was read")
        return
    known = set(HOST_UNIQUENESS_COLUMNS)
    names = {n.strip() for lists in ctx.uniqueness.values() for hu in lists for n in hu.split(",") if n.strip() and hu != "None"}
    missing = sum(c for lists in ctx.uniqueness.values() for hu, c in lists.items() if hu == "None")
    mark(ctx, "host-uniqueness", SETTLED if not missing and names <= known else CONTRADICTED, f"lists seen: {sum(len(v) for v in ctx.uniqueness.values())}; unknown names: {', '.join(sorted(names - known)) or 'none'}; records without a list: {missing}")
    mark(ctx, "host-uniqueness-per-format", SETTLED if all(len(v) <= 1 for v in ctx.uniqueness.values()) else CONTRADICTED, "; ".join(f"{fmt}: {', '.join(safe(k, 60) for k in v)}" for fmt, v in ctx.uniqueness.items()))
    agent_lists = ctx.uniqueness.get("agent")
    if agent_lists:
        mark(ctx, "agent-uuid-field", SETTLED if all("uuid" in hu.split(",") and "agentUUID" not in hu for hu in agent_lists) else CONTRADICTED)
    else:
        mark(ctx, "agent-uuid-field", NOT_REACHED, "no agent repository read")
    for assumption, keys in (("last-mitigated", ("lastMitigated",)), ("vuln-uuid", ("vulnUUID", "vulnUniqueness")), ("cve-on-finding", ("cve",))):
        mark(ctx, assumption, SETTLED if all(seen_fields[k] for k in keys) else CONTRADICTED, ", ".join(f"{k} on {seen_fields[k]} records" for k in keys))
    if wrapper:
        mark(ctx, "plugin-output-wrapper", SETTLED if not wrapper[False] else CONTRADICTED, f"wrapped {wrapper[True]}, unwrapped {wrapper[False]}")
    else:
        mark(ctx, "plugin-output-wrapper", NOT_REACHED, "no record carried pluginText")
    if compliance:
        mark(ctx, "compliance-elements", SETTLED)
    else:
        mark(ctx, "compliance-elements", NOT_REACHED, "no compliance result in the first pages")
    both = with_uuid & without_uuid
    mark(ctx, "host-uuid-stability", CONTRADICTED if both else SETTLED, f"{len(both)} plugin/port/ip triples seen both ways in the first pages")


def step_filters(ctx: Context) -> None:
    """The valid filter names (a known-bad filter is refused with the list), the lastSeen format and the wasVuln filter."""
    assert ctx.probe is not None
    version = ctx.probe.version
    _, failure = query(ctx, "valid filter names", analysis.body("vulndetails", "cumulative", start=0, end=1, filters=[analysis.flt("tapProbeUnknownFilter", "1")], version=version))
    # The names are Security Center's vocabulary, not instance data; the message itself is not printed.
    found = re.search(r"valid filters:\s*([A-Za-z0-9_, ]+)", (failure.error_msg or "") if failure is not None else "")
    ctx.filter_names = sorted({n.strip() for n in found.group(1).split(",") if n.strip()}) if found else []
    expected = {"repositoryIDs", "pluginID", "port", "protocol", "severity", "familyID", "exploitAvailable", "cveID", "asset", "recastRiskStatus", "lastSeen"}
    if ctx.filter_names:
        missing = expected - set(ctx.filter_names)
        mark(ctx, "valid-filter-names", SETTLED if not missing else CONTRADICTED, f"missing: {', '.join(sorted(missing)) or 'none'}")
    else:
        mark(ctx, "valid-filter-names", NOT_REACHED, "the refusal did not list filter names in a form this command reads; see the saved shape")
    _, failure = query(ctx, "lastSeen documented form", analysis.body("vulndetails", "cumulative", start=0, end=1, filters=[analysis.flt("lastSeen", "0:30")], version=version))
    mark(ctx, "lastseen-format", SETTLED if failure is None else CONTRADICTED)
    parsed = compat.version_tuple(version)
    if parsed is None or parsed < analysis.WAS_FILTER_FROM:
        mark(ctx, "wasvuln-filter", NOT_REACHED, "version below 6.2 or unreadable: the filter is not sent")
    else:
        ok = any(line.operation == "analysis" and line.status.startswith("HTTP") for line in ctx.lines)
        mark(ctx, "wasvuln-filter", SETTLED if ok else NOT_REACHED, "every cumulative query above carried it")
    mark(ctx, "accepted-default", NOT_REACHED, "the transport sends acceptRiskStatus=all on every query (req-tenable-transport-9), so the default cannot be observed; compare in the query UI")


def step_rank(ctx: Context) -> None:
    """Plugin ids ranked by result count, so the first parsers follow the data (req-tenable-observe-6)."""
    assert ctx.probe is not None
    reply, _ = query(ctx, "rank plugins", analysis.body("sumid", "cumulative", start=0, end=200, version=ctx.probe.version))
    ranked = []
    for record in results_of(reply):
        plugin_id, total = record.get("pluginID"), record.get("total")
        if plugin_id is not None and str(total).isdigit():
            ranked.append((str(plugin_id), int(total)))
    ctx.plugin_rank = sorted(ranked, key=lambda p: -p[1])[:25]


def step_tools(ctx: Context) -> None:
    """Field names of the host summary and the service, OS and software list tools."""
    assert ctx.probe is not None
    for tool in FIELD_TOOLS:
        reply, _ = query(ctx, f"tool {tool}", analysis.body(tool, "cumulative", start=0, end=5, version=ctx.probe.version))
        if tool == "sumip":
            fields = set().union(*(r.keys() for r in results_of(reply))) if results_of(reply) else set()
            wanted = {"lastAuthRun", "lastUnauthRun", "osCPE"}
            if reply is None or not fields:
                mark(ctx, "host-summary-fields", NOT_REACHED, "sumip returned no record")
            else:
                mark(ctx, "host-summary-fields", SETTLED if wanted <= fields else CONTRADICTED, f"missing: {', '.join(sorted(wanted - fields)) or 'none'}")


def step_plugins(ctx: Context) -> None:
    fetch(ctx, "plugin list page", "plugin_list", params={"startOffset": "0", "endOffset": "10"})
    sample = ctx.plugin_rank[0][0] if ctx.plugin_rank else None
    if sample is None:
        ctx.lines.append(Line("plugin detail", "plugin", "not read", note="no plugin id to sample"))
        ctx.operations_read.setdefault("plugin", "not read: no plugin id to sample")
        mark(ctx, "check-type", NOT_REACHED, "no plugin read")
    else:
        reply = fetch(ctx, "plugin detail", "plugin", path_id=sample)
        data = reply.response if reply is not None else None
        if isinstance(data, dict):
            mark(ctx, "check-type", SETTLED if data.get("checkType") not in (None, "") else CONTRADICTED, "checkType present" if data.get("checkType") else "checkType empty or absent on the sampled plugin")
        else:
            mark(ctx, "check-type", NOT_REACHED, "plugin read failed")
    fetch(ctx, "plugin families", "plugin_family_list")


def step_scans(ctx: Context) -> None:
    now = int(time.time())
    start = now - ctx.credential.scan_result_window_days * 86400
    reply = fetch(ctx, "scan results", "scan_result_list", params={"startTime": str(start), "endTime": str(now)})
    scans = reply.response if reply is not None else None
    items = (scans.get("usable") or scans.get("manageable") or []) if isinstance(scans, dict) else scans if isinstance(scans, list) else []
    finished = [s for s in items if isinstance(s, dict) and str(s.get("id", "")).isdigit() and str(s.get("importStatus", "")).lower() == "finished"]
    if not finished:
        ctx.operations_read.setdefault("scan_result", "not read: no finished scan result in the window")
        mark(ctx, "individual-view", NOT_REACHED, "no finished scan result in the window")
        mark(ctx, "scan-detail-scanners", NOT_REACHED, "no finished scan result in the window")
        return
    newest = max(finished, key=lambda s: int(str(s.get("finishTime", "0")) or 0) if str(s.get("finishTime", "0")).isdigit() else 0)
    scan_id = str(newest["id"])
    detail = fetch(ctx, "scan result detail", "scan_result", path_id=scan_id)
    progress = detail.response.get("progress") if detail is not None and isinstance(detail.response, dict) else None
    mark(ctx, "scan-detail-scanners", SETTLED if isinstance(progress, dict) and "scanners" in progress else (NOT_REACHED if detail is None else CONTRADICTED))
    assert ctx.probe is not None
    reply2, failure = query(ctx, "individual view", analysis.body("vulndetails", "individual", start=0, end=PAGE, version=ctx.probe.version, scan_result_id=scan_id))
    mark(ctx, "individual-view", SETTLED if reply2 is not None else CONTRADICTED, "" if failure is None else safe(str(failure).split(": ", 1)[-1]))


def step_inventory(ctx: Context) -> None:
    for step, operation in (("accept-risk rules", "accept_risk_rule_list"), ("recast-risk rules", "recast_risk_rule_list"), ("asset lists", "asset_list")):
        fetch(ctx, step, operation)
    main_scanners = fetch(ctx, "scanners (main credential)", "scanner_list")
    fetch(ctx, "passive scanners (main credential)", "passive_scanner_list")
    fetch(ctx, "zones (main credential)", "zone_list")
    items = main_scanners.response if main_scanners is not None else None
    if isinstance(items, list):
        widths = {len(s) for s in items if isinstance(s, dict)}
        mark(ctx, "scanner-org-view", SETTLED if not items or max(widths, default=0) <= 6 else CONTRADICTED, f"{len(items)} scanners, field counts {sorted(widths)}")
    else:
        mark(ctx, "scanner-org-view", NOT_REACHED, "the main credential's scanner list was not read")
    if ctx.admin is None:
        ctx.operations_read.setdefault("organization_list", "not read: no administrator envelope")
        return
    for step, operation in (("scanners (admin)", "scanner_list"), ("passive scanners (admin)", "passive_scanner_list"), ("zones (admin)", "zone_list"), ("organizations (admin)", "organization_list")):
        fetch(ctx, step, operation, client=ctx.admin)


def account_for_every_operation(ctx: Context) -> None:
    """Every allowlisted operation is listed as read or not read, with the reason (req-tenable-observe-9)."""
    for op in ALLOWLIST:
        ctx.operations_read.setdefault(op.name, "not read: no step reached it")


def finish_ledger(ctx: Context) -> list[dict[str, str]]:
    ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    mark(ctx, "hosts-paging", NOT_REACHED, "/hosts is not read in v0 (req-tenable-host-assets)")
    out = []
    for entry in ledger["assumptions"]:
        verdict, note = ctx.ledger.get(entry["id"], (NOT_REACHED, "no step reached it"))
        out.append({"id": entry["id"], "acid": entry["acid"], "verdict": verdict, "note": note})
    return out


def render(ctx: Context, ledger: list[dict[str, str]], stdout: TextIO) -> None:
    w = stdout.write
    w(f"Tenable observation of {safe(ctx.credential.qualified)}\n")
    for warning in ctx.credential.warnings():
        w(f"  WARNING {warning}\n")
    if ctx.probe is not None:
        w(f"  version {safe(ctx.probe.version)} verdict {ctx.probe.verdict}; warnings: {', '.join(ctx.probe.warnings) or 'none'}\n")
    w("\nSteps\n")
    for line in ctx.lines:
        extra = f" records={line.records}" if line.records is not None else ""
        timing = f" {line.elapsed_ms}ms" if line.elapsed_ms is not None else ""
        w(f"  {safe(line.step, 48):48} {line.operation:24} {safe(line.status, 12):12}{timing}{extra} {safe(line.note)}\n")
    w("\nOperations\n")
    for name, status in sorted(ctx.operations_read.items()):
        w(f"  {name:24} {safe(status)}\n")
    w("\nhostUniqueness lists by repository format\n")
    for fmt, lists in ctx.uniqueness.items():
        for hu, count in lists.items():
            w(f"  {safe(fmt, 12):12} {safe(hu, 60):60} {count}\n")
    w("\nPlugins by result count (top 25)\n")
    for plugin_id, total in ctx.plugin_rank:
        w(f"  {safe(plugin_id, 12):12} {total}\n")
    if ctx.filter_names:
        w(f"\nValid filter names ({len(ctx.filter_names)}): {safe(', '.join(ctx.filter_names), 2000)}\n")
    w("\nAssumptions ledger\n")
    for entry in ledger:
        w(f"  {entry['id']:28} {entry['verdict']:13} {entry['acid']:40} {safe(entry['note'])}\n")
    if ctx.out_dir is not None:
        w(f"\nShapes saved to {ctx.out_dir}\n")
        if ctx.record_bodies:
            w(f"Raw bodies saved there too ({ctx.redactions} key replacements). They can hold credentials from plugin output: delete them when done.\n")


def plan(credential: Credential, stdout: TextIO) -> None:
    """What a run would read, sending nothing (req-tenable-observe-5)."""
    stdout.write(f"Would observe {safe(credential.qualified)}; administrator envelope: {'yes' if credential.admin else 'no'}\n")
    for warning in credential.warnings():
        stdout.write(f"  WARNING {warning}\n")
    for op in ALLOWLIST:
        roles = "/".join(sorted(op.roles))
        stdout.write(f"  {op.method:4} {op.path:28} {op.name:24} {roles}\n")


def run(
    credential: Credential,
    *,
    record_bodies: bool = False,
    out_root: Path | None = None,
    save: bool = True,
    transport: BaseAdapter | None = None,
    sleep: Callable[[float], None] | None = None,
    stdout: TextIO | None = None,
) -> Context:
    stdout = stdout or sys.stdout
    kwargs: dict[str, Any] = {"transport": transport}
    if sleep is not None:
        kwargs["sleep"] = sleep
    client = SecurityCenterClient(credential, **kwargs)
    admin = SecurityCenterClient(credential, role=ADMIN, **kwargs) if credential.admin is not None else None
    out_dir = _out_dir(credential, out_root) if save else None
    ctx = Context(credential, client, admin, out_dir, record_bodies)
    token = _redact.set(credential.redact)
    try:
        _observe(ctx)
        account_for_every_operation(ctx)
        ledger = finish_ledger(ctx)
        # Both outputs carry text the instance chose (versions, field names, notes), so either key is
        # replaced in them as written, not only in saved bodies (req-tenable-observe-3).
        if out_dir is not None:
            shapes, _ = credential.redact(json.dumps({"instance_key": credential.instance_key, "responses": ctx.shapes, "ledger": ledger}, indent=2))
            write_private(out_dir / "shapes.json", shapes)
        report = io.StringIO()
        render(ctx, ledger, report)
        stdout.write(credential.redact(report.getvalue())[0])
    finally:
        _redact.reset(token)
    return ctx


def _observe(ctx: Context) -> None:
    """The steps, in order; the clients are closed whatever happens."""
    try:
        if step_probe(ctx):
            step_findings(ctx)
            step_filters(ctx)
            step_rank(ctx)
            step_tools(ctx)
            step_plugins(ctx)
            step_scans(ctx)
            step_inventory(ctx)
    finally:
        ctx.client.close()
        if ctx.admin is not None:
            ctx.admin.close()


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None, out_root: Path | None = None, secrets: Path | None = None, transport: BaseAdapter | None = None, sleep: Callable[[float], None] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tap_plugin.tenable.observe", description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument("--list", action="store_true", help="list the envelopes in scope tenable and exit; sends nothing")
    parser.add_argument("--key", help="the envelope key to observe")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and send nothing")
    parser.add_argument("--record-bodies", action="store_true", help="also save raw bodies (keys replaced); they can hold credentials from plugin output")
    args = parser.parse_args(argv)
    stdout = stdout or sys.stdout
    if secrets is None:
        from tap import secrets_root

        secrets = Path(secrets_root())
    credentials, errors = discover(secrets)
    for error in errors:
        stdout.write(f"unusable: {safe(error)}\n")
    if args.list:
        for c in credentials:
            stdout.write(f"{safe(c.key)}  admin={'yes' if c.admin else 'no'}\n")
        return 0
    chosen = [c for c in credentials if c.key == args.key]
    if not chosen:
        stdout.write("no usable envelope with that key (use --list)\n")
        return 2
    if args.dry_run:
        plan(chosen[0], stdout)
        return 0
    run(chosen[0], record_bodies=args.record_bodies, out_root=out_root, transport=transport, sleep=sleep, stdout=stdout)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
