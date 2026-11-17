"""Analysis query bodies, built by the plugin and never by pyTenable's helpers (req-tenable-transport-7).

pyTenable's ``analysis.vulns()`` adds ``wasVuln=excludeWas`` to every cumulative query, and Security
Center accepts that filter only from 6.2 (pyTenable issue 828). Here the filter is added only when the
probed version is 6.2 or later. Every body carries ``acceptRiskStatus=all`` (req-tenable-transport-9).

Two shapes are disputed between Tenable's documentation and pyTenable (req-tenable-response-contract-7).
Paging offsets go at the request root in the documentation and inside ``query`` in pyTenable, and
the ``individual`` view's scan id goes at the root in pyTenable's ``vulns()`` and inside ``query`` in
its generic path. Each body sends both forms until the observation command has settled them on an
instance.
"""

from __future__ import annotations

from typing import Any

from tap_plugin.tenable.compat import version_tuple
from tap_plugin.tenable.transport import ACCEPT_ALL

WAS_FILTER_FROM = (6, 2, 0, 0)


def flt(name: str, value: Any, operator: str = "=") -> dict[str, Any]:
    """One analysis filter in Security Center's documented form."""
    return {"filterName": name, "operator": operator, "value": value}


def body(
    tool: str,
    source_type: str,
    *,
    start: int,
    end: int,
    filters: list[dict[str, Any]] | None = None,
    version: str | None = None,
    scan_result_id: str | None = None,
) -> dict[str, Any]:
    """An analysis body for ``tool`` over records ``[start, end)``.

    ``filters`` are the run's filters. ``acceptRiskStatus=all`` is always added, and so is
    ``wasVuln=excludeWas`` on a cumulative or patched query when ``version`` is 6.2 or later.
    """
    if end <= start or start < 0:
        raise ValueError("an analysis page must have end > start >= 0")
    if (source_type == "individual") != (scan_result_id is not None):
        raise ValueError("an individual query needs a scan result id, and only it may have one")
    out_filters = [dict(f) for f in (filters or []) if f.get("filterName") not in ("acceptRiskStatus", "wasVuln")]
    out_filters.append(dict(ACCEPT_ALL))
    parsed = version_tuple(version)
    if source_type != "individual" and parsed is not None and parsed >= WAS_FILTER_FROM:
        out_filters.append(flt("wasVuln", "excludeWas"))
    query: dict[str, Any] = {"type": "vuln", "tool": tool, "filters": out_filters, "startOffset": start, "endOffset": end}
    payload: dict[str, Any] = {"type": "vuln", "sourceType": source_type, "query": query, "startOffset": start, "endOffset": end}
    if scan_result_id is not None:
        payload["scanID"] = scan_result_id
        query["scanID"] = scan_result_id
        query["view"] = "all"
    return payload
