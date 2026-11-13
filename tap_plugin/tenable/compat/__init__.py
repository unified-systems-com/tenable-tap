"""Supported upstream versions as data, and the verdict a run records against them (req-tenable-upstream-versions)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

HERE = Path(__file__).resolve().parent
DATA_PATH = HERE / "upstream.json"
SCHEMA_PATH = HERE / "upstream.schema.json"

#: The four verdicts a run can record (req-tenable-upstream-versions-3).
OBSERVED = "observed"
DOCUMENTED_ONLY = "documented-only"
OUTSIDE = "outside"
UNREADABLE = "unreadable"

_VERSION = re.compile(r"^\s*([0-9]+(?:\.[0-9]+){0,3})")


class CompatError(Exception):
    """The upstream file is not valid."""


@dataclass(frozen=True)
class Verdict:
    """One run's verdict on the instance's version. ``below_floor`` ends the run (req-tenable-upstream-versions-4)."""

    verdict: str
    version: str | None
    below_floor: bool = False

    @property
    def warning(self) -> str | None:
        """The run warning this verdict records, if any."""
        return {OUTSIDE: "VERSION_OUTSIDE", UNREADABLE: "VERSION_UNREADABLE"}.get(self.verdict)


def version_tuple(text: str | None) -> tuple[int, ...] | None:
    """The leading dotted number of a version string as a tuple, or None when there is none."""
    if not isinstance(text, str):
        return None
    found = _VERSION.match(text)
    if found is None:
        return None
    parts = tuple(int(p) for p in found.group(1).split("."))
    return parts + (0,) * (4 - len(parts))


def contains(spec: str, version: tuple[int, ...]) -> bool:
    """Whether ``version`` satisfies a bounded specifier from the file."""
    if spec.startswith("=="):
        return version == version_tuple(spec[2:])
    lower, upper = spec.split(",")
    low, high = version_tuple(lower[2:]), version_tuple(upper[1:])
    assert low is not None and high is not None
    return low <= version < high


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    """The upstream file, validated against its schema."""
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        raise CompatError(f"{DATA_PATH.name}: {exc.message}") from None
    return data


def verdict(version: str | None, data: dict[str, Any] | None = None) -> Verdict:
    """The verdict for a Security Center version as the probe read it."""
    data = data if data is not None else load()
    parsed = version_tuple(version)
    if parsed is None:
        return Verdict(UNREADABLE, None)
    floor = version_tuple(data["hard_floor"])
    assert floor is not None
    if parsed < floor:
        return Verdict(OUTSIDE, version, below_floor=True)
    matches = [e for e in data["entries"] if e["product"] == "tenable_security_center" and contains(e["supported"], parsed)]
    if any(e["evidence"] == "observed" for e in matches):
        return Verdict(OBSERVED, version)
    if matches:
        return Verdict(DOCUMENTED_ONLY, version)
    return Verdict(OUTSIDE, version)


def readme_table(data: dict[str, Any] | None = None) -> str:
    """The README's supported-versions table, generated from the file (req-tenable-upstream-versions-5)."""
    data = data if data is not None else load()
    names = {"tenable_security_center": "Tenable Security Center", "pytenable": "pyTenable"}
    rows = ["| Product | Supported | Evidence |", "| --- | --- | --- |"]
    rows += [f"| {names[e['product']]} | `{e['supported']}` | {e['evidence']} |" for e in data["entries"]]
    return "\n".join(rows)
