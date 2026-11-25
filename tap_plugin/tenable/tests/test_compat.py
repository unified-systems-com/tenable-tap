"""Supported upstream versions as data: the schema, the verdict, and the README table (req-tenable-upstream-versions-*)."""

import copy
import json
import re
from pathlib import Path

import jsonschema
import pytest

from tap_plugin.tenable import compat

REPO = Path(compat.__file__).resolve().parents[3]


def schema():
    return json.loads(compat.SCHEMA_PATH.read_text(encoding="utf-8"))


def entry(**over):
    base = {"description": "d", "product": "tenable_security_center", "supported": ">=5.13,<6.10", "evidence": "documented", "note": "n"}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def doc(*entries):
    return {"description": "d", "hard_floor": "5.13", "entries": list(entries) or [entry()]}


@pytest.mark.spec("req-tenable-upstream-versions-1")
class TestSchema:
    def test_the_committed_file_validates(self):
        compat.load.cache_clear()
        data = compat.load()
        assert data["hard_floor"] == "5.13" and all(e["description"] for e in data["entries"])

    @pytest.mark.parametrize("supported", [">=5.13", ">5.13,<6.10", ">=5.13,<=6.10", "<6.10", "*", "~=6.0"])
    def test_an_open_or_loose_specifier_is_refused(self, supported):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc(entry(supported=supported)), schema())

    def test_an_entry_without_a_description_is_refused(self):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc(entry(description=None)), schema())


@pytest.mark.spec("req-tenable-upstream-versions-2")
class TestObservedNeedsEvidence:
    def test_observed_without_a_date_and_recording_is_refused(self):
        for missing in ({"observed_on": None, "recording": "fixtures/x.json"}, {"observed_on": "2026-11-12", "recording": None}):
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(doc(entry(evidence="observed", **missing)), schema())

    def test_observed_with_both_validates(self):
        jsonschema.validate(doc(entry(evidence="observed", observed_on="2026-11-12", recording="fixtures/x.json")), schema())

    def test_nothing_starts_observed(self):
        compat.load.cache_clear()
        assert all(e["evidence"] != "observed" for e in compat.load()["entries"])


@pytest.mark.spec("req-tenable-upstream-versions-3")
@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("6.4.0", compat.DOCUMENTED_ONLY),
        ("5.13", compat.DOCUMENTED_ONLY),
        ("6.10.0", compat.OUTSIDE),
        ("7.0", compat.OUTSIDE),
        (None, compat.UNREADABLE),
        ("", compat.UNREADABLE),
        ("unknown", compat.UNREADABLE),
    ],
)
def test_each_version_gets_exactly_one_of_four_verdicts(version, expected):
    found = compat.verdict(version)
    assert found.verdict == expected
    assert found.verdict in {compat.OBSERVED, compat.DOCUMENTED_ONLY, compat.OUTSIDE, compat.UNREADABLE}


@pytest.mark.spec("req-tenable-upstream-versions-3")
def test_an_observed_entry_makes_its_range_observed():
    data = doc(entry(supported=">=6.4,<6.5", evidence="observed", observed_on="2026-11-12", recording="x"), entry())
    assert compat.verdict("6.4.1", data).verdict == compat.OBSERVED
    assert compat.verdict("6.5.0", data).verdict == compat.DOCUMENTED_ONLY


@pytest.mark.spec("req-tenable-upstream-versions-4")
def test_outside_warns_and_only_below_the_floor_ends_the_run():
    above = compat.verdict("6.12.0")
    assert above.warning == "VERSION_OUTSIDE" and above.below_floor is False
    assert compat.verdict("garbled").warning == "VERSION_UNREADABLE"
    below = compat.verdict("5.12.9")
    assert below.verdict == compat.OUTSIDE and below.below_floor is True
    assert compat.verdict("6.4.0").warning is None


@pytest.mark.spec("req-tenable-upstream-versions-5")
def test_the_readme_table_is_generated_from_the_file():
    readme = REPO / "README.md"
    if not readme.exists():
        pytest.skip("installed without the repository checkout")
    found = re.search(r"<!-- upstream-versions:begin -->\n(.*?)\n<!-- upstream-versions:end -->", readme.read_text(encoding="utf-8"), re.S)
    assert found, "README has no upstream-versions block"
    compat.load.cache_clear()
    assert found.group(1) == compat.readme_table()


@pytest.mark.spec("req-tenable-upstream-versions-5")
def test_the_pytenable_entry_matches_the_pin():
    pyproject = REPO / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("installed without the repository checkout")
    pin = re.search(r'"pytenable(==[^"]+)"', pyproject.read_text(encoding="utf-8"))
    assert pin
    compat.load.cache_clear()
    assert [e["supported"] for e in compat.load()["entries"] if e["product"] == "pytenable"] == [pin.group(1)]


def test_an_invalid_file_raises_compat_error(monkeypatch, tmp_path):
    bad = copy.deepcopy(compat.load())
    bad["entries"][0]["supported"] = ">=5.13"
    path = tmp_path / "upstream.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    monkeypatch.setattr(compat, "DATA_PATH", path)
    compat.load.cache_clear()
    try:
        with pytest.raises(compat.CompatError, match="upstream.json"):
            compat.load()
    finally:
        monkeypatch.undo()
        compat.load.cache_clear()
