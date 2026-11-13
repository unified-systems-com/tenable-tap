"""The dimension seed declares every key tenable stamps, and only tenable's own (req-tenable-shared-facts-6)."""

import json
import tomllib
from pathlib import Path

import pytest

from tap_plugin.tenable import models

HERE = Path(models.__file__).resolve().parent.parent
SEED = HERE / "grift" / "dimension.grift.json"


def declared():
    doc = json.loads(SEED.read_text(encoding="utf-8"))
    (batch,) = doc["batches"]
    assert batch["edges"] == []
    return {n["node"]["name"]: n for n in batch["nodes"]}


def stamped():
    """Every (key, value) the node and edge types stamp by default."""
    out = []
    for name in models.__all__:
        out += list(getattr(models, name).DEFAULT_DIMENSIONS.items())
    for path in sorted((HERE / "edges").glob("*.edge.json")):
        out += list(json.loads(path.read_text(encoding="utf-8")).get("default_dimensions", {}).items())
    return out


@pytest.mark.spec("req-tenable-shared-facts-6")
def test_every_stamped_key_and_value_is_declared():
    seed = declared()
    for key, value in stamped():
        assert key in seed, f"{key} is stamped but not declared in {SEED.name}"
        allowed = seed[key]["node"].get("values")
        assert allowed is None or value in allowed, f"{key}={value} is outside the declared values {allowed}"


@pytest.mark.spec("req-tenable-shared-facts-6")
def test_the_seed_declares_only_tenables_own_keys_with_well_typed_knobs():
    for name, entry in declared().items():
        assert name.startswith("tenable."), f"{name} belongs to another plugin's seed"
        assert entry["entity"]["entity_type"] == "dimension" and entry["entity"]["name"] == name
        assert entry["entity"]["dimensions"] == {"tap.meta": "dimension"}
        node = entry["node"]
        assert node["description"]
        assert isinstance(node.get("usable_in_keys", False), bool)
        values = node.get("values")
        assert values is None or (isinstance(values, list) and values and len(set(values)) == len(values) and all(isinstance(v, str) and v for v in values))
    assert set(declared()) == {"tenable.area", "tenable.instance", "tenable.scan_result"}


def test_the_manifest_lists_the_seed():
    manifest = tomllib.loads((HERE / "tap-plugin.toml").read_text(encoding="utf-8"))
    assert manifest["grift"]["dimension"] == "grift/dimension.grift.json"
