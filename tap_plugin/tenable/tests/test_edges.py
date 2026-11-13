"""The Tenable edge types (specs/spec-tenable-v0.md, Edge types).

Every edge between two Tenable types is created through the service layer with its declared
endpoints and refused with a wrong one, and carries its area dimension. Edges into
`computing_core` and `compliance_core` are checked against their declarations: their targets are
written by later PRs and need nodes this plugin never mints.
"""

import json
from pathlib import Path

import pytest
import tap_plugin.tenable.models  # noqa: F401 — trigger model registration

from tap_grid.dimension_names import view
from tap_grid.constraints import InvalidEdgeError
from tap_grid.models import Entity
from tap_grid.services import create_edge, create_node

from .test_nodes import PAYLOADS

EDGES = Path(__file__).resolve().parents[1] / "edges"

#: Edges between two Tenable types: slug -> (source type, target type).
INTERNAL = {
    "RUN_OF_SECURITY_CENTER__tenable": ("tenable__tenable_scan_run", "tenable__tenable_security_center"),
    "HELD_BY_SECURITY_CENTER__tenable": ("tenable__tenable_repository", "tenable__tenable_security_center"),
    "RESULT_OF_SECURITY_CENTER__tenable": ("tenable__tenable_scan_result", "tenable__tenable_security_center"),
    "MANAGED_BY_SECURITY_CENTER__tenable": ("tenable__tenable_scanner", "tenable__tenable_security_center"),
    "IN_SCAN_ZONE__tenable": ("tenable__tenable_scanner", "tenable__tenable_scan_zone"),
    "RUN_BY_SCANNER__tenable": ("tenable__tenable_scan_result", "tenable__tenable_scanner"),
    "ABOUT_PLUGIN__tenable": ("tenable__tenable_finding", "tenable__tenable_plugin"),
    "IN_PLUGIN_FAMILY__tenable": ("tenable__tenable_plugin", "tenable__tenable_plugin_family"),
    "ABOUT_HOST__tenable": ("tenable__tenable_compliance_result", "tenable__tenable_observed_host"),
    "IMPORTED_INTO_REPOSITORY__tenable": ("tenable__tenable_scan_result", "tenable__tenable_repository"),
    "RECORDED_IN_REPOSITORY__tenable": ("tenable__tenable_observed_host", "tenable__tenable_repository"),
    "HOSTS_PROGRAM__tenable": ("tenable__tenable_observed_host", "tenable__tenable_observed_program"),
    "COVERS_PLUGIN__tenable": ("tenable__tenable_recast_risk_rule", "tenable__tenable_plugin"),
    "COVERS_REPOSITORY__tenable": ("tenable__tenable_accept_risk_rule", "tenable__tenable_repository"),
    "COVERS_ASSET_LIST__tenable": ("tenable__tenable_accept_risk_rule", "tenable__tenable_asset_list"),
    "LAST_SEEN_IN_RUN__tenable": ("tenable__tenable_finding", "tenable__tenable_scan_run"),
}

#: Edges into another plugin's vocabulary: slug -> (sources, the one target).
EXTERNAL = {
    "ABOUT_VULNERABILITY__tenable": (["tenable__tenable_plugin"], "compliance_core__compliance_vulnerability"),
    "FOUND_IN_PACKAGE__tenable": (["tenable__tenable_finding"], "computing_core__package"),
    "ABOUT_PORT__tenable": (["tenable__tenable_finding"], "computing_core__port"),
    "ABOUT_ADDRESS__tenable": (["tenable__tenable_finding"], "computing_core__ip_address"),
    "OBSERVED_AT_ADDRESS__tenable": (["tenable__tenable_observed_host"], "computing_core__ip_address"),
    "REPORTS_INTERFACE__tenable": (["tenable__tenable_observed_host"], "computing_core__network_interface"),
    "OBSERVED_ON_PORT__tenable": (["tenable__tenable_observed_program"], "computing_core__port"),
}


def _node(type_slug: str) -> Entity:
    payload, _, _ = PAYLOADS[type_slug]
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return Entity.objects.get(pk=result.entity_id)


def _definition(slug: str) -> dict:
    return json.loads((EDGES / f"{slug}.edge.json").read_text())


def test_every_edge_file_is_covered():
    assert {p.name.removesuffix(".edge.json") for p in EDGES.glob("*.edge.json")} == set(INTERNAL) | set(EXTERNAL)


@pytest.mark.django_db
@pytest.mark.parametrize("slug", sorted(INTERNAL))
class TestInternalEdges:
    def test_declared_endpoints_accepted_with_area(self, slug):
        source, target = INTERNAL[slug]
        edge = create_edge(_node(source), _node(target), slug)
        edge.entity.refresh_from_db()
        assert view(edge.entity.dimensions).get("tenable.area") == _definition(slug)["default_dimensions"]["tenable.area"]

    def test_reversed_endpoints_refused(self, slug):
        source, target = INTERNAL[slug]
        with pytest.raises(InvalidEdgeError):
            create_edge(_node(target), _node(source), slug)


@pytest.mark.parametrize("slug", sorted(EXTERNAL))
def test_external_edges_are_closed_to_one_declared_type(slug):
    sources, target = EXTERNAL[slug]
    definition = _definition(slug)
    assert definition["sources"] == sources
    assert definition["targets"] == [target]
    assert "vocabulary dependency" in definition["description"]


@pytest.mark.spec("req-tenable-run-links")
def test_last_seen_reaches_every_observation():
    sources = set(_definition("LAST_SEEN_IN_RUN__tenable")["sources"])
    assert sources == {
        "tenable__tenable_finding",
        "tenable__tenable_compliance_result",
        "tenable__tenable_observed_host",
        "tenable__tenable_observed_program",
        "tenable__tenable_repository",
        "tenable__tenable_scan_result",
        "tenable__tenable_accept_risk_rule",
        "tenable__tenable_recast_risk_rule",
        "tenable__tenable_scanner",
        "tenable__tenable_scan_zone",
        "tenable__tenable_plugin_family",
        "tenable__tenable_asset_list",
    }


@pytest.mark.spec("req-tenable-scan-result-5")
def test_no_edge_from_a_result_to_a_scan_result():
    for definition in (json.loads(p.read_text()) for p in EDGES.glob("*.edge.json")):
        if "tenable__tenable_scan_result" in definition.get("targets", []):
            assert not {"tenable__tenable_finding", "tenable__tenable_compliance_result"} & set(definition["sources"])
