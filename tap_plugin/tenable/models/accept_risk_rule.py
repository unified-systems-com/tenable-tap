"""Tenable accept-risk rule — an operator's statement that a risk is accepted."""

from typing import Any, ClassVar

from ._risk_rule import RULE_CREATE_REQUIRED, RULE_CRUD_SCHEMA, RULE_VALIDATION_SCHEMA, TenableRiskRule


class TenableAcceptRiskRule(TenableRiskRule):
    """An accept-risk rule as Security Center returns it.

    Which results a rule covers is each result's own `accept_risk` flag; no edge to individual
    results is written, because a rule covering all hosts would fan out across the fleet.

    Spec: specs/spec-tenable-v0.md (req-tenable-risk-rules).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_accept_risk_rule"
    ENTITY_NAME: ClassVar[str] = "Tenable Accept Risk Rule"
    ENTITY_DESCRIPTION: ClassVar[str] = "An operator's accept-risk rule in Tenable Security Center: which plugin, hosts and port it covers, until when, and why."
    ENTITY_ICON: ClassVar[str] = "tenable-accept-risk-rule"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "risk"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "rule_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_plugin"}], "edges": [{"type": "COVERS_PLUGIN__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_repository"}], "edges": [{"type": "COVERS_REPOSITORY__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_asset_list"}], "edges": [{"type": "COVERS_ASSET_LIST__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = RULE_CRUD_SCHEMA
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = RULE_VALIDATION_SCHEMA
    CREATE_REQUIRED: ClassVar[list[str]] = RULE_CREATE_REQUIRED

    class Meta(TenableRiskRule.Meta):
        db_table = "tenable_accept_risk_rule"
