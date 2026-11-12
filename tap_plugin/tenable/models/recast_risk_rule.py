"""Tenable recast-risk rule — an operator's statement that a result's severity is changed."""

from typing import Any, ClassVar

from django.db import models

from ._risk_rule import RULE_CREATE_REQUIRED, RULE_CRUD_SCHEMA, RULE_VALIDATION_SCHEMA, TenableRiskRule
from ._schemas import STR_OR_NULL, validated

_RECAST_ONLY: dict[str, Any] = {"new_severity": STR_OR_NULL, "rule_order": STR_OR_NULL}


class TenableRecastRiskRule(TenableRiskRule):
    """A recast-risk rule as Security Center returns it: the accept-risk shape plus the new severity.

    Which results a rule covers is each result's own `recast_risk` flag, and the severity a result
    carries is already the recast one; no edge to individual results is written.

    Spec: specs/spec-tenable-v0.md (req-tenable-risk-rules).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_recast_risk_rule"
    ENTITY_NAME: ClassVar[str] = "Tenable Recast Risk Rule"
    ENTITY_DESCRIPTION: ClassVar[str] = "An operator's recast-risk rule in Tenable Security Center: which plugin, hosts and port it re-rates, to what severity, and why."
    ENTITY_ICON: ClassVar[str] = "tenable-recast-risk-rule"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "risk"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "rule_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_plugin"}], "edges": [{"type": "COVERS_PLUGIN__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_repository"}], "edges": [{"type": "COVERS_REPOSITORY__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_asset_list"}], "edges": [{"type": "COVERS_ASSET_LIST__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {**RULE_CRUD_SCHEMA, **_RECAST_ONLY}
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {**RULE_VALIDATION_SCHEMA, **validated(_RECAST_ONLY)}
    CREATE_REQUIRED: ClassVar[list[str]] = RULE_CREATE_REQUIRED

    new_severity = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="newSeverity as returned.")
    rule_order = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The rule's order as returned.")

    class Meta(TenableRiskRule.Meta):
        db_table = "tenable_recast_risk_rule"
