"""Tenable finding — one non-audit plugin result on one host."""

from typing import Any, ClassVar

from django.db import models

from ._result import RESULT_CREATE_REQUIRED, RESULT_CRUD_SCHEMA, RESULT_VALIDATION_SCHEMA, TenableResult
from ._schemas import ARRAY_OR_NULL, STR_OR_NULL, validated

_FINDING_ONLY: dict[str, Any] = {
    "acr_score": STR_OR_NULL,
    "asset_exposure_score": STR_OR_NULL,
    "package_observations": ARRAY_OR_NULL,
}


class TenableFinding(TenableResult):
    """One vulnerability or informational plugin result on one host, as Security Center returned it.

    Keyed by the console and an assertion key over the repository, host, plugin, port and
    protocol, never the run, so two runs reporting the same result are one finding. What
    describes the plugin (its CVEs, CPE, scores and exploit fields) is held once on the plugin
    node and reached through `ABOUT_PLUGIN__tenable`; this node holds what belongs to the result
    on this host. The package a parser read from the plugin output is kept beside the raw text.
    This plugin writes no `compliance_core` node.

    Spec: specs/spec-tenable-v0.md (req-tenable-findings, req-tenable-parsers, req-tenable-states).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_finding"
    ENTITY_NAME: ClassVar[str] = "Tenable Finding"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One Tenable plugin result (vulnerability or informational) on one host, as Security Center "
        "returned it, with its raw output and parse result."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-finding"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "finding"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "assertion_key")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_plugin"}], "edges": [{"type": "ABOUT_PLUGIN__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_observed_host"}], "edges": [{"type": "ABOUT_HOST__tenable"}]},
        {"nodes": [{"type": "computing_core__port"}], "edges": [{"type": "ABOUT_PORT__tenable"}]},
        {"nodes": [{"type": "computing_core__ip_address"}], "edges": [{"type": "ABOUT_ADDRESS__tenable"}]},
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "FOUND_IN_PACKAGE__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {**RESULT_CRUD_SCHEMA, **_FINDING_ONLY}
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {**RESULT_VALIDATION_SCHEMA, **validated(_FINDING_ONLY)}
    CREATE_REQUIRED: ClassVar[list[str]] = RESULT_CREATE_REQUIRED

    acr_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="acrScore (asset criticality) as returned.")
    asset_exposure_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="assetExposureScore as returned.")
    package_observations = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text=(
            "What the plugin's registered parser read from plugin_text: a list of package observations (ecosystem, product, name, "
            "version, installed_path, fixed_version, evidence, mapping_unambiguous); [] when it found none, null when no parser ran."
        ),
    )

    class Meta(TenableResult.Meta):
        db_table = "tenable_finding"
