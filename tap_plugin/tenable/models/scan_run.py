"""Tenable scan run — one collection of one Security Center."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ._schemas import OBJECT_OR_NULL, STR, STR_OR_NULL, validated

#: Every warning code a run may record: the counter table in req-tenable-scanner-run, and nothing else
#: (req-tenable-scanner-run-4).
WARNING_CODES = (
    "PLAINTEXT_TRANSPORT",
    "TLS_VERIFICATION_DISABLED",
    "VERSION_OUTSIDE",
    "VERSION_UNREADABLE",
    "FEED_STALE",
    "CREDENTIAL_VIEW_CHANGED",
    "HOST_UNIQUENESS_CHANGED",
    "RECONCILE_NOT_ARMED",
    "INVENTORY_NOT_VISIBLE",
)

#: Every counter a run may record, from the same table.
COUNTER_NAMES = (
    "parsed",
    "no_parser",
    "parser_failed",
    "not_applicable",
    "entries_not_stored",
    "duplicate_assertions",
    "fields_truncated",
    "facts_refused",
    "cve_disagreements",
    "possibly_truncated",
    "plugins_not_read",
    "unknown_format",
)

_SCOPES_READ = {"type": ["array", "null"], "items": {"type": "string"}}
_SCOPES_NOT_READ = {
    "type": ["array", "null"],
    "items": {
        "type": "object",
        "required": ["scope", "reason"],
        "additionalProperties": False,
        "properties": {"scope": {"type": "string"}, "reason": {"type": "string"}},
    },
}
_WARNINGS = {
    "type": ["array", "null"],
    "items": {
        "type": "object",
        "required": ["code"],
        "additionalProperties": False,
        "properties": {"code": {"type": "string", "enum": list(WARNING_CODES)}, "detail": {"type": "string"}},
    },
}
_COUNTERS = {
    "type": ["object", "null"],
    "additionalProperties": False,
    "properties": {name: {"type": "integer", "minimum": 0} for name in COUNTER_NAMES},
}
_CREDENTIAL = {
    "type": ["object", "null"],
    "additionalProperties": False,
    "properties": {name: {"type": ["string", "null"]} for name in ("user_id", "role", "organization", "group")},
}
_VERDICT = {"type": ["string", "null"], "enum": ["observed", "documented_only", "outside", "unreadable", None]}


class TenableScanRun(BaseModel):
    """One collection against one Security Center: what it read, from what, and what it could not.

    A result is judged against the run that last read it, so the run records the probe (version
    and verdict, the credential's identity, feed freshness), the filter, whether it was armed to
    reconcile, every scope read or not read, and the counters and warnings of the one table in
    the spec. It holds no list of what it saw: each observation points at it by one moved edge.

    Keyed by the console and a run id the collector mints once, as Anchore's run is, so every
    edge a run's batch writes resolves to the one run node.

    Spec: specs/spec-tenable-v0.md (req-tenable-scanner-run, req-tenable-probe, req-tenable-run-links).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_scan_run"
    ENTITY_NAME: ClassVar[str] = "Tenable Scan Run"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One collection of one Tenable Security Center: the probe, the filter, the scopes read and "
        "not read, and the run's counters and warnings."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-scan-run"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "run_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_security_center"}], "edges": [{"type": "RUN_OF_SECURITY_CENTER__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [
                {"type": "tenable__tenable_finding"},
                {"type": "tenable__tenable_compliance_result"},
                {"type": "tenable__tenable_observed_host"},
                {"type": "tenable__tenable_observed_program"},
                {"type": "tenable__tenable_repository"},
                {"type": "tenable__tenable_scan_result"},
                {"type": "tenable__tenable_accept_risk_rule"},
                {"type": "tenable__tenable_recast_risk_rule"},
                {"type": "tenable__tenable_scanner"},
                {"type": "tenable__tenable_scan_zone"},
                {"type": "tenable__tenable_plugin_family"},
                {"type": "tenable__tenable_asset_list"},
            ],
            "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "run_id": STR,
        "started_at": STR_OR_NULL,
        "finished_at": STR_OR_NULL,
        "reported_version": STR_OR_NULL,
        "version_verdict": _VERDICT,
        "credential": _CREDENTIAL,
        "feed": OBJECT_OR_NULL,
        "applied_filter": OBJECT_OR_NULL,
        "incremental": {"type": ["boolean", "null"]},
        "reconcile_armed": {"type": ["boolean", "null"]},
        "scopes_read": _SCOPES_READ,
        "scopes_not_read": _SCOPES_NOT_READ,
        "warnings": _WARNINGS,
        "counters": _COUNTERS,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "run_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center this run read (identity.canonical_root).")
    run_id = models.CharField(max_length=64, help_text="Identity within the console: an id the collector mints once per run.")
    started_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When the collector began the run; null when unobserved.")
    finished_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When the run ended; null while unfinished or unobserved.")
    reported_version = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="The version the console reported in this run's probe; null when not read."
    )
    version_verdict = models.CharField(
        max_length=16,
        null=True,
        blank=True,
        default=None,
        help_text="The supported-versions verdict: observed, documented_only, outside or unreadable; null when the probe did not run.",
    )
    credential = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="Who the credential is, from GET /rest/currentUser with pinned fields: user id, role, organisation and group; never a name, contact detail or secret. Null when not read.",
    )
    feed = models.JSONField(
        null=True, blank=True, default=None, help_text="The plugin-feed status as returned by GET /rest/feed (pinned fields), recording feed freshness; null when not read."
    )
    applied_filter = models.JSONField(
        null=True, blank=True, default=None, help_text="The scope filter this run applied, from the credential envelope; {} for none, null when unobserved."
    )
    incremental = models.BooleanField(
        null=True, blank=True, default=None, help_text="True when a filter made this run incremental, so nothing resolves by absence; null when unobserved."
    )
    reconcile_armed = models.BooleanField(
        null=True, blank=True, default=None, help_text="Whether an operator armed this run's reconcile authority, so moved edges retire; null when unobserved."
    )
    scopes_read = models.JSONField(
        null=True, blank=True, default=None, help_text="Each repository and view this run read successfully; [] when none, null when unobserved."
    )
    scopes_not_read = models.JSONField(
        null=True, blank=True, default=None, help_text="Each repository and view this run could not read, with the reason; [] when none were missed, null when unobserved."
    )
    warnings = models.JSONField(
        null=True, blank=True, default=None, help_text="Warning codes from the spec's one counter table, each with optional detail; [] when none."
    )
    counters = models.JSONField(
        null=True, blank=True, default=None, help_text="Counts from the spec's one counter table, by name; null when the run recorded none."
    )

    class Meta(BaseModel.Meta):
        db_table = "tenable_scan_run"

    def get_name(self) -> str:
        return f"run {self.run_id}" if self.run_id else ""

    def __str__(self) -> str:
        return self.get_name()
