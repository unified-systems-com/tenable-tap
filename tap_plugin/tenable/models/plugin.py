"""Tenable plugin — what one Security Center says about a plugin behind its results."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ._schemas import STR, STR_OR_NULL, validated

#: Plugin fields that hold free text or lists of Tenable's own, stored whole as returned.
_TEXT = ("description", "synopsis", "solution", "see_also", "xrefs", "dependencies", "cpe", "cve", "vpr_context")

#: Plugin fields that hold one short value as returned.
_SHORT = (
    "name",
    "risk_factor",
    "check_type",
    "plugin_type",
    "version",
    "required_ports",
    "required_udp_ports",
    "exploit_available",
    "exploit_ease",
    "exploit_frameworks",
    "base_score",
    "temporal_score",
    "cvss_vector",
    "cvss_v3_base_score",
    "cvss_v3_temporal_score",
    "cvss_v3_vector",
    "cvss_v4_base_score",
    "cvss_v4_vector",
    "vpr_score",
    "epss_score",
    "plugin_pub_date",
    "plugin_mod_date",
    "vuln_pub_date",
    "patch_pub_date",
    "modified_time",
    "agent",
    "seol_date",
    "stig_severity",
)


class TenablePlugin(BaseModel):
    """A Tenable plugin as one Security Center reports it, held once and linked from every result it produced.

    The plugin's CVE and CPE strings are held here and on no result: they describe the plugin, and
    a cumulative update plugin can name hundreds of CVEs while being reported once per host
    (req-tenable-plugin-5, -8). The scores, exploit fields and dates describe the plugin too, so
    they are held here once, not on every host's result. Every field is stored as returned. A plugin whose own read failed
    is still written from its results' fields, with every field only that read supplies null and
    `read_state` set to not_read (req-tenable-plugin-4). The family is an edge, not a column.

    Spec: specs/spec-tenable-v0.md (req-tenable-plugin).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_plugin"
    ENTITY_NAME: ClassVar[str] = "Tenable Plugin"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A Tenable plugin as one Security Center reports it: what it checks, its scores, CVEs and "
        "CPEs, held once for every result it produced."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-plugin"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "plugin"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "plugin_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_plugin_family"}], "edges": [{"type": "IN_PLUGIN_FAMILY__tenable"}]},
        {"nodes": [{"type": "compliance_core__compliance_vulnerability"}], "edges": [{"type": "ABOUT_VULNERABILITY__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "tenable__tenable_finding"}, {"type": "tenable__tenable_compliance_result"}],
            "edges": [{"type": "ABOUT_PLUGIN__tenable"}],
        },
        {
            "nodes": [{"type": "tenable__tenable_accept_risk_rule"}, {"type": "tenable__tenable_recast_risk_rule"}],
            "edges": [{"type": "COVERS_PLUGIN__tenable"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "plugin_id": STR,
        **dict.fromkeys((*_SHORT, *_TEXT), STR_OR_NULL),
        "read_state": {"type": ["string", "null"], "enum": ["read", "not_read", None]},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "plugin_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center whose feed this plugin belongs to.")
    plugin_id = models.CharField(max_length=32, db_index=True, help_text="The plugin id as returned (audit checks are above 1,000,000 in Security Center).")
    name = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="The plugin's name as returned.")
    description = models.TextField(null=True, blank=True, default=None, help_text="The plugin's description as returned.")
    synopsis = models.TextField(null=True, blank=True, default=None, help_text="The plugin's synopsis as returned.")
    solution = models.TextField(null=True, blank=True, default=None, help_text="The plugin's solution text as returned.")
    see_also = models.TextField(null=True, blank=True, default=None, help_text="seeAlso as returned.")
    xrefs = models.TextField(null=True, blank=True, default=None, help_text="xrefs as returned.")
    dependencies = models.TextField(null=True, blank=True, default=None, help_text="The plugin's dependencies as returned.")
    cpe = models.TextField(null=True, blank=True, default=None, help_text="The plugin's CPE string as returned; held here once and on no result.")
    cve = models.TextField(
        null=True, blank=True, default=None, help_text="The plugin's CVE string exactly as its results return it; held here once and on no result (req-tenable-plugin-5)."
    )
    vpr_context = models.TextField(null=True, blank=True, default=None, help_text="vprContext as returned.")
    risk_factor = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="riskFactor as returned.")
    check_type = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="checkType as returned.")
    plugin_type = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="The plugin's type as returned (documented: active, passive, lce, compliance, custom)."
    )
    version = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The plugin's version as returned.")
    required_ports = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="requiredPorts as returned.")
    required_udp_ports = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="requiredUDPPorts as returned.")
    exploit_available = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="exploitAvailable as returned.")
    exploit_ease = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="exploitEase as returned.")
    exploit_frameworks = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="exploitFrameworks as returned.")
    base_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The CVSS v2 base score as returned.")
    temporal_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The CVSS v2 temporal score as returned.")
    cvss_vector = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The CVSS v2 vector as returned.")
    cvss_v3_base_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The CVSS v3 base score as returned.")
    cvss_v3_temporal_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The CVSS v3 temporal score as returned.")
    cvss_v3_vector = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The CVSS v3 vector as returned.")
    cvss_v4_base_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The CVSS v4 base score as returned.")
    cvss_v4_vector = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The CVSS v4 vector as returned.")
    vpr_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The VPR score as returned.")
    epss_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The EPSS score as returned.")
    plugin_pub_date = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="pluginPubDate as returned (epoch seconds as a string).")
    plugin_mod_date = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="pluginModDate as returned; a change rewrites the plugin (req-tenable-plugin-3)."
    )
    vuln_pub_date = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="vulnPubDate as returned.")
    patch_pub_date = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="patchPubDate as returned.")
    modified_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="modifiedTime as returned.")
    agent = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="Whether the plugin runs on agents, as returned.")
    seol_date = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="seolDate (the product's end-of-life date) as returned.")
    stig_severity = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="stigSeverity as returned.")
    read_state = models.CharField(
        max_length=16,
        null=True,
        blank=True,
        default=None,
        help_text="read when GET /rest/plugin/{id} succeeded; not_read when the plugin was written from its results' fields alone. Null when unobserved.",
    )

    class Meta(BaseModel.Meta):
        db_table = "tenable_plugin"

    def get_name(self) -> str:
        return (self.name or f"plugin {self.plugin_id}")[:255] if self.plugin_id else ""

    def __str__(self) -> str:
        return self.get_name()
