"""Tenable repository — where a Security Center keeps results, and the unit of reading and resolution."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ._schemas import STATEMENT_STATE, STR, STR_OR_NULL, validated

_LIFETIMES = ("active_vulns_lifetime", "passive_vulns_lifetime", "compliance_vulns_lifetime", "mitigated_vulns_lifetime")


class TenableRepository(BaseModel):
    """A Security Center repository: where results are kept, read and resolved.

    Its data format says how its hosts are told apart and whether its results come from agents.
    The data lifetimes say how long Security Center keeps a result after it was last seen, which
    is what tells a result that aged out from one that was fixed (req-tenable-states-6). The
    `hostUniqueness` list last seen in it is stored, so a run can tell when every host key in the
    repository moved (req-tenable-findings-12).

    Spec: specs/spec-tenable-v0.md (req-tenable-repository).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_repository"
    ENTITY_NAME: ClassVar[str] = "Tenable Repository"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A Security Center repository: where results are kept, its data format and data lifetimes, "
        "and the host-uniqueness rule its results use."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-repository"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "repository_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_security_center"}], "edges": [{"type": "HELD_BY_SECURITY_CENTER__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_observed_host"}], "edges": [{"type": "RECORDED_IN_REPOSITORY__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_result"}], "edges": [{"type": "IMPORTED_INTO_REPOSITORY__tenable"}]},
        {
            "nodes": [{"type": "tenable__tenable_accept_risk_rule"}, {"type": "tenable__tenable_recast_risk_rule"}],
            "edges": [{"type": "COVERS_REPOSITORY__tenable"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "repository_id": STR,
        "repository_uuid": STR_OR_NULL,
        "name": STR_OR_NULL,
        "description": STR_OR_NULL,
        "repository_type": STR_OR_NULL,
        "data_format": STR_OR_NULL,
        "vuln_count": STR_OR_NULL,
        "last_sync_time": STR_OR_NULL,
        "last_vuln_update": STR_OR_NULL,
        **dict.fromkeys(_LIFETIMES, STR_OR_NULL),
        "host_uniqueness": STR_OR_NULL,
        "state": STATEMENT_STATE,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "repository_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that holds this repository.")
    repository_id = models.CharField(max_length=32, help_text="The repository's id as returned.")
    repository_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The repository's uuid as returned; stored, not keyed.")
    name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The repository's name as returned.")
    description = models.TextField(null=True, blank=True, default=None, help_text="The repository's description as returned.")
    repository_type = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The record's type as returned (Local, Remote, Offline).")
    data_format = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="dataFormat as returned (agent, IPv4, IPv6, mobile, universal); agent marks on-board results."
    )
    vuln_count = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="vulnCount as returned.")
    last_sync_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="lastSyncTime as returned.")
    last_vuln_update = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="lastVulnUpdate as returned.")
    active_vulns_lifetime = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="activeVulnsLifetime (days) as returned.")
    passive_vulns_lifetime = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="passiveVulnsLifetime (days) as returned.")
    compliance_vulns_lifetime = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="complianceVulnsLifetime (days) as returned.")
    mitigated_vulns_lifetime = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="mitigatedVulnsLifetime (days) as returned.")
    host_uniqueness = models.CharField(
        max_length=255, null=True, blank=True, default=None, help_text="The hostUniqueness list last seen on this repository's results, as returned; null before any result."
    )
    state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="current while the repository list reports it, withdrawn once it no longer does; null when unobserved."
    )

    class Meta(BaseModel.Meta):
        db_table = "tenable_repository"

    def get_name(self) -> str:
        return (self.name or f"repository {self.repository_id}")[:255] if self.repository_id else ""

    def __str__(self) -> str:
        return self.get_name()
