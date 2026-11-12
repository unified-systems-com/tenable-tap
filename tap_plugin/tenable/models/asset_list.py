"""Tenable asset list — a named host group in Security Center, by its definition."""

from typing import Any, ClassVar

from django.db import models

from ._base import TenableNode
from ._schemas import STATEMENT_STATE, STR, STR_OR_NULL, validated

_DEFINITION = ("defined_ips", "defined_dns_names", "rules", "combinations")


class TenableAssetList(TenableNode):
    """A Security Center asset list: its name, type and definition as returned.

    Risk rules, scans and groups refer to asset lists, so a rule scoped to one needs a node to point
    at. Membership is not stored: Security Center recomputes it, so a membership edge would be a
    snapshot (req-tenable-asset-list-membership, Backlog). No bind credential or credential
    reference of an LDAP-query list is read; the read pins its `fields`.

    Spec: specs/spec-tenable-v0.md (req-tenable-asset-lists).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_asset_list"
    ENTITY_NAME: ClassVar[str] = "Tenable Asset List"
    ENTITY_DESCRIPTION: ClassVar[str] = "A Tenable Security Center asset list: a named host group, by its type and definition, as returned."
    ENTITY_ICON: ClassVar[str] = "tenable-asset-list"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "risk"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "asset_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "tenable__tenable_accept_risk_rule"}, {"type": "tenable__tenable_recast_risk_rule"}],
            "edges": [{"type": "COVERS_ASSET_LIST__tenable"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "asset_id": STR,
        "asset_uuid": STR_OR_NULL,
        "name": STR_OR_NULL,
        "description": STR_OR_NULL,
        "asset_type": STR_OR_NULL,
        **dict.fromkeys(_DEFINITION, STR_OR_NULL),
        "tags": STR_OR_NULL,
        "created_time": STR_OR_NULL,
        "modified_time": STR_OR_NULL,
        "state": STATEMENT_STATE,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "asset_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that holds this asset list.")
    asset_id = models.CharField(max_length=32, help_text="The asset list's id as returned.")
    asset_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The asset list's uuid as returned; stored, not keyed.")
    name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The asset list's name as returned.")
    description = models.TextField(null=True, blank=True, default=None, help_text="The description as returned.")
    asset_type = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="type as returned (static, dynamic, combination, dnsname, ldapquery, watchlist, ...)."
    )
    defined_ips = models.TextField(null=True, blank=True, default=None, help_text="definedIPs as returned, for a static list.")
    defined_dns_names = models.TextField(null=True, blank=True, default=None, help_text="definedDNSNames as returned, for a DNS-name list.")
    rules = models.TextField(null=True, blank=True, default=None, help_text="The dynamic list's rules as returned (JSON text), for a dynamic list.")
    combinations = models.TextField(null=True, blank=True, default=None, help_text="The combination as returned (JSON text), for a combination list.")
    tags = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="tags as returned.")
    created_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="createdTime as returned.")
    modified_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="modifiedTime as returned.")
    state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="current while a complete read reports the list, withdrawn once one no longer does; null when unobserved."
    )

    class Meta(TenableNode.Meta):
        db_table = "tenable_asset_list"

    def get_name(self) -> str:
        return (self.name or f"asset list {self.asset_id}")[:255] if self.asset_id else ""

    def __str__(self) -> str:
        return self.get_name()
