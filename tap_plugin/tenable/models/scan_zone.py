"""Tenable scan zone — a group of scanners and the ranges they cover."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

from ..identity import text_within_ceiling
from ._schemas import STATEMENT_STATE, STR, STR_OR_NULL, validated


class TenableScanZone(BaseModel):
    """A scan zone: a named group of scanners and the address ranges Security Center sends them.

    Its ranges are stored as Tenable returns them. Mapping a zone to a `computing_core` network is
    not done in v0; per-zone network configuration is the likely answer for consoles whose results
    span several networks.

    Spec: specs/spec-tenable-v0.md (req-tenable-scanners-zones).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_scan_zone"
    ENTITY_NAME: ClassVar[str] = "Tenable Scan Zone"
    ENTITY_DESCRIPTION: ClassVar[str] = "A Security Center scan zone: a named group of scanners and the address ranges it covers."
    ENTITY_ICON: ClassVar[str] = "tenable-scan-zone"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "zone_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_scanner"}], "edges": [{"type": "IN_SCAN_ZONE__tenable"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "zone_id": STR,
        "zone_uuid": STR_OR_NULL,
        "name": STR_OR_NULL,
        "description": STR_OR_NULL,
        "ip_list": STR_OR_NULL,
        "created_time": STR_OR_NULL,
        "modified_time": STR_OR_NULL,
        "state": STATEMENT_STATE,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {**validated(FIELD_CRUD_SCHEMA), "ip_list": {"validation": "function"}}
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "zone_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that holds this zone.")
    zone_id = models.CharField(max_length=32, help_text="The zone's id as returned.")
    zone_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The zone's uuid as returned; stored, not keyed.")
    name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The zone's name as returned.")
    description = models.TextField(null=True, blank=True, default=None, help_text="The zone's description as returned.")
    ip_list = models.TextField(null=True, blank=True, default=None, help_text="The zone's ranges (ipList) exactly as returned, up to the free-text ceiling.")
    created_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="createdTime as returned (epoch seconds as a string).")
    modified_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="modifiedTime as returned (epoch seconds as a string).")
    state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="current while a complete read reports the zone, withdrawn once one no longer does; null when unobserved."
    )

    class Meta(BaseModel.Meta):
        db_table = "tenable_scan_zone"

    def validate_ip_list(self) -> None:
        if not text_within_ceiling(self.ip_list):
            raise ValidationError({"ip_list": ["ip_list exceeds the free-text ceiling"]})

    def get_name(self) -> str:
        return (self.name or f"zone {self.zone_id}")[:255] if self.zone_id else ""

    def __str__(self) -> str:
        return self.get_name()
