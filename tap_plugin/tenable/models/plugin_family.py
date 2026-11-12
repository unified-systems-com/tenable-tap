"""Tenable plugin family — a named group of plugins."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ._schemas import STATEMENT_STATE, STR, STR_OR_NULL, validated


class TenablePluginFamily(BaseModel):
    """A plugin family as one Security Center reports it.

    Many plugins share one family, and risk rules, scan policies and filters name families, so the
    family is its own node rather than a pair of columns repeated on every plugin.

    Spec: specs/spec-tenable-v0.md (req-tenable-plugin-family).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_plugin_family"
    ENTITY_NAME: ClassVar[str] = "Tenable Plugin Family"
    ENTITY_DESCRIPTION: ClassVar[str] = "A Tenable plugin family (for example \"Ubuntu Local Security Checks\") as one Security Center reports it."
    ENTITY_ICON: ClassVar[str] = "tenable-plugin-family"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "plugin"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "family_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_plugin"}], "edges": [{"type": "IN_PLUGIN_FAMILY__tenable"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "family_id": STR,
        "name": STR_OR_NULL,
        "family_type": STR_OR_NULL,
        "plugin_count": STR_OR_NULL,
        "state": STATEMENT_STATE,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "family_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center whose feed this family belongs to.")
    family_id = models.CharField(max_length=32, help_text="The family's id as returned.")
    name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The family's name as returned.")
    family_type = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The family's type as returned (active, passive, lce, compliance, custom).")
    plugin_count = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="How many plugins the family holds (count), as returned.")
    state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="current while a complete read reports the family, withdrawn once one no longer does; null when unobserved."
    )

    class Meta(BaseModel.Meta):
        db_table = "tenable_plugin_family"

    def get_name(self) -> str:
        return (self.name or f"family {self.family_id}")[:255] if self.family_id else ""

    def __str__(self) -> str:
        return self.get_name()
