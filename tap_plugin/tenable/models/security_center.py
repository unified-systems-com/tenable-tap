"""Tenable Security Center — one console this plugin reads."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

from ..identity import canonical_root
from ._schemas import STR, STR_OR_NULL, validated


class TenableSecurityCenter(BaseModel):
    """One Security Center console, the source every other Tenable node is attributed to.

    Its identity is the canonical root of the configured base URL, so the same host on another
    port or path root is another console. The console is not a scanner: the engines it drives are
    `tenable_scanner` nodes. The reported version and the declared network are facts about the
    console as last read, not part of its key. The key holds the root as identity only; the
    collector never reads a connection setting back from the grid (req-tenable-connection-1).

    Spec: specs/spec-tenable-v0.md (req-tenable-scanner-run, req-tenable-connection-1, -10).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_security_center"
    ENTITY_NAME: ClassVar[str] = "Tenable Security Center"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One Tenable Security Center console: the source every Tenable scan run, repository, scanner "
        "and result is attributed to."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-security-center"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key",)

    # The console is only ever the far end.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "RUN_OF_SECURITY_CENTER__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_repository"}], "edges": [{"type": "HELD_BY_SECURITY_CENTER__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_result"}], "edges": [{"type": "RESULT_OF_SECURITY_CENTER__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scanner"}], "edges": [{"type": "MANAGED_BY_SECURITY_CENTER__tenable"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "platform": {"type": "string", "enum": ["security_center"]},
        "reported_version": STR_OR_NULL,
        "network_name": STR,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        **validated(FIELD_CRUD_SCHEMA),
        "instance_key": {"validation": "function"},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "network_name"]

    instance_key = models.CharField(
        max_length=1024,
        db_index=True,
        help_text="Identity: the canonical root of the base URL (identity.canonical_root): lower-cased scheme and host, explicit port, path without a trailing slash.",
    )
    platform = models.CharField(
        max_length=32,
        default="security_center",
        help_text="Which Tenable product this is; only security_center in v0 (vulnerability_management is reserved).",
    )
    reported_version = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="The version the console reported when last probed; null when never observed. Not identity."
    )
    network_name = models.CharField(
        max_length=255,
        help_text="The network this console's results come from, as declared in its credential envelope: a value of computing_core's tap.computing.network_name dimension.",
    )

    class Meta(BaseModel.Meta):
        db_table = "tenable_security_center"

    def validate_instance_key(self) -> None:
        try:
            canonical = canonical_root(self.instance_key or "")
        except ValueError as exc:
            raise ValidationError({"instance_key": [str(exc)]}) from exc
        if canonical != self.instance_key:
            raise ValidationError({"instance_key": ["instance_key must be the canonical root"]})

    def get_name(self) -> str:
        return self.instance_key or ""

    def __str__(self) -> str:
        return self.get_name()
