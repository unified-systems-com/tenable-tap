"""Tenable scanner — one scan engine a Security Center manages."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ._schemas import STATEMENT_STATE, STR, STR_OR_NULL, validated


class TenableScanner(BaseModel):
    """One scan engine a Security Center drives: a Nessus scanner, a Nessus Manager, or a passive scanner.

    One console commonly drives several engines, so the console and its engines are separate
    nodes. Active and passive engines come from two lists that number their ids separately, so the
    kind is part of the key. Nessus's own `serverUUID` is stored but not keyed: an administrator
    re-adding a scanner gets a new id (inferred). No credential field exists on this model; the
    reads that fill it pin their `fields` so a username, password, certificate or API key is never
    fetched (req-tenable-transport-8).

    Spec: specs/spec-tenable-v0.md (req-tenable-scanners-zones).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_scanner"
    ENTITY_NAME: ClassVar[str] = "Tenable Scanner"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One scan engine a Tenable Security Center manages (a Nessus scanner, Nessus Manager or "
        "passive scanner), as the console reports it."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-scanner"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "scanner_kind", "scanner_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_security_center"}], "edges": [{"type": "MANAGED_BY_SECURITY_CENTER__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_zone"}], "edges": [{"type": "IN_SCAN_ZONE__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_scan_result"}], "edges": [{"type": "RUN_BY_SCANNER__tenable"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "scanner_kind": {"type": "string", "enum": ["active", "passive"]},
        "scanner_id": STR,
        "name": STR_OR_NULL,
        "description": STR_OR_NULL,
        "ip": STR_OR_NULL,
        "port": STR_OR_NULL,
        "status": STR_OR_NULL,
        "enabled": STR_OR_NULL,
        "version": STR_OR_NULL,
        "scanner_type": STR_OR_NULL,
        "agent_capable": STR_OR_NULL,
        "loaded_plugin_set": STR_OR_NULL,
        "num_scans": STR_OR_NULL,
        "num_hosts": STR_OR_NULL,
        "server_uuid": STR_OR_NULL,
        "state": STATEMENT_STATE,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "scanner_kind", "scanner_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that manages this scanner.")
    scanner_kind = models.CharField(max_length=8, help_text="active (GET /rest/scanner) or passive (GET /rest/passivescanner); the two number ids separately.")
    scanner_id = models.CharField(max_length=32, help_text="The scanner's id in its list, as returned.")
    name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The scanner's name as returned.")
    description = models.TextField(null=True, blank=True, default=None, help_text="The scanner's description as returned.")
    ip = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The address the console reaches the scanner at, as returned.")
    port = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The scanner's port as returned.")
    status = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The console's status code for the scanner, as returned.")
    enabled = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="Whether the scanner is enabled, as returned (\"true\" or \"false\").")
    version = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The scanner's version as returned.")
    scanner_type = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The scanner's type as returned (the record's `type`).")
    agent_capable = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="Whether the scanner manages agents, as returned.")
    loaded_plugin_set = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The plugin set the scanner has loaded, as returned.")
    num_scans = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="Scans running on the scanner when read, as returned.")
    num_hosts = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="Hosts being scanned when read, as returned.")
    server_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Nessus's own server UUID (serverUUID), stored and not keyed.")
    state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="current while a complete read reports the scanner, withdrawn once one no longer does; null when unobserved."
    )

    class Meta(BaseModel.Meta):
        db_table = "tenable_scanner"

    def get_name(self) -> str:
        return (self.name or f"{self.scanner_kind} scanner {self.scanner_id}")[:255] if self.scanner_id else ""

    def __str__(self) -> str:
        return self.get_name()
