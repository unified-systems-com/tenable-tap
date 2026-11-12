"""Tenable observed program — what Tenable thinks is listening on a host's port."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ._schemas import SHA256_HEX, STR, STR_OR_NULL, validated


class TenableObservedProgram(BaseModel):
    """A service Tenable detected on one port of one observed host: an observation, never a `computing_core` program.

    A network scan infers the service from how the port answered; it does not see the program. So
    a program is written only when a registered service-detection parser names the service, and it
    is keyed by the host and the socket as Tenable returned them. Product, version and CPE are added
    with the product parsers that would fill them (req-tenable-product-parsers).

    Spec: specs/spec-tenable-v0.md (req-tenable-observed-program).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_observed_program"
    ENTITY_NAME: ClassVar[str] = "Tenable Observed Program"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A service Tenable detected listening on one port of one observed host, with the plugin output "
        "it was read from. An observation, not a computing_core program."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-observed-program"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "observation"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "host_key", "transport", "port_number")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__port"}], "edges": [{"type": "OBSERVED_ON_PORT__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_observed_host"}], "edges": [{"type": "HOSTS_PROGRAM__tenable"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "host_key": SHA256_HEX,
        "transport": STR,
        "port_number": STR,
        "service_name": STR_OR_NULL,
        "detecting_plugin_id": STR_OR_NULL,
        "evidence": STR_OR_NULL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "host_key", "transport", "port_number"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that reported this program.")
    host_key = models.CharField(max_length=64, db_index=True, help_text="The observed host's key (identity.host_key).")
    transport = models.CharField(max_length=16, help_text="The result's protocol exactly as returned (for example \"TCP\").")
    port_number = models.CharField(max_length=16, help_text="The result's port exactly as returned.")
    service_name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="The service the detection plugin named (for example \"www\").")
    detecting_plugin_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The plugin whose output named the service (22964 in v0).")
    evidence = models.TextField(null=True, blank=True, default=None, help_text="The exact segment of the plugin output the service was read from.")

    class Meta(BaseModel.Meta):
        db_table = "tenable_observed_program"

    def get_name(self) -> str:
        if not self.port_number:
            return ""
        return f"{self.service_name or 'service'} on {self.port_number}/{self.transport}"[:255]

    def __str__(self) -> str:
        return self.get_name()
