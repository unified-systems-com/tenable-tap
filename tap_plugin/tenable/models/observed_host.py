"""Tenable observed host — a host as one Security Center repository tells it apart."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from ._base import TenableNode
from ..identity import UnkeyableError, host_key
from ._schemas import OBJECT_OR_NULL, SHA256_HEX, STR, STR_OR_NULL, validated

_REPORTED = ("host_uuid", "agent_uuid", "ip", "ips", "dns_name", "netbios_name", "mac_address", "operating_system")


class TenableObservedHost(TenableNode):
    """A host as Tenable tracks it in one repository: an observation, never a `computing_core` host.

    Keyed by the console and the host key derived from the record's own `hostUniqueness` list, by
    the same function the findings use, so every result, its host and its programs agree. The
    repository is always in the key, so one machine recorded in two repositories is two observed
    hosts, joined if ever by the reconciler. Facts Tenable can state for certain (an address on a
    network, an interface's MAC) live on shared `computing_core` nodes this host points at.

    Spec: specs/spec-tenable-v0.md (req-tenable-observed-host).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_observed_host"
    ENTITY_NAME: ClassVar[str] = "Tenable Observed Host"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A host as one Tenable Security Center repository tells it apart: the identifiers it reported "
        "and its per-host scan facts. An observation, not a computing_core host."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-observed-host"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "observation"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "host_key")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_repository"}], "edges": [{"type": "RECORDED_IN_REPOSITORY__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_observed_program"}], "edges": [{"type": "HOSTS_PROGRAM__tenable"}]},
        {"nodes": [{"type": "computing_core__ip_address"}], "edges": [{"type": "OBSERVED_AT_ADDRESS__tenable"}]},
        {"nodes": [{"type": "computing_core__network_interface"}], "edges": [{"type": "REPORTS_INTERFACE__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "tenable__tenable_finding"}, {"type": "tenable__tenable_compliance_result"}],
            "edges": [{"type": "ABOUT_HOST__tenable"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "host_key": SHA256_HEX,
        "repository_id": STR,
        "host_uniqueness": STR,
        **dict.fromkeys(_REPORTED, STR_OR_NULL),
        "host_summary": OBJECT_OR_NULL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "host_key", "repository_id", "host_uniqueness"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that reported this host.")
    host_key = models.CharField(
        max_length=64, db_index=True, help_text="Identity: derived from host_uniqueness and the component columns (identity.host_key), validated against them."
    )
    repository_id = models.CharField(max_length=32, db_index=True, help_text="The repository this host is recorded in, as returned; always part of the host key.")
    host_uniqueness = models.CharField(max_length=255, help_text="The hostUniqueness list as returned: which fields tell this host apart in its repository.")
    host_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, db_index=True, help_text="hostUUID as last reported.")
    agent_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, db_index=True, help_text="The agent UUID (uuid) as last reported.")
    ip = models.CharField(max_length=64, null=True, blank=True, default=None, db_index=True, help_text="The IP as last reported.")
    ips = models.TextField(null=True, blank=True, default=None, help_text="Every IP the host summary reported, as returned.")
    dns_name = models.CharField(max_length=255, null=True, blank=True, default=None, db_index=True, help_text="dnsName as last reported.")
    netbios_name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="netbiosName as last reported; held here until a NetBIOS node exists.")
    mac_address = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="macAddress as last reported.")
    operating_system = models.TextField(null=True, blank=True, default=None, help_text="operatingSystem as last reported: Tenable's guess.")
    host_summary = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="The host's record from the sumip analysis tool, as returned (last authenticated and unauthenticated scan, OS CPE, ...); null when not read.",
    )

    class Meta(TenableNode.Meta):
        db_table = "tenable_observed_host"

    def validate(self) -> None:
        """The key must say what the columns say (req-tenable-observed-host, req-tenable-findings-11), after the checks every node makes."""
        super().validate()
        try:
            expected = host_key(
                self.host_uniqueness,
                {
                    "repository_id": self.repository_id,
                    "ip": self.ip,
                    "dns_name": self.dns_name,
                    "netbios_name": self.netbios_name,
                    "mac_address": self.mac_address,
                    "agent_uuid": self.agent_uuid,
                    "host_uuid": self.host_uuid,
                },
            )
        except UnkeyableError as exc:
            raise ValidationError({"host_key": [str(exc)]}) from exc
        if self.host_key != expected:
            raise ValidationError({"host_key": ["host_key does not match host_uniqueness and the component columns"]})

    def get_name(self) -> str:
        if not self.host_key:
            return ""
        return (self.dns_name or self.ip or self.netbios_name or self.host_uuid or self.agent_uuid or self.host_key[:12])[:255]

    def __str__(self) -> str:
        return self.get_name()
