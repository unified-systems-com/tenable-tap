"""The columns a Tenable finding and a Tenable compliance result share.

Both are one plugin result on one host, keyed the same way and resolved the same way; they differ
in what the result means and in the columns their plugin output fills (req-tenable-compliance-results:
"stored as on a finding"). This abstract model holds the shared half once. It declares no entity
type and no edges, so it registers nothing.
"""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

from ..identity import UnkeyableError, assertion_key, host_key, text_within_ceiling
from ._schemas import (
    ARRAY_OR_NULL,
    OBSERVATION_PATH,
    PARSE_STATE,
    RESOLUTION_SOURCE,
    RESULT_STATE,
    SHA256_HEX,
    STR,
    STR_OR_NULL,
    validated,
)

#: Free-text columns held to the ceiling (req-tenable-findings-13).
RESULT_TEXT_FIELDS = ("plugin_text", "accept_risk_comment", "recast_risk_comment")

RESULT_CRUD_SCHEMA: dict[str, Any] = {
    "instance_key": STR,
    "assertion_key": SHA256_HEX,
    "repository_id": STR,
    "host_key": SHA256_HEX,
    "host_uniqueness": STR,
    "host_uuid": STR_OR_NULL,
    "agent_uuid": STR_OR_NULL,
    "ip": STR_OR_NULL,
    "dns_name": STR_OR_NULL,
    "netbios_name": STR_OR_NULL,
    "mac_address": STR_OR_NULL,
    "operating_system": STR_OR_NULL,
    "plugin_id": STR,
    "port": STR,
    "protocol": STR,
    "severity_id": STR_OR_NULL,
    "severity_name": STR_OR_NULL,
    "first_seen": STR_OR_NULL,
    "last_seen": STR_OR_NULL,
    "last_mitigated": STR_OR_NULL,
    "has_been_mitigated": STR_OR_NULL,
    "accept_risk": STR_OR_NULL,
    "recast_risk": STR_OR_NULL,
    "accept_risk_comment": STR_OR_NULL,
    "recast_risk_comment": STR_OR_NULL,
    "vuln_uuid": STR_OR_NULL,
    "vuln_uniqueness": STR_OR_NULL,
    "plugin_text": STR_OR_NULL,
    "truncated_fields": ARRAY_OR_NULL,
    "state": RESULT_STATE,
    "resolution_source": RESOLUTION_SOURCE,
    "observation_path": OBSERVATION_PATH,
    "parse_state": PARSE_STATE,
    "parser_version": STR_OR_NULL,
}

RESULT_VALIDATION_SCHEMA: dict[str, Any] = {
    **validated(RESULT_CRUD_SCHEMA),
    **{name: {"validation": "function"} for name in RESULT_TEXT_FIELDS},
}

RESULT_CREATE_REQUIRED = [
    "instance_key",
    "assertion_key",
    "repository_id",
    "host_key",
    "host_uniqueness",
    "plugin_id",
    "port",
    "protocol",
]


def _within_ceiling(model: BaseModel, name: str) -> None:
    if not text_within_ceiling(getattr(model, name)):
        raise ValidationError({name: [f"{name} exceeds the free-text ceiling; cut it and name it in truncated_fields"]})


class TenableResult(BaseModel):
    """One plugin result on one host, as Security Center returned it: the shared half."""

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = RESULT_VALIDATION_SCHEMA

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center this result came from.")
    assertion_key = models.CharField(
        max_length=64,
        db_index=True,
        help_text="Identity: sha256 of [repository_id, host_key, plugin_id, port, protocol] (identity.assertion_key), validated against those columns.",
    )
    repository_id = models.CharField(max_length=32, db_index=True, help_text="The repository the result is recorded in (repository.id), as returned.")
    host_key = models.CharField(
        max_length=64,
        db_index=True,
        help_text="The observed host's key, derived from host_uniqueness and the component columns (identity.host_key), validated against them.",
    )
    host_uniqueness = models.CharField(max_length=255, help_text="The record's hostUniqueness list as returned: which fields tell its host apart.")
    host_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, db_index=True, help_text="hostUUID as returned.")
    agent_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, db_index=True, help_text="The agent UUID (the record's uuid) as returned.")
    ip = models.CharField(max_length=64, null=True, blank=True, default=None, db_index=True, help_text="The reported IP as returned.")
    dns_name = models.CharField(max_length=255, null=True, blank=True, default=None, db_index=True, help_text="dnsName as returned.")
    netbios_name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="netbiosName as returned.")
    mac_address = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="macAddress as returned.")
    operating_system = models.TextField(null=True, blank=True, default=None, help_text="operatingSystem as returned: Tenable's guess.")
    plugin_id = models.CharField(max_length=32, db_index=True, help_text="pluginID as returned.")
    port = models.CharField(max_length=16, help_text="The port as returned; \"0\" is an observed value meaning no port.")
    protocol = models.CharField(max_length=16, help_text="The protocol as returned (for example \"TCP\").")
    severity_id = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="severity.id as returned (after any recast).")
    severity_name = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="severity.name as returned.")
    first_seen = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="firstSeen as returned (epoch seconds as a string).")
    last_seen = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="lastSeen as returned (epoch seconds as a string).")
    last_mitigated = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="lastMitigated as returned; documented only as a filter name, so null until observed."
    )
    has_been_mitigated = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="hasBeenMitigated as returned.")
    accept_risk = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="acceptRisk as returned: whether an accept-risk rule covers the result.")
    recast_risk = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="recastRisk as returned: whether a recast-risk rule covers the result.")
    accept_risk_comment = models.TextField(null=True, blank=True, default=None, help_text="acceptRiskRuleComment as returned: operator text, up to the ceiling.")
    recast_risk_comment = models.TextField(null=True, blank=True, default=None, help_text="recastRiskRuleComment as returned: operator text, up to the ceiling.")
    vuln_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="vulnUUID as returned; stored, never keyed (only 6.7+ guarantees it).")
    vuln_uniqueness = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="vulnUniqueness as returned; stored, never keyed.")
    plugin_text = models.TextField(
        null=True,
        blank=True,
        default=None,
        help_text=(
            "The plugin output as returned, whole up to 4 MiB. Scanner output: it can hold paths, configuration "
            "fragments or credentials; it is neither scanned nor redacted, and grid read authorization protects it."
        ),
    )
    truncated_fields = models.JSONField(
        null=True, blank=True, default=None, help_text="Names of the free-text fields cut at the ceiling; [] when none, null when unobserved."
    )
    state = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="current or resolved; null when never observed.")
    resolution_source = models.CharField(
        max_length=32,
        null=True,
        blank=True,
        default=None,
        help_text="How a resolved result was resolved: tenable_mitigated, not_reported, aged_out or identity_changed; null while current.",
    )
    observation_path = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="passive, on_board (agent repository) or network; null when unobserved."
    )
    parse_state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="parsed, no_parser, parser_failed or not_applicable; never read no_parser as no package."
    )
    parser_version = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The version of the parser that produced the parse result; null when none ran.")

    class Meta(BaseModel.Meta):
        abstract = True

    def validate_plugin_text(self) -> None:
        _within_ceiling(self, "plugin_text")

    def validate_accept_risk_comment(self) -> None:
        _within_ceiling(self, "accept_risk_comment")

    def validate_recast_risk_comment(self) -> None:
        _within_ceiling(self, "recast_risk_comment")

    def validate(self) -> None:
        """The keys must say what the columns say (req-tenable-findings-2, -11)."""
        try:
            expected_host = host_key(
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
            expected_assertion = assertion_key(self.repository_id, expected_host, self.plugin_id, self.port, self.protocol)
        except UnkeyableError as exc:
            raise ValidationError({"host_key": [str(exc)]}) from exc
        errors = {}
        if self.host_key != expected_host:
            errors["host_key"] = ["host_key does not match host_uniqueness and the component columns"]
        if self.assertion_key != expected_assertion:
            errors["assertion_key"] = ["assertion_key does not match its component columns"]
        if errors:
            raise ValidationError(errors)

    def get_name(self) -> str:
        if not self.plugin_id:
            return ""
        where = self.dns_name or self.ip or self.host_uuid or self.agent_uuid or self.host_key[:12]
        return f"{self.plugin_id} on {where}:{self.port}/{self.protocol}"[:255]

    def __str__(self) -> str:
        return self.get_name()
