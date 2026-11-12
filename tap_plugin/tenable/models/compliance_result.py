"""Tenable compliance result — one configuration audit check result on one host."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from ..identity import text_within_ceiling
from ._result import RESULT_CREATE_REQUIRED, RESULT_CRUD_SCHEMA, RESULT_VALIDATION_SCHEMA, TenableResult
from ._schemas import STR_OR_NULL

#: The documented `cm:compliance-*` elements, each stored as its own column as written
#: (req-tenable-compliance-results). The column is `cm_` plus the element's suffix.
CM_ELEMENTS = (
    "check_name",
    "check_id",
    "result",
    "actual_value",
    "policy_value",
    "audit_file",
    "benchmark_name",
    "benchmark_version",
    "benchmark_profile",
    "control_id",
    "functional_id",
    "informational_id",
    "full_id",
    "info",
    "reference",
    "see_also",
    "solution",
    "source",
    "error",
)
CM_COLUMNS = tuple(f"cm_{element}" for element in CM_ELEMENTS)

_CM_SCHEMA: dict[str, Any] = dict.fromkeys(CM_COLUMNS, STR_OR_NULL)


class TenableComplianceResult(TenableResult):
    """One configuration audit check result (a CIS or DISA benchmark check) on one host.

    It means something different from a vulnerability and is read differently, so it has its own
    type, keyed like a finding. Its result, policy value and actual value are not structured fields
    in Security Center: they are `cm:` elements inside the plugin output, read by the one shared
    compliance parser into the `cm_` columns, each up to the free-text ceiling. Mapping a result to
    a compliance control is not done here.

    Spec: specs/spec-tenable-v0.md (req-tenable-compliance-results).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_compliance_result"
    ENTITY_NAME: ClassVar[str] = "Tenable Compliance Result"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One Tenable configuration audit check result on one host: the check, its result, the policy "
        "and actual values, and the raw output."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-compliance-result"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "finding"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "assertion_key")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_plugin"}], "edges": [{"type": "ABOUT_PLUGIN__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_observed_host"}], "edges": [{"type": "ABOUT_HOST__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {**RESULT_CRUD_SCHEMA, **_CM_SCHEMA}
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        **RESULT_VALIDATION_SCHEMA,
        **{name: {"validation": "function"} for name in CM_COLUMNS},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = RESULT_CREATE_REQUIRED

    cm_check_name = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-check-name as written; null when absent.")
    cm_check_id = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-check-id as written; null when absent.")
    cm_result = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-result as written (PASSED, FAILED, WARNING, ...); null when absent.")
    cm_actual_value = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-actual-value as written; null when absent.")
    cm_policy_value = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-policy-value as written; null when absent.")
    cm_audit_file = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-audit-file as written; null when absent.")
    cm_benchmark_name = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-benchmark-name as written; null when absent.")
    cm_benchmark_version = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-benchmark-version as written; null when absent.")
    cm_benchmark_profile = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-benchmark-profile as written; null when absent.")
    cm_control_id = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-control-id as written; null when absent.")
    cm_functional_id = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-functional-id as written; null when absent.")
    cm_informational_id = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-informational-id as written; null when absent.")
    cm_full_id = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-full-id as written; null when absent.")
    cm_info = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-info as written; null when absent.")
    cm_reference = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-reference as written; null when absent.")
    cm_see_also = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-see-also as written; null when absent.")
    cm_solution = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-solution as written; null when absent.")
    cm_source = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-source as written; null when absent.")
    cm_error = models.TextField(null=True, blank=True, default=None, help_text="cm:compliance-error as written; null when absent.")

    class Meta(TenableResult.Meta):
        db_table = "tenable_compliance_result"

    def _cm_within_ceiling(self, name: str) -> None:
        value = getattr(self, name)
        if value is not None and not isinstance(value, str):
            raise ValidationError({name: [f"{name} must be a string or null"]})
        if not text_within_ceiling(value):
            raise ValidationError({name: [f"{name} exceeds the free-text ceiling; cut it and name it in truncated_fields"]})

    def validate_cm_check_name(self) -> None:
        self._cm_within_ceiling("cm_check_name")

    def validate_cm_check_id(self) -> None:
        self._cm_within_ceiling("cm_check_id")

    def validate_cm_result(self) -> None:
        self._cm_within_ceiling("cm_result")

    def validate_cm_actual_value(self) -> None:
        self._cm_within_ceiling("cm_actual_value")

    def validate_cm_policy_value(self) -> None:
        self._cm_within_ceiling("cm_policy_value")

    def validate_cm_audit_file(self) -> None:
        self._cm_within_ceiling("cm_audit_file")

    def validate_cm_benchmark_name(self) -> None:
        self._cm_within_ceiling("cm_benchmark_name")

    def validate_cm_benchmark_version(self) -> None:
        self._cm_within_ceiling("cm_benchmark_version")

    def validate_cm_benchmark_profile(self) -> None:
        self._cm_within_ceiling("cm_benchmark_profile")

    def validate_cm_control_id(self) -> None:
        self._cm_within_ceiling("cm_control_id")

    def validate_cm_functional_id(self) -> None:
        self._cm_within_ceiling("cm_functional_id")

    def validate_cm_informational_id(self) -> None:
        self._cm_within_ceiling("cm_informational_id")

    def validate_cm_full_id(self) -> None:
        self._cm_within_ceiling("cm_full_id")

    def validate_cm_info(self) -> None:
        self._cm_within_ceiling("cm_info")

    def validate_cm_reference(self) -> None:
        self._cm_within_ceiling("cm_reference")

    def validate_cm_see_also(self) -> None:
        self._cm_within_ceiling("cm_see_also")

    def validate_cm_solution(self) -> None:
        self._cm_within_ceiling("cm_solution")

    def validate_cm_source(self) -> None:
        self._cm_within_ceiling("cm_source")

    def validate_cm_error(self) -> None:
        self._cm_within_ceiling("cm_error")
