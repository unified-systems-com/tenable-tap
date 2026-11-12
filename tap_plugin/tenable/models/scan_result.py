"""Tenable scan result — one scan a Security Center ran."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

from ._schemas import STR, STR_OR_NULL, validated

#: The scan-result fields stored as returned, by column name.
_RETURNED = (
    "name",
    "description",
    "status",
    "initiator_id",
    "owner_id",
    "scan_id",
    "scan_name",
    "import_status",
    "import_start",
    "import_finish",
    "data_format",
    "result_type",
    "result_source",
    "running",
    "error_details",
    "import_error_details",
    "total_ips",
    "scanned_ips",
    "completed_ips",
    "completed_checks",
    "total_checks",
    "start_time",
    "finish_time",
    "scan_duration",
    "agent_scan_uuid",
    "details",
    "download_available",
)


class TenableScanResult(BaseModel):
    """A scan Security Center ran, not a scan definition: when it ran, what it covered, and how its import went.

    Read for scans in the configured window. No user's name or contact details are stored: the
    initiator and owner are ids only. Which results a scan last saw is the `tenable.scan_result`
    dimension on those results, not an edge, so a scan seeing tens of thousands of results does
    not become a super-node (req-tenable-scan-result-5).

    Spec: specs/spec-tenable-v0.md (req-tenable-scan-result).
    """

    ENTITY_TYPE: ClassVar[str] = "tenable__tenable_scan_result"
    ENTITY_NAME: ClassVar[str] = "Tenable Scan Result"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A scan a Tenable Security Center ran: its status, timing, coverage and import outcome, and "
        "the repository and scanners involved."
    )
    ENTITY_ICON: ClassVar[str] = "tenable-scan-result"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"tenable.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("instance_key", "scan_result_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "tenable__tenable_security_center"}], "edges": [{"type": "RESULT_OF_SECURITY_CENTER__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_repository"}], "edges": [{"type": "IMPORTED_INTO_REPOSITORY__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scanner"}], "edges": [{"type": "RUN_BY_SCANNER__tenable"}]},
        {"nodes": [{"type": "tenable__tenable_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__tenable"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "instance_key": STR,
        "scan_result_id": STR,
        **dict.fromkeys(_RETURNED, STR_OR_NULL),
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = validated(FIELD_CRUD_SCHEMA)
    CREATE_REQUIRED: ClassVar[list[str]] = ["instance_key", "scan_result_id"]

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that ran this scan.")
    scan_result_id = models.CharField(max_length=32, help_text="The scan result's id as returned.")
    name = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="The scan result's name as returned.")
    description = models.TextField(null=True, blank=True, default=None, help_text="The description as returned.")
    status = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="status as returned (for example Completed, Running, Error).")
    initiator_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The initiating user's id only; never a name.")
    owner_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The owning user's id only; never a name.")
    scan_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The scan definition's id (scan.id) as returned.")
    scan_name = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="The scan definition's name (scan.name) as returned.")
    import_status = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="importStatus as returned.")
    import_start = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="importStart as returned.")
    import_finish = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="importFinish as returned.")
    data_format = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="dataFormat as returned.")
    result_type = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="resultType as returned.")
    result_source = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="resultSource as returned.")
    running = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="running as returned.")
    error_details = models.TextField(null=True, blank=True, default=None, help_text="errorDetails as returned.")
    import_error_details = models.TextField(null=True, blank=True, default=None, help_text="importErrorDetails as returned.")
    total_ips = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="totalIPs as returned.")
    scanned_ips = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="scannedIPs as returned.")
    completed_ips = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="completedIPs as returned.")
    completed_checks = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="completedChecks as returned.")
    total_checks = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="totalChecks as returned.")
    start_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="startTime as returned.")
    finish_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="finishTime as returned.")
    scan_duration = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="scanDuration as returned.")
    agent_scan_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="agentScanUUID as returned.")
    details = models.TextField(null=True, blank=True, default=None, help_text="details as returned, which names the scan policy.")
    download_available = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="downloadAvailable as returned.")

    class Meta(BaseModel.Meta):
        db_table = "tenable_scan_result"

    def get_name(self) -> str:
        return (self.name or f"scan result {self.scan_result_id}")[:255] if self.scan_result_id else ""

    def __str__(self) -> str:
        return self.get_name()

