"""The columns an accept-risk rule and a recast-risk rule share.

Both are an operator's statement in Security Center about a plugin's results on some hosts; a
recast rule also sets a new severity. This abstract model holds the shared half once. It declares
no entity type and no edges, so it registers nothing.
"""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

from ..identity import text_within_ceiling
from ._schemas import STATEMENT_STATE, STR, STR_OR_NULL, validated

RULE_CRUD_SCHEMA: dict[str, Any] = {
    "instance_key": STR,
    "rule_id": STR,
    "repository_id": STR_OR_NULL,
    "organization_id": STR_OR_NULL,
    "user_id": STR_OR_NULL,
    "plugin_id": STR_OR_NULL,
    "host_type": STR_OR_NULL,
    "host_value": STR_OR_NULL,
    "port": STR_OR_NULL,
    "protocol": STR_OR_NULL,
    "expires": STR_OR_NULL,
    "status": STR_OR_NULL,
    "comments": STR_OR_NULL,
    "created_time": STR_OR_NULL,
    "modified_time": STR_OR_NULL,
    "state": STATEMENT_STATE,
}
RULE_VALIDATION_SCHEMA: dict[str, Any] = {**validated(RULE_CRUD_SCHEMA), "comments": {"validation": "function"}}
RULE_CREATE_REQUIRED = ["instance_key", "rule_id"]


class TenableRiskRule(BaseModel):
    """An operator's risk rule in Security Center, as returned: the shared half."""

    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = RULE_VALIDATION_SCHEMA

    instance_key = models.CharField(max_length=1024, db_index=True, help_text="The Security Center that holds this rule.")
    rule_id = models.CharField(max_length=32, help_text="The rule's id as returned.")
    repository_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The repository the rule applies to (repository.id), as returned.")
    organization_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The organisation's id as returned.")
    user_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The creating user's id only; never a name.")
    plugin_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="The plugin the rule applies to (plugin.id), as returned.")
    host_type = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="hostType as returned (all, asset, ip, uuid).")
    host_value = models.TextField(null=True, blank=True, default=None, help_text="hostValue as returned: the asset list, addresses or UUIDs the rule names.")
    port = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The port the rule applies to, as returned.")
    protocol = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="The protocol the rule applies to, as returned.")
    expires = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="expires as returned (-1 when unset); a consumer compares it with the current time itself."
    )
    status = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="status as returned.")
    comments = models.TextField(null=True, blank=True, default=None, help_text="The operator's comments as returned, up to the free-text ceiling.")
    created_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="createdTime as returned.")
    modified_time = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="modifiedTime as returned.")
    state = models.CharField(
        max_length=16,
        null=True,
        blank=True,
        default=None,
        help_text="current while a complete read reports the rule, withdrawn once one no longer does; a withdrawn rule is not an assertion to rely on.",
    )

    class Meta(BaseModel.Meta):
        abstract = True

    def validate_comments(self) -> None:
        if not text_within_ceiling(self.comments):
            raise ValidationError({"comments": ["comments exceeds the free-text ceiling; cut it and record the cut on the run"]})

    def get_name(self) -> str:
        return f"rule {self.rule_id} on plugin {self.plugin_id or 'any'}"[:255] if self.rule_id else ""

    def __str__(self) -> str:
        return self.get_name()
