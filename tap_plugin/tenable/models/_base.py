"""The checks every Tenable node makes on save, whatever its type.

Two invariants hold on every Tenable-owned row, so they live once here rather than in fifteen
models: the instance key is the canonical root `identity.canonical_root` produces (so no writer can
store a key carrying userinfo, or split one console into two key spaces), and no text or JSON
column holds more than the free-text ceiling (req-tenable-findings-10, -13). This abstract model
declares no fields, no entity type and no edges, so it registers nothing and adds no migration.
"""

import json

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel

from ..identity import FREE_TEXT_CEILING_BYTES, canonical_root, text_within_ceiling


class TenableNode(BaseModel):
    """A Tenable-owned node: canonical instance key, and every free-text column within the ceiling."""

    class Meta(BaseModel.Meta):
        abstract = True

    def validate(self) -> None:
        super().validate()
        errors: dict[str, list[str]] = {}
        try:
            canonical = canonical_root(self.instance_key or "")
        except ValueError as exc:
            errors["instance_key"] = [str(exc)]
        else:
            if canonical != self.instance_key:
                errors["instance_key"] = ["instance_key must be the canonical root (identity.canonical_root)"]
        for field in self._meta.concrete_fields:
            value = getattr(self, field.attname, None)
            if value is None:
                continue
            if isinstance(field, models.TextField) and not text_within_ceiling(value):
                errors[field.name] = [f"{field.name} exceeds the free-text ceiling; cut it and name it in the run's counters"]
            elif isinstance(field, models.JSONField) and len(json.dumps(value).encode("utf-8")) > FREE_TEXT_CEILING_BYTES:
                errors[field.name] = [f"{field.name} exceeds the free-text ceiling"]
        if errors:
            raise ValidationError(errors)
