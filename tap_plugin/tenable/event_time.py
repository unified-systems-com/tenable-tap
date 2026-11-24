"""How Security Center's times reach core's event time (req-tenable-event-time).

Security Center sends every time as a count of seconds since 1970, as a string, and this plugin
stores it exactly as sent (req-grid-entity-event-time rule 22). Core's own reader for that form,
``from_epoch_seconds``, reads ``-1`` and ``0`` as real instants on purpose (rule 27); Security
Center uses both to mean "not set" (``expires`` is ``-1`` on a rule that never expires, a running
scan has no ``finishTime``). So every tenable declaration names :func:`from_tenable_epoch`, which
returns nothing for those markers and hands every other value to core's reader. It is pure: it reads
its argument and nothing else (rule 25).

Changing what this function returns changes what stored spine values mean with no change of
definition: raise each declaring type's ``MODEL_VERSION`` by hand and run core's re-derive pass
(rule 28).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from tap_grid.event_time import from_epoch_seconds

__all__ = ["TENABLE_EPOCH", "UNSET_MARKERS", "from_tenable_epoch"]

#: The import path every tenable declaration names: a path, so a type's definition records it by name (rule 28).
TENABLE_EPOCH = "tap_plugin.tenable.event_time:from_tenable_epoch"

#: The values Security Center sends for a time it does not have.
UNSET_MARKERS = frozenset({"-1", "0", -1, 0})


def from_tenable_epoch(value: Any) -> datetime | None:
    """A Security Center time as an aware UTC datetime, or None where it means "not set"."""
    if value in UNSET_MARKERS:
        return None
    return from_epoch_seconds(value)
