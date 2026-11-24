"""Security Center's times on core's event time (req-tenable-event-time).

Every Tenable time is stored exactly as Security Center sends it, epoch seconds as text, and reaches
the spine only through the plugin's reader, which reads ``-1`` and ``0`` as "not set". The values
are spec-derived from Tenable's documented API, not recorded from an instance.
"""

from datetime import UTC, datetime

import pytest
import tap_plugin.tenable.models  # noqa: F401 — trigger model registration
from tap_plugin.tenable.event_time import TENABLE_EPOCH, from_tenable_epoch
from tap_plugin.tenable.tests.conftest import dimension_view
from tap_plugin.tenable.tests.test_nodes import PAYLOADS, _result

from tap_grid.event_time import NO_EVENT_TIME, TIME_DIMENSION, Interval, Moment
from tap_grid.models import Entity
from tap_grid.registry import get_model_class, list_entity_types
from tap_grid.services import create_node

EPOCH = "1763805600"
INSTANT = datetime(2025, 11, 22, 10, 0, tzinfo=UTC)
LATER = "1763892000"
LATER_INSTANT = datetime(2025, 11, 23, 10, 0, tzinfo=UTC)

#: What each type declares (req-tenable-event-time-1).
TIMED = {
    "tenable__tenable_finding": ("first_seen", None, "first_seen"),
    "tenable__tenable_compliance_result": ("first_seen", None, "first_seen"),
    "tenable__tenable_plugin": ("plugin_pub_date", None, "published"),
    "tenable__tenable_scan_result": ("start_time", "finish_time", "occurred"),
    "tenable__tenable_accept_risk_rule": ("created_time", "expires", "created"),
    "tenable__tenable_recast_risk_rule": ("created_time", "expires", "created"),
    "tenable__tenable_asset_list": ("created_time", None, "created"),
    "tenable__tenable_scan_zone": ("created_time", None, "created"),
}
UNTIMED = (
    "tenable__tenable_security_center",
    "tenable__tenable_scanner",
    "tenable__tenable_plugin_family",
    "tenable__tenable_observed_host",
    "tenable__tenable_observed_program",
    "tenable__tenable_repository",
    "tenable__tenable_scan_run",
)


def _payload(type_slug: str) -> dict:
    if type_slug in ("tenable__tenable_finding", "tenable__tenable_compliance_result"):
        return _result()
    return dict(PAYLOADS[type_slug][0])


def _entity(type_slug: str, payload: dict) -> Entity:
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return Entity.objects.get(pk=result.entity_id)


class TestTheReader:
    @pytest.mark.spec("req-tenable-event-time-2")
    def test_an_epoch_string_is_that_instant(self):
        assert from_tenable_epoch(EPOCH) == INSTANT

    @pytest.mark.spec("req-tenable-event-time-2")
    @pytest.mark.parametrize("marker", ["-1", "0", -1, 0])
    def test_the_unset_markers_are_no_time(self, marker):
        assert from_tenable_epoch(marker) is None

    @pytest.mark.spec("req-tenable-event-time-2")
    def test_a_value_that_is_not_a_count_raises(self):
        # Core treats a raise as an unreadable value: a warning, and the write goes on (rule 25).
        with pytest.raises(ValueError):
            from_tenable_epoch("2025-11-22")


class TestTheDeclarations:
    @pytest.mark.spec("req-tenable-event-time-1")
    def test_every_type_declares(self):
        ours = {slug for slug in list_entity_types() if slug.startswith("tenable__")}
        assert ours == set(TIMED) | set(UNTIMED)

    @pytest.mark.spec("req-tenable-event-time-1")
    @pytest.mark.parametrize("type_slug", sorted(TIMED))
    def test_a_timed_type_names_its_field_kind_and_reader(self, type_slug):
        start, end, kind = TIMED[type_slug]
        declaration = get_model_class(type_slug).EVENT_TIME
        if end is None and type_slug == "tenable__tenable_plugin":
            assert declaration == Moment(start, kind, reader=TENABLE_EPOCH)
        else:
            assert isinstance(declaration, Interval)
            assert (declaration.start, declaration.end, declaration.kind) == (start, end, kind)
            assert declaration.reader == TENABLE_EPOCH
            assert declaration.end_reader == (TENABLE_EPOCH if end else None)

    @pytest.mark.spec("req-tenable-event-time-1")
    @pytest.mark.parametrize("type_slug", UNTIMED)
    def test_an_untimed_type_says_so(self, type_slug):
        assert get_model_class(type_slug).EVENT_TIME is NO_EVENT_TIME


@pytest.mark.django_db
class TestOnTheSpine:
    @pytest.mark.spec("req-tenable-event-time-3")
    @pytest.mark.parametrize("type_slug", sorted(TIMED))
    def test_the_start_is_the_epoch_instant_and_the_field_is_unchanged(self, type_slug):
        start, _end, kind = TIMED[type_slug]
        entity = _entity(type_slug, {**_payload(type_slug), start: EPOCH})
        assert entity.event_start == INSTANT
        assert entity.event_precision == "second"
        assert dimension_view(entity).get(TIME_DIMENSION) == kind
        assert getattr(get_model_class(type_slug).objects.get(entity=entity), start) == EPOCH

    @pytest.mark.spec("req-tenable-event-time-4")
    def test_a_finding_stays_open_whatever_its_last_sighting(self):
        entity = _entity("tenable__tenable_finding", {**_result(), "first_seen": EPOCH, "last_seen": LATER})
        assert entity.event_start == INSTANT
        assert entity.event_end is None

    @pytest.mark.spec("req-tenable-event-time-4")
    def test_a_risk_rule_ends_at_its_expiry_and_stays_open_when_it_never_expires(self):
        payload = PAYLOADS["tenable__tenable_accept_risk_rule"][0]
        ending = _entity("tenable__tenable_accept_risk_rule", {**payload, "created_time": EPOCH, "expires": LATER})
        assert (ending.event_start, ending.event_end) == (INSTANT, LATER_INSTANT)
        never = _entity("tenable__tenable_accept_risk_rule", {**payload, "rule_id": "10", "created_time": EPOCH, "expires": "-1"})
        assert (never.event_start, never.event_end) == (INSTANT, None)

    @pytest.mark.spec("req-tenable-event-time-4")
    def test_a_running_scan_result_has_no_end(self):
        payload = PAYLOADS["tenable__tenable_scan_result"][0]
        entity = _entity("tenable__tenable_scan_result", {**payload, "start_time": EPOCH, "finish_time": "0"})
        assert (entity.event_start, entity.event_end) == (INSTANT, None)

    @pytest.mark.spec("req-tenable-event-time-3")
    def test_an_unset_start_leaves_no_event_time(self):
        entity = _entity("tenable__tenable_scan_zone", {**PAYLOADS["tenable__tenable_scan_zone"][0], "created_time": "-1"})
        assert entity.event_start is None
        assert TIME_DIMENSION not in dimension_view(entity)
