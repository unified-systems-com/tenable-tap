"""The probe: what the instance is and what this credential sees, read before any data (req-tenable-probe-*)."""

import json

import pytest

from tap_plugin.tenable import compat, probe
from tap_plugin.tenable.tests.fakes import FakeAdapter, credential, no_sleep, ok, raw
from tap_plugin.tenable.transport import SecurityCenterClient

NOW = 1_800_000_000
DAY = 86400

USER = ok({"id": "7", "username": "jane", "email": "jane@corp.example", "role": {"id": "3", "name": "Security Manager"}, "group": {"id": "2", "name": "Ops"}, "organization": {"id": "1", "name": "Corp"}})
ORG = ok({"id": "1", "name": "Corp", "zones": [{"id": "4", "name": "DMZ"}, {"id": "5", "name": "LAN"}]})
REPOS = ok(
    [
        {"id": "1", "name": "IPv4 main", "dataFormat": "IPv4"},
        {"id": "2", "name": "Agents", "dataFormat": "agent"},
        {"id": "3", "name": "Phones", "dataFormat": "mobile"},
        {"id": "4", "name": "Odd", "dataFormat": "ipv9"},
    ]
)
REFUSED = raw(403, json.dumps({"error_code": 403, "error_msg": "forbidden"}))


def feed(active_age_days=1, passive_age_days=1, stale="false"):
    return ok(
        {
            "active": {"updateTime": str(NOW - active_age_days * DAY), "stale": stale, "updateRunning": "false"},
            "passive": {"updateTime": str(NOW - passive_age_days * DAY), "stale": "false", "updateRunning": "false"},
            "sc": {"updateTime": str(NOW - DAY), "stale": "false", "updateRunning": "false"},
        }
    )


def routes(**over):
    base = {
        ("GET", "/rest/status"): [ok({"jobd": "Running"})],
        ("GET", "/rest/currentUser"): [USER],
        ("GET", "/rest/currentOrganization"): [ORG],
        ("GET", "/rest/feed"): [feed()],
        ("GET", "/rest/repository"): [REPOS],
    }
    for name, value in over.items():
        base[("GET", name)] = [value]
    return base


def run(routes_=None, **data):
    adapter = FakeAdapter(routes=routes_ if routes_ is not None else routes())
    cred = credential(**data)
    client = SecurityCenterClient(cred, transport=adapter, sleep=no_sleep())
    try:
        return probe.run(client, cred, now=NOW), adapter
    finally:
        client.close()


@pytest.mark.spec("req-tenable-probe-1")
def test_the_probe_reads_only_its_endpoints_in_order_and_records_its_results():
    found, adapter = run()
    assert [p for p in adapter.paths() if p != "GET /rest/system"] == [
        "GET /rest/status",
        "GET /rest/currentUser",
        "GET /rest/currentOrganization",
        "GET /rest/feed",
        "GET /rest/repository",
    ]
    assert not any("analysis" in p for p in adapter.paths())
    record = found.record()
    assert record["version"] == "6.4.0" and record["verdict"] == compat.DOCUMENTED_ONLY and record["status_read"] is True
    assert [r["id"] for r in record["repositories"]] == ["1", "2", "3", "4"]


@pytest.mark.spec("req-tenable-probe-2")
@pytest.mark.parametrize("path", ["/rest/status", "/rest/currentUser", "/rest/currentOrganization", "/rest/feed"])
def test_a_refused_optional_read_is_null_and_the_run_continues(path):
    found, adapter = run(routes(**{path: REFUSED}))
    assert "GET /rest/repository" in adapter.paths() and len(found.repositories) == 4
    assert found.not_read
    if path == "/rest/currentUser":
        assert found.user_id is found.role_id is found.group_id is None and found.organization_id == "1"
    if path == "/rest/currentOrganization":
        assert found.zone_ids is None
    if path == "/rest/status":
        assert found.status_read is None


@pytest.mark.spec("req-tenable-probe-2")
def test_an_unreadable_system_read_falls_back_to_the_version_read_at_connect():
    first = {"n": 0}

    def system(sent):
        first["n"] += 1
        return ok({"version": "6.4.0"}) if first["n"] == 1 else REFUSED

    r = routes()
    r[("GET", "/rest/system")] = system
    found, _ = run(r)
    assert found.version == "6.4.0" and "system" in found.not_read


@pytest.mark.spec("req-tenable-probe-3")
def test_an_unreadable_repository_list_ends_the_run_before_any_scope():
    with pytest.raises(probe.ProbeError, match="repository list"):
        run(routes(**{"/rest/repository": REFUSED}))


@pytest.mark.spec("req-tenable-probe-3")
@pytest.mark.parametrize("payload", [{"id": "1"}, [{"name": "no id"}], ["x"]])
def test_a_malformed_repository_list_ends_the_run(payload):
    with pytest.raises(probe.ProbeError):
        run(routes(**{"/rest/repository": ok(payload)}))


@pytest.mark.spec("req-tenable-probe-4")
def test_only_ids_are_recorded_never_a_name_or_contact_detail():
    found, _ = run()
    assert (found.user_id, found.role_id, found.group_id, found.organization_id, found.zone_ids) == ("7", "3", "2", "1", ["4", "5"])
    text = json.dumps(found.record())
    for detail in ("jane", "corp.example", "Security Manager", "Ops", "DMZ"):
        assert detail not in text


@pytest.mark.spec("req-tenable-probe-4")
def test_the_credential_view_changes_when_what_it_sees_changes():
    before, _ = run()
    fewer = ok([{"id": "1", "name": "IPv4 main", "dataFormat": "IPv4"}])
    after, _ = run(routes(**{"/rest/repository": fewer}))
    assert before.credential_view() != after.credential_view()
    assert before.credential_view() == run()[0].credential_view()


@pytest.mark.spec("req-tenable-probe-5")
class TestFeed:
    def test_a_fresh_feed_records_its_times_and_no_warning(self):
        found, _ = run()
        assert found.feed_stale is False and "FEED_STALE" not in found.warnings
        assert found.feed["active"]["update_time"] == str(NOW - DAY)

    def test_a_feed_older_than_the_threshold_is_stale(self):
        found, _ = run(routes(**{"/rest/feed": feed(active_age_days=8)}))
        assert found.feed_stale is True and "FEED_STALE" in found.warnings

    def test_the_threshold_comes_from_the_envelope(self):
        found, _ = run(routes(**{"/rest/feed": feed(active_age_days=8)}), feed_stale_days=10)
        assert found.feed_stale is False

    def test_security_centers_own_stale_flag_counts(self):
        found, _ = run(routes(**{"/rest/feed": feed(stale="true")}))
        assert found.feed_stale is True

    def test_a_refused_feed_is_null_never_fresh(self):
        found, _ = run(routes(**{"/rest/feed": REFUSED}))
        assert found.feed is None and found.feed_stale is None and "FEED_STALE" not in found.warnings


@pytest.mark.spec("req-tenable-probe-6")
def test_each_repository_format_gets_its_treatment():
    found, _ = run()
    treatments = {r.id: (r.treatment, r.reason is not None) for r in found.repositories}
    assert treatments == {"1": ("read", False), "2": ("read", False), "3": ("not_read", True), "4": ("unknown_format", True)}


@pytest.mark.spec("req-tenable-upstream-versions-4")
def test_a_version_below_the_floor_ends_the_probe_and_an_outside_one_warns():
    r = routes()
    r[("GET", "/rest/system")] = [ok({"version": "6.12.0"})]
    found, _ = run(r)
    assert found.verdict == compat.OUTSIDE and "VERSION_OUTSIDE" in found.warnings and found.repositories
    r = routes()
    r[("GET", "/rest/system")] = [ok({"version": "6.4.0"}), ok({"version": "5.12.0"})]
    with pytest.raises(probe.ProbeError, match="below the 5.13 floor"):
        run(r)


@pytest.mark.spec("req-tenable-probe-5")
@pytest.mark.parametrize(
    "payload",
    [
        {"active": {}, "passive": {}},
        {"active": {"updateTime": "soon"}, "passive": {"updateTime": str(NOW - DAY)}},
        {"active": {"updateTime": str(NOW - DAY)}},
        {"sc": {"updateTime": str(NOW - DAY)}},
    ],
)
def test_a_feed_without_readable_update_times_is_unobserved_never_fresh(payload):
    found, _ = run(routes(**{"/rest/feed": ok(payload)}))
    assert found.feed_stale is None and "FEED_STALE" not in found.warnings
