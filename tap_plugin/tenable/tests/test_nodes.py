"""The Tenable node types through the service layer (specs/spec-tenable-v0.md, Model catalog).

Creation, display, the area dimension, required fields, the declared natural keys (found again by
the generated search), keys checked against the columns they rest on, null as unobserved, and
the free-text ceiling. The payloads are spec-derived from Tenable's documented API, not recorded
from an instance.
"""

import pytest
import tap_plugin.tenable.models  # noqa: F401 — trigger model registration

from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node
from tap_plugin.tenable.identity import FREE_TEXT_CEILING_BYTES, assertion_key, canonical_root, host_key

INSTANCE = canonical_root("https://sc.example")
IPV4_UNIQUENESS = "repositoryID,ip,dnsName"
HOST_COLUMNS = {"repository_id": "1", "ip": "10.0.0.5", "dns_name": "web01.corp"}
HOST_KEY = host_key(IPV4_UNIQUENESS, HOST_COLUMNS)


def _result(plugin_id: str = "19506", port: str = "0", protocol: str = "TCP") -> dict:
    return {
        "instance_key": INSTANCE,
        "assertion_key": assertion_key("1", HOST_KEY, plugin_id, port, protocol),
        "host_key": HOST_KEY,
        "host_uniqueness": IPV4_UNIQUENESS,
        "plugin_id": plugin_id,
        "port": port,
        "protocol": protocol,
        **HOST_COLUMNS,
    }


#: One valid minimal payload per type, with its expected area and display name.
PAYLOADS = {
    "tenable__tenable_security_center": ({"instance_key": INSTANCE, "network_name": "corp"}, "run", INSTANCE),
    "tenable__tenable_scan_run": ({"instance_key": INSTANCE, "run_id": "r1"}, "run", "run r1"),
    "tenable__tenable_scanner": (
        {"instance_key": INSTANCE, "scanner_kind": "active", "scanner_id": "3", "name": "dmz-nessus"},
        "run",
        "dmz-nessus",
    ),
    "tenable__tenable_scan_zone": ({"instance_key": INSTANCE, "zone_id": "2", "name": "DMZ"}, "run", "DMZ"),
    "tenable__tenable_plugin_family": ({"instance_key": INSTANCE, "family_id": "5", "name": "General"}, "plugin", "General"),
    "tenable__tenable_plugin": ({"instance_key": INSTANCE, "plugin_id": "19506", "name": "Nessus Scan Information"}, "plugin", "Nessus Scan Information"),
    "tenable__tenable_repository": ({"instance_key": INSTANCE, "repository_id": "1", "name": "Corp IPv4"}, "run", "Corp IPv4"),
    "tenable__tenable_scan_result": ({"instance_key": INSTANCE, "scan_result_id": "77", "name": "Weekly"}, "run", "Weekly"),
    "tenable__tenable_observed_host": (
        {"instance_key": INSTANCE, "host_key": HOST_KEY, "host_uniqueness": IPV4_UNIQUENESS, **HOST_COLUMNS},
        "observation",
        "web01.corp",
    ),
    "tenable__tenable_observed_program": (
        {"instance_key": INSTANCE, "host_key": HOST_KEY, "transport": "TCP", "port_number": "443", "service_name": "www"},
        "observation",
        "www on 443/TCP",
    ),
    "tenable__tenable_finding": (_result(), "finding", "19506 on web01.corp:0/TCP"),
    "tenable__tenable_compliance_result": (_result("1000123"), "finding", "1000123 on web01.corp:0/TCP"),
    "tenable__tenable_accept_risk_rule": ({"instance_key": INSTANCE, "rule_id": "9", "plugin_id": "19506"}, "risk", "rule 9 on plugin 19506"),
    "tenable__tenable_recast_risk_rule": ({"instance_key": INSTANCE, "rule_id": "9", "plugin_id": "19506"}, "risk", "rule 9 on plugin 19506"),
    "tenable__tenable_asset_list": ({"instance_key": INSTANCE, "asset_id": "4", "name": "Web servers"}, "risk", "Web servers"),
}


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


@pytest.mark.django_db
@pytest.mark.parametrize("type_slug", sorted(PAYLOADS))
class TestEveryType:
    def test_create_display_and_area(self, type_slug):
        payload, area, name = PAYLOADS[type_slug]
        node = _create(type_slug, payload)
        node.entity.refresh_from_db()
        assert node.entity.name == name
        assert node.entity.dimensions.get("tenable.area") == area

    def test_found_again_by_its_natural_key(self, type_slug):
        payload, _, _ = PAYLOADS[type_slug]
        node = _create(type_slug, payload)
        model = get_model_class(type_slug)
        assert model.find_existing(**{k: payload[k] for k in model.NATURAL_KEY}).pk == node.pk

    def test_every_key_part_is_required(self, type_slug):
        payload, _, _ = PAYLOADS[type_slug]
        for part in get_model_class(type_slug).NATURAL_KEY:
            assert not create_node(type_slug, {k: v for k, v in payload.items() if k != part}).success, part

    def test_icon_is_shipped(self, type_slug):
        from pathlib import Path

        icon = get_model_class(type_slug).ENTITY_ICON
        assert (Path(__file__).resolve().parents[1] / "static" / "tenable" / "icons" / f"{icon}.svg").is_file()


@pytest.mark.django_db
class TestSecurityCenter:
    @pytest.mark.spec("req-tenable-connection-5")
    def test_a_non_canonical_key_is_refused(self):
        for key in ("https://SC.example:443", "https://sc.example", "https://sc.example:443/", "https://u:p@sc.example:443"):
            assert not create_node("tenable__tenable_security_center", {"instance_key": key, "network_name": "corp"}).success, key

    @pytest.mark.spec("req-tenable-connection-10")
    def test_network_is_required(self):
        assert not create_node("tenable__tenable_security_center", {"instance_key": INSTANCE}).success
        assert not create_node("tenable__tenable_security_center", {"instance_key": INSTANCE, "network_name": ""}).success

    @pytest.mark.spec("req-tenable-connection-1")
    def test_no_connection_setting_is_a_field(self):
        fields = {f.name for f in get_model_class("tenable__tenable_security_center")._meta.get_fields()}
        assert not fields & {"access_key", "secret_key", "ssl_verify", "ca_bundle", "scope", "base_url"}

    def test_unread_version_is_null_not_empty(self):
        assert _create("tenable__tenable_security_center", PAYLOADS["tenable__tenable_security_center"][0]).reported_version is None


@pytest.mark.django_db
class TestScanRun:
    @pytest.mark.spec("req-tenable-scanner-run-4")
    def test_only_tabled_warnings_and_counters(self):
        base = {"instance_key": INSTANCE, "run_id": "r2"}
        assert create_node("tenable__tenable_scan_run", {**base, "warnings": [{"code": "FEED_STALE"}], "counters": {"parsed": 3}}).success
        assert not create_node("tenable__tenable_scan_run", {**base, "run_id": "r3", "warnings": [{"code": "MADE_UP"}]}).success
        assert not create_node("tenable__tenable_scan_run", {**base, "run_id": "r4", "counters": {"made_up": 1}}).success

    def test_credential_identity_holds_no_secret(self):
        payload = {"instance_key": INSTANCE, "run_id": "r5", "credential": {"user_id": "7", "password": "x"}}
        assert not create_node("tenable__tenable_scan_run", payload).success


@pytest.mark.django_db
class TestScanner:
    @pytest.mark.spec("req-tenable-scanners-zones-2")
    def test_kind_is_in_the_key(self):
        model = get_model_class("tenable__tenable_scanner")
        active = _create("tenable__tenable_scanner", {"instance_key": INSTANCE, "scanner_kind": "active", "scanner_id": "1"})
        passive = _create("tenable__tenable_scanner", {"instance_key": INSTANCE, "scanner_kind": "passive", "scanner_id": "1"})
        assert active.pk != passive.pk
        assert model.find_existing(instance_key=INSTANCE, scanner_kind="passive", scanner_id="1").pk == passive.pk

    @pytest.mark.spec("req-tenable-scanners-zones-3")
    def test_no_secret_fields(self):
        fields = {f.name for f in get_model_class("tenable__tenable_scanner")._meta.get_fields()}
        assert not fields & {"username", "password", "cert", "access_key", "secret_key"}


@pytest.mark.django_db
class TestResultKeys:
    @pytest.mark.parametrize("type_slug", ["tenable__tenable_finding", "tenable__tenable_compliance_result"])
    @pytest.mark.spec("req-tenable-findings-2")
    def test_a_key_that_disagrees_with_its_columns_is_refused(self, type_slug):
        assert not create_node(type_slug, {**_result(), "ip": "10.0.0.6"}).success
        assert not create_node(type_slug, {**_result(), "port": "443"}).success
        assert not create_node(type_slug, {**_result(), "host_uniqueness": "repositoryID,hostUUID"}).success

    @pytest.mark.spec("req-tenable-findings-11")
    def test_universal_record_keys_on_host_uuid(self):
        columns = {"repository_id": "2", "host_uuid": "h-1"}
        hk = host_key("repositoryID,hostUUID", columns)
        payload = {
            "instance_key": INSTANCE,
            "assertion_key": assertion_key("2", hk, "19506", "0", "TCP"),
            "host_key": hk,
            "host_uniqueness": "repositoryID,hostUUID",
            "plugin_id": "19506",
            "port": "0",
            "protocol": "TCP",
            **columns,
        }
        assert create_node("tenable__tenable_finding", payload).success

    def test_observed_host_key_checked_against_columns(self):
        payload, _, _ = PAYLOADS["tenable__tenable_observed_host"]
        assert not create_node("tenable__tenable_observed_host", {**payload, "dns_name": "other.corp"}).success

    @pytest.mark.spec("req-tenable-plugin-5")
    def test_no_cve_or_cpe_on_a_result(self):
        for type_slug in ("tenable__tenable_finding", "tenable__tenable_compliance_result"):
            fields = {f.name for f in get_model_class(type_slug)._meta.get_fields()}
            assert not fields & {"cve", "cpe"}, type_slug

    def test_state_is_null_until_observed_and_enumerated(self):
        assert _create("tenable__tenable_finding", _result()).state is None
        assert not create_node("tenable__tenable_finding", {**_result("2"), "state": "fixed"}).success
        assert not create_node("tenable__tenable_finding", {**_result("3"), "resolution_source": "guessed"}).success


@pytest.mark.django_db
@pytest.mark.spec("req-tenable-findings-10")
class TestFreeTextCeiling:
    def test_large_output_below_the_ceiling_reads_back_unchanged(self):
        text = "x" * 300_000 + "é" * 10
        node = _create("tenable__tenable_finding", {**_result(), "plugin_text": text})
        node.refresh_from_db()
        assert node.plugin_text == text

    def test_output_above_the_ceiling_is_refused(self):
        assert not create_node("tenable__tenable_finding", {**_result(), "plugin_text": "x" * (FREE_TEXT_CEILING_BYTES + 1)}).success

    @pytest.mark.spec("req-tenable-findings-13")
    def test_the_same_ceiling_on_audit_columns_and_rule_comments(self):
        big = "x" * (FREE_TEXT_CEILING_BYTES + 1)
        assert not create_node("tenable__tenable_compliance_result", {**_result("1000123"), "cm_actual_value": big}).success
        assert not create_node("tenable__tenable_accept_risk_rule", {"instance_key": INSTANCE, "rule_id": "1", "comments": big}).success


@pytest.mark.django_db
@pytest.mark.spec("req-tenable-states-7")
class TestStatements:
    @pytest.mark.parametrize(
        "type_slug",
        [
            "tenable__tenable_accept_risk_rule",
            "tenable__tenable_recast_risk_rule",
            "tenable__tenable_repository",
            "tenable__tenable_scanner",
            "tenable__tenable_scan_zone",
            "tenable__tenable_asset_list",
        ],
    )
    def test_current_or_withdrawn_only(self, type_slug):
        payload, _, _ = PAYLOADS[type_slug]
        assert _create(type_slug, {**payload, "state": "withdrawn"}).state == "withdrawn"

    def test_any_other_state_is_refused(self):
        payload, _, _ = PAYLOADS["tenable__tenable_accept_risk_rule"]
        assert not create_node("tenable__tenable_accept_risk_rule", {**payload, "state": "expired"}).success

    def test_observations_carry_no_state(self):
        for type_slug in ("tenable__tenable_observed_host", "tenable__tenable_observed_program"):
            fields = {f.name for f in get_model_class(type_slug)._meta.get_fields()}
            assert "state" not in fields, type_slug
