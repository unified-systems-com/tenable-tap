"""The guarded transport: the allowlist, the root, the pins, bounded retries and bounded input (req-tenable-transport-*)."""

import json
import logging
import re
import tomllib
from pathlib import Path

import pytest
import requests

from tap_plugin.tenable import analysis
from tap_plugin.tenable.tests.fakes import ACCESS, SECRET, FakeAdapter, credential, no_sleep, ok, raw
from tap_plugin.tenable.transport import (
    ALLOWLIST,
    FORBIDDEN_FIELDS,
    OPERATIONS,
    GuardedSession,
    ReadFailed,
    Refused,
    SecurityCenterClient,
    parse_json,
)

ROOT = "https://sc.example:443"


def client(adapter=None, **kwargs):
    adapter = adapter or FakeAdapter()
    return SecurityCenterClient(credential(**kwargs.pop("data", {})), transport=adapter, sleep=kwargs.pop("sleep", no_sleep()), **kwargs), adapter


def session(role="main", verify=True):
    s = GuardedSession(ROOT, verify, role)
    s.mount("https://", FakeAdapter())
    s.mount("http://", FakeAdapter())
    return s


def good_body(**over):
    body = analysis.body("vulndetails", "cumulative", start=0, end=10)
    body.update(over)
    return body


@pytest.mark.spec("req-tenable-transport-1")
class TestAllowlist:
    @pytest.mark.parametrize(
        "method, path",
        [("POST", "/rest/token"), ("DELETE", "/rest/token"), ("PATCH", "/rest/scan/1"), ("PUT", "/rest/repository"), ("POST", "/rest/scan"), ("GET", "/rest/credential"), ("GET", "/rest/user"), ("POST", "/rest/scanResult/1/download"), ("DELETE", "/rest/scanResult/1")],
    )
    def test_a_pair_off_the_list_is_refused_before_anything_is_sent(self, method, path):
        s = session()
        with pytest.raises(Refused):
            s.request(method, ROOT + path)
        assert s.get_adapter(ROOT).sent == []

    def test_an_aliased_lower_case_method_is_refused(self):
        s = session()
        request = requests.Request("get", ROOT + "/rest/status").prepare()
        request.method = "get"
        with pytest.raises(Refused):
            s.send(request)

    def test_a_request_from_another_module_through_the_session_is_still_guarded(self):
        sc, adapter = client()
        sc.connect()
        with pytest.raises(Refused):
            sc._session.post(ROOT + "/rest/token", json={"username": "x", "password": "y"})
        with pytest.raises(Refused):
            sc._sc.delete("token")
        assert adapter.paths() == ["GET /rest/system"]

    def test_pytenable_logout_sends_nothing(self):
        sc, adapter = client()
        sc.connect()
        try:
            sc._sc.logout()
        except Refused:
            pass
        assert adapter.paths() == ["GET /rest/system"]


@pytest.mark.spec("req-tenable-nongoals-1")
def test_no_allowlist_entry_sends_a_mutating_operation():
    for op in ALLOWLIST:
        assert op.method in ("GET", "POST")
        if op.method == "POST":
            assert op.name == "analysis" and op.path == "/rest/analysis"


@pytest.mark.spec("req-tenable-transport-2")
class TestAnalysisIsQueryOnly:
    @pytest.mark.parametrize("change", [{"type": "event"}, {"type": "mobile"}, {"sourceType": "lce"}, {"query": {"type": "event", "tool": "x", "filters": [analysis.ACCEPT_ALL]}}])
    def test_a_body_that_is_not_a_vuln_query_is_refused(self, change):
        s = session()
        with pytest.raises(Refused):
            s.post(ROOT + "/rest/analysis", json=good_body(**change))
        assert s.get_adapter(ROOT).sent == []

    def test_the_download_path_is_unreachable(self):
        with pytest.raises(Refused):
            session().post(ROOT + "/rest/analysis/download", json=good_body())

    def test_a_vuln_query_is_sent(self):
        s = session()
        s.post(ROOT + "/rest/analysis", json=good_body())
        assert [x.path for x in s.get_adapter(ROOT).sent] == ["/rest/analysis"]


@pytest.mark.spec("req-tenable-transport-3")
class TestBoundToTheRoot:
    @pytest.mark.parametrize("url", ["https://other.example/rest/status", "https://sc.example:8443/rest/status", "http://sc.example/rest/status", "https://sc.example/status", "https://sc.example/rest/%2e%2e/token", "ftp://sc.example/rest/status"])
    def test_anything_outside_the_root_is_refused(self, url):
        with pytest.raises(Refused):
            session().get(url)

    def test_the_default_port_spelled_out_or_not_is_the_same_root(self):
        s = session()
        s.get("https://sc.example/rest/status")
        s.get("https://SC.example:443/rest/status")
        assert len(s.get_adapter(ROOT).sent) == 2

    def test_a_path_root_is_kept(self):
        s = GuardedSession("https://sc.example:443/sc", True, "main")
        s.mount("https://", FakeAdapter())
        with pytest.raises(Refused):
            s.get("https://sc.example/rest/status")
        s.get("https://sc.example/sc/rest/status")

    def test_a_redirect_is_refused_and_not_followed(self):
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(302, "", {"location": "https://evil.example/"})]})
        sc, _ = client(adapter)
        with pytest.raises(ReadFailed, match="redirect"):
            sc.get("status")
        assert adapter.paths() == ["GET /rest/system", "GET /rest/status"]


@pytest.mark.spec("req-tenable-transport-4")
class TestBoundedRetries:
    def test_retry_after_is_honoured_up_to_a_cap(self):
        sleep = no_sleep()
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(429, "{}", {"retry-after": "5"}), raw(503, "{}", {"retry-after": "99999"}), ok({})]})
        sc, _ = client(adapter, sleep=sleep)
        sc.get("status")
        assert sleep.slept == [5.0, 60.0]

    def test_exhaustion_is_a_failure_never_an_empty_result(self):
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(500, "{}")]})
        sc, _ = client(adapter)
        with pytest.raises(ReadFailed) as raised:
            sc.get("status")
        assert raised.value.status == 500 and adapter.paths().count("GET /rest/status") == 3

    def test_connection_errors_are_retried_by_the_plugin_not_pytenable(self):
        adapter = FakeAdapter(raise_on={("GET", "/rest/status"): [requests.ConnectionError("down"), requests.Timeout("slow")]}, routes={("GET", "/rest/status"): [ok({"x": 1})]})
        sc, _ = client(adapter)
        assert sc.get("status").response == {"x": 1}

    def test_the_total_budget_stops_retries(self):
        clock = iter(range(0, 10_000, 200))
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(503, "{}")]})
        sc, _ = client(adapter, clock=lambda: next(clock), budget=300)
        with pytest.raises(ReadFailed, match="budget|failed"):
            sc.get("status")
        assert adapter.paths().count("GET /rest/status") < 3

    def test_a_403_is_a_refusal_and_is_not_retried(self):
        adapter = FakeAdapter(routes={("GET", "/rest/feed"): [raw(403, json.dumps({"error_code": 12, "error_msg": "no"}))]})
        sc, _ = client(adapter)
        with pytest.raises(ReadFailed) as raised:
            sc.get("feed")
        assert raised.value.refused and adapter.paths().count("GET /rest/feed") == 1

    def test_invalid_parameters_are_not_a_refusal(self):
        adapter = FakeAdapter(routes={("POST", "/rest/analysis"): [raw(403, json.dumps({"error_code": 146, "error_msg": "The filter 'x' is invalid (valid filters: port, pluginID)."}))]})
        sc, _ = client(adapter)
        with pytest.raises(ReadFailed) as raised:
            sc.analysis(good_body())
        assert not raised.value.refused and "valid filters" in raised.value.error_msg
        assert "valid filters" not in str(raised.value)

    def test_an_error_code_in_a_200_is_a_failure(self):
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(200, json.dumps({"error_code": 7, "error_msg": "x", "response": {}}))]})
        sc, _ = client(adapter)
        with pytest.raises(ReadFailed) as raised:
            sc.get("status")
        assert raised.value.error_code == 7


@pytest.mark.spec("req-tenable-transport-5")
@pytest.mark.spec("req-tenable-fips-2")
def test_pytenable_is_pinned_exactly_with_no_extra():
    pyproject = Path(__file__).resolve().parents[3] / "pyproject.toml"
    deps = tomllib.loads(pyproject.read_text())["project"]["dependencies"]
    pins = [d for d in deps if d.lower().startswith("pytenable")]
    assert pins == ["pytenable==26.10.1"]
    assert not any("[" in d for d in deps)


@pytest.mark.spec("req-tenable-transport-6")
class TestVerificationCannotBeOverridden:
    @pytest.mark.parametrize("override", [{"verify": False}, {"verify": "/tmp/evil.pem"}, {"cert": ("/a", "/b")}, {"proxies": {"https": "http://proxy"}}])
    def test_a_per_request_override_is_refused(self, override):
        with pytest.raises(Refused):
            session().get(ROOT + "/rest/status", **override)

    def test_pytenable_receives_the_explicit_setting(self):
        for data, expected in (({}, True), ({"ssl_verify": False}, False), ({"ca_bundle": "/etc/ca.pem"}, "/etc/ca.pem")):
            sc, _ = client(data=data)
            sc.connect()
            assert sc._sc._ssl_verify == expected and sc._session.verify == expected

    def test_the_environment_is_ignored(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/tmp/evil.pem")
        s = session()
        s.get(ROOT + "/rest/status")
        assert len(s.get_adapter(ROOT).sent) == 1


@pytest.mark.spec("req-tenable-transport-7")
class TestNoImplicitFilters:
    def test_wasvuln_only_from_6_2(self):
        def names(version):
            return [f["filterName"] for f in analysis.body("vulndetails", "cumulative", start=0, end=1, version=version)["query"]["filters"]]

        assert names("6.1.9") == ["acceptRiskStatus"]
        assert names(None) == ["acceptRiskStatus"]
        assert names("6.2.0") == ["acceptRiskStatus", "wasVuln"]
        individual = analysis.body("vulndetails", "individual", start=0, end=1, version="6.4.0", scan_result_id="7")
        assert [f["filterName"] for f in individual["query"]["filters"]] == ["acceptRiskStatus"]

    def test_the_body_sent_is_the_body_built(self):
        adapter = FakeAdapter(routes={("POST", "/rest/analysis"): [ok({"results": [], "totalRecords": "0", "returnedRecords": 0})]})
        sc, _ = client(adapter)
        body = analysis.body("vulndetails", "cumulative", start=0, end=10, filters=[analysis.flt("repositoryIDs", "1")], version="6.1.0")
        sc.analysis(body)
        assert adapter.sent[-1].body == body


@pytest.mark.spec("req-tenable-transport-8")
class TestFieldsPinned:
    def test_no_pinned_list_names_a_secret_field(self):
        for op in ALLOWLIST:
            if op.fields is not None:
                assert not set(op.fields.split(",")) & FORBIDDEN_FIELDS, op.name

    @pytest.mark.parametrize("query", ["", "fields=id", "fields=id,name,password", "fields=" + OPERATIONS["scanner_list"].fields + ",username"])
    def test_a_get_without_the_exact_fields_is_refused(self, query):
        with pytest.raises(Refused):
            session().get(ROOT + "/rest/scanner" + ("?" + query if query else ""))

    def test_extra_or_repeated_parameters_are_refused(self):
        fields = OPERATIONS["scanner_list"].fields
        for query in (f"fields={fields}&expand=1", f"fields={fields}&fields={fields}"):
            with pytest.raises(Refused):
                session().get(f"{ROOT}/rest/scanner?{query}")

    def test_the_scan_result_list_is_read_on_finish_time(self):
        sc, adapter = client(FakeAdapter(routes={("GET", "/rest/scanResult"): [ok({"usable": []})]}))
        sc.get("scan_result_list", params={"startTime": "1", "endTime": "2"})
        assert adapter.sent[-1].params["timeCompareField"] == "finishTime"
        with pytest.raises(Refused):
            session().get(f"{ROOT}/rest/scanResult", params={"fields": OPERATIONS["scan_result_list"].fields, "timeCompareField": "createdTime"})

    def test_the_client_sends_the_pin(self):
        sc, adapter = client(FakeAdapter(routes={("GET", "/rest/scanner"): [ok([])]}))
        sc.get("scanner_list")
        assert adapter.sent[-1].params == {"fields": OPERATIONS["scanner_list"].fields}

    def test_the_admin_client_reads_inventory_only(self):
        from tap.runtime_secrets import parse_secret_envelope

        from tap_plugin.tenable.credential import admin_from_envelope
        from tap_plugin.tenable.tests.fakes import admin_payload

        admin = admin_from_envelope(parse_secret_envelope(admin_payload(), Path("/nonexistent/a.secret.json")))
        adapter = FakeAdapter(routes={("GET", "/rest/scanner"): [ok([])]})
        sc = SecurityCenterClient(credential().with_admin(admin), role="admin", transport=adapter, sleep=no_sleep())
        sc.get("scanner_list")
        for name in ("repository_list", "current_user", "plugin"):
            with pytest.raises(Refused):
                sc.get(name, path_id="1" if name == "plugin" else None)
        with pytest.raises(Refused, match="admin"):
            sc.analysis(good_body())
        # Its only system read is pyTenable's version check at construction, which carries no key.
        assert [("X-APIKey" in s.headers) for s in adapter.sent if s.path == "/rest/system"] == [False]
        with pytest.raises(Refused, match="admin"):
            sc.get("system")


@pytest.mark.spec("req-tenable-transport-9")
def test_every_analysis_body_carries_accept_risk_status_all():
    without = good_body()
    without["query"]["filters"] = []
    with pytest.raises(Refused):
        session().post(ROOT + "/rest/analysis", json=without)
    built = analysis.body("vulndetails", "patched", start=0, end=1, filters=[analysis.flt("acceptRiskStatus", "accepted")])
    assert built["query"]["filters"] == [analysis.ACCEPT_ALL]


@pytest.mark.spec("req-tenable-transport-10")
class TestBoundedInput:
    def test_a_response_over_the_cap_is_refused(self):
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(200, b'{"response": "' + b"x" * 2048 + b'"}')]})
        sc, _ = client(adapter, max_bytes=1024)
        with pytest.raises(ReadFailed, match="cap"):
            sc.get("status")

    def test_a_declared_length_over_the_cap_is_refused_before_reading(self):
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(200, b"{}", {"content-length": str(10**12)})]})
        sc, _ = client(adapter)
        with pytest.raises(ReadFailed, match="cap"):
            sc.get("status")

    @pytest.mark.parametrize("body", [b'{"response": NaN}', b'{"response": Infinity}', b'{"response": -Infinity}', b"[" * 70 + b"]" * 70])
    def test_constants_and_deep_nesting_are_refused(self, body):
        with pytest.raises(ValueError):
            parse_json(body)

    def test_a_refused_body_is_a_failed_read_never_a_partial_result(self):
        adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(200, b'{"response": {"a": NaN}}')]})
        sc, _ = client(adapter)
        with pytest.raises(ReadFailed, match="bounded JSON|envelope"):
            sc.get("status")

    def test_a_read_past_its_deadline_is_a_failure(self):
        now = [0.0]

        def slow(_sent):
            now[0] += 10_000  # the body is still arriving long after the budget
            return ok({})

        adapter = FakeAdapter(routes={("GET", "/rest/status"): slow})
        sc, _ = client(adapter, clock=lambda: now[0], budget=300)
        sc.connect()
        with pytest.raises(ReadFailed, match="deadline"):
            sc.get("status")


@pytest.mark.spec("req-tenable-connection-2")
def test_keys_never_reach_an_error_a_log_or_a_repr(caplog):
    caplog.set_level(logging.DEBUG)
    adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(500, json.dumps({"error_code": 1, "error_msg": f"echo {ACCESS} {SECRET}"}))]}, raise_on={("GET", "/rest/feed"): [requests.ConnectionError(f"accessKey={ACCESS}")] * 3})
    sc, _ = client(adapter)
    messages = []
    for name in ("status", "feed"):
        with pytest.raises(ReadFailed) as raised:
            sc.get(name)
        messages += [str(raised.value), repr(raised.value), raised.value.error_msg or ""]
    text = " ".join(messages) + caplog.text + repr(sc) + repr(sc._session)
    assert ACCESS not in text and SECRET not in text
    assert not re.search(r"secretKey=\w", text)


@pytest.mark.spec("req-tenable-connection-2")
def test_a_key_straddling_the_error_message_limit_leaves_no_fragment():
    from tap_plugin.tenable.transport import MAX_ERROR_MSG

    message = "x" * (MAX_ERROR_MSG - 5) + SECRET
    adapter = FakeAdapter(routes={("GET", "/rest/status"): [raw(500, json.dumps({"error_code": 1, "error_msg": message}))]})
    sc, _ = client(adapter)
    with pytest.raises(ReadFailed) as raised:
        sc.get("status")
    kept = raised.value.error_msg or ""
    assert len(kept) <= MAX_ERROR_MSG and SECRET[:5] not in kept


@pytest.mark.spec("req-tenable-transport-10")
@pytest.mark.parametrize("body", ['{"version": "6.4.0", "extra": NaN}', '{"version": "6.4.0", "x": ' + "[" * 80 + "]" * 80 + "}"])
def test_the_system_read_at_connect_is_bounded_before_pytenable_parses_it(body):
    adapter = FakeAdapter(routes={("GET", "/rest/system"): [raw(200, body)]})
    sc, _ = client(adapter)
    with pytest.raises(ReadFailed, match="UnboundedResponse"):
        sc.connect()
