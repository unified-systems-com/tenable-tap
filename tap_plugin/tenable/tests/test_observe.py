"""The observation command: read one instance through the allowlist and record shapes, never values (req-tenable-observe-*)."""

import io
import json
import re
import stat
from pathlib import Path

import pytest

from tap_plugin.tenable import observe
from tap_plugin.tenable.tests.fakes import (
    ACCESS,
    ADMIN_ACCESS,
    ADMIN_SECRET,
    SECRET,
    FakeAdapter,
    admin_payload,
    envelope_payload,
    no_sleep,
    ok,
    raw,
    write_envelope,
)
from tap_plugin.tenable.transport import ALLOWLIST

SPEC = Path(observe.__file__).resolve().parents[2] / "specs" / "spec-tenable-v0.md"

# Instance data that must never reach the report: a host, an address, an asset name.
HOST, IP, ASSET = "web01.corp.example", "10.20.30.40", "Crown Jewels"
UNIQ = "repositoryID,ip,dnsName"
FILTERS_MSG = "Invalid filter 'tapProbeUnknownFilter'. valid filters: repositoryIDs, pluginID, port, protocol, severity, familyID, exploitAvailable, cveID, asset, recastRiskStatus, lastSeen, wasVuln"


def finding(plugin="19506", **over):
    base = {
        "pluginID": plugin,
        "port": "443",
        "ip": IP,
        "dnsName": HOST,
        "hostUniqueness": UNIQ,
        "hostUUID": "",
        "repository": {"id": "1"},
        "lastMitigated": "0",
        "vulnUUID": "u",
        "vulnUniqueness": "repositoryID,ip,port,protocol,pluginID",
        "cve": "CVE-2026-0001",
        # A plugin echoing what it was sent: the key must be replaced before any body is saved.
        "pluginText": f"<plugin_output>header accessKey={ACCESS}; secretKey={SECRET}</plugin_output>",
    }
    base.update(over)
    return base


def analysis(sent):
    query = sent.body["query"]
    names = {f["filterName"] for f in query["filters"]}
    if "tapProbeUnknownFilter" in names:
        return raw(403, json.dumps({"error_code": 146, "error_msg": FILTERS_MSG}))
    tool = query["tool"]
    if tool == "vulndetails":
        return ok({"totalRecords": "2", "returnedRecords": 2, "results": [finding(), finding("10863")]})
    if tool == "sumid":
        return ok({"results": [{"pluginID": "10863", "total": "4"}, {"pluginID": "19506", "total": "90"}, {"pluginID": "1", "total": "x"}]})
    if tool == "sumip":
        return ok({"results": [{"ip": IP, "dnsName": HOST, "lastAuthRun": "1", "lastUnauthRun": "2", "osCPE": "cpe:/o:x"}]})
    return ok({"results": [{"name": ASSET}]})


def instance(over=None):
    routes = {
        ("POST", "/rest/analysis"): analysis,
        ("GET", "/rest/status"): [ok({"jobd": "Running"})],
        ("GET", "/rest/currentUser"): [ok({"id": "7", "role": {"id": "3"}, "group": {"id": "2"}, "organization": {"id": "1"}})],
        ("GET", "/rest/currentOrganization"): [ok({"id": "1", "zones": [{"id": "4"}]})],
        ("GET", "/rest/feed"): [ok({"active": {"updateTime": "1"}, "passive": {"updateTime": "1"}})],
        ("GET", "/rest/repository"): [
            ok(
                [
                    {"id": "1", "name": ASSET, "dataFormat": "IPv4", "activeVulnsLifetime": "1", "passiveVulnsLifetime": "1", "complianceVulnsLifetime": "1", "mitigatedVulnsLifetime": "1"},
                    {"id": "3", "name": "Phones", "dataFormat": "mobile"},
                ]
            )
        ],
        ("GET", "/rest/plugin"): [ok([{"id": "19506", "name": "Nessus Scan Information"}])],
        ("GET", "/rest/plugin/19506"): [ok({"id": "19506", "checkType": "remote"})],
        ("GET", "/rest/pluginFamily"): [ok([{"id": "1", "name": "General"}])],
        ("GET", "/rest/scanResult"): [ok({"usable": [{"id": "55", "importStatus": "Finished", "finishTime": "100", "name": ASSET}]})],
        ("GET", "/rest/scanResult/55"): [ok({"id": "55", "progress": {"scanners": [{"id": "9"}]}})],
        ("GET", "/rest/acceptRiskRule"): [ok([])],
        ("GET", "/rest/recastRiskRule"): [ok([])],
        ("GET", "/rest/asset"): [ok({"usable": [{"id": "1", "name": ASSET}]})],
        ("GET", "/rest/scanner"): [ok([{"id": "9", "name": HOST}])],
        ("GET", "/rest/passivescanner"): [ok([])],
        ("GET", "/rest/zone"): [ok([{"id": "4", "name": "DMZ", "ipList": IP}])],
        ("GET", "/rest/organization"): [ok([{"id": "1", "zones": []}])],
    }
    routes.update(over or {})
    return FakeAdapter(routes=routes)


@pytest.fixture
def secrets(tmp_path):
    root = tmp_path / "secrets"
    root.mkdir()
    write_envelope(root, envelope_payload("sc-one"))
    write_envelope(root, admin_payload())
    return root


@pytest.fixture
def home(tmp_path):
    out = tmp_path / "home"
    out.mkdir()
    return out


def observe_run(secrets, home, adapter, *flags):
    stdout = io.StringIO()
    code = observe.main(["--key", "sc-one", *flags], stdout=stdout, out_root=home, secrets=secrets, transport=adapter, sleep=no_sleep())
    assert code == 0
    run_dir = next((home / observe.RECORDINGS_DIRNAME).iterdir())
    return stdout.getvalue(), run_dir


class Refuses:
    """A transport that fails the test if anything is sent."""

    def send(self, *args, **kwargs):
        raise AssertionError("a request was sent")

    def close(self):
        pass


@pytest.mark.spec("req-tenable-observe-1")
def test_every_request_is_an_allowlisted_operation(secrets, home):
    adapter = instance()
    observe_run(secrets, home, adapter)
    patterns = {(op.method, re.compile("^" + op.path.replace("{id}", "[0-9]+") + "$")) for op in ALLOWLIST}
    for sent in adapter.sent:
        assert any(sent.method == m and p.match(sent.path) for m, p in patterns), f"{sent.method} {sent.path}"


@pytest.mark.spec("req-tenable-observe-2")
def test_recordings_are_owner_only_and_never_inside_a_repository(secrets, home, tmp_path):
    _, run_dir = observe_run(secrets, home, instance(), "--record-bodies")
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(run_dir.parent.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in run_dir.iterdir())
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    with pytest.raises(SystemExit, match="git repository"):
        observe.main(["--key", "sc-one"], stdout=io.StringIO(), out_root=repo, secrets=secrets, transport=instance(), sleep=no_sleep())


@pytest.mark.spec("req-tenable-observe-3")
def test_the_report_and_shapes_hold_no_key_body_host_or_asset(secrets, home):
    report, run_dir = observe_run(secrets, home, instance())
    shapes = (run_dir / "shapes.json").read_text()
    assert [f.name for f in run_dir.iterdir()] == ["shapes.json"]
    for text in (report, shapes):
        for value in (ACCESS, SECRET, ADMIN_ACCESS, ADMIN_SECRET, HOST, IP, ASSET, "plugin_output", "Nessus Scan Information"):
            assert value not in text, value
    assert "sc.example" not in report


@pytest.mark.spec("req-tenable-observe-3")
def test_text_from_the_instance_is_stripped_of_control_characters(secrets, home):
    adapter = instance({("GET", "/rest/system"): [ok({"version": "6.4.0\x1b[2J\x07"})]})
    report, _ = observe_run(secrets, home, adapter)
    assert "\x1b" not in report and "\x07" not in report


@pytest.mark.spec("req-tenable-observe-4")
def test_a_step_that_cannot_run_is_not_read_with_its_reason(secrets, home):
    refused = raw(403, json.dumps({"error_code": 403, "error_msg": "forbidden"}))
    adapter = instance({("GET", "/rest/scanResult"): [refused]})
    report, run_dir = observe_run(secrets, home, adapter)
    assert re.search(r"scan_result_list\s+not read: refused", report)
    assert re.search(r"scan_result\s+not read: no finished scan result", report)
    ledger = {e["id"]: e for e in json.loads((run_dir / "shapes.json").read_text())["ledger"]}
    assert ledger["individual-view"]["verdict"] == observe.NOT_REACHED and ledger["individual-view"]["note"]


@pytest.mark.spec("req-tenable-observe-5")
@pytest.mark.parametrize("flags", [["--list"], ["--key", "sc-one", "--dry-run"]])
def test_dry_run_and_list_send_nothing(secrets, home, flags):
    stdout = io.StringIO()
    assert observe.main(flags, stdout=stdout, out_root=home, secrets=secrets, transport=Refuses(), sleep=no_sleep()) == 0
    assert not (home / observe.RECORDINGS_DIRNAME).exists()
    assert "sc.example" not in stdout.getvalue() and "sc-one" in stdout.getvalue()


@pytest.mark.spec("req-tenable-observe-6")
def test_plugins_are_ranked_by_result_count(secrets, home):
    report, _ = observe_run(secrets, home, instance())
    section = report.split("Plugins by result count (top 25)\n", 1)[1].split("\n\n", 1)[0]
    assert [line.split() for line in section.splitlines()] == [["19506", "90"], ["10863", "4"]]


@pytest.mark.spec("req-tenable-observe-7")
def test_bodies_are_saved_only_when_asked_with_the_path_and_a_reminder(secrets, home):
    report, run_dir = observe_run(secrets, home, instance(), "--record-bodies")
    bodies = [f for f in run_dir.iterdir() if f.name != "shapes.json"]
    assert bodies and str(run_dir) in report and "delete them when done" in report


@pytest.mark.spec("req-tenable-observe-8")
def test_an_echoed_key_is_replaced_before_saving_and_counted(secrets, home):
    report, run_dir = observe_run(secrets, home, instance(), "--record-bodies")
    saved = "".join(f.read_text() for f in run_dir.iterdir())
    assert ACCESS not in saved and SECRET not in saved
    assert HOST in saved, "bodies are raw apart from the keys"
    count = int(re.search(r"\((\d+) key replacements\)", report).group(1))
    assert count > 0


@pytest.mark.spec("req-tenable-observe-9")
def test_every_allowlisted_operation_is_reached_by_a_step(secrets, home):
    report, _ = observe_run(secrets, home, instance())
    section = report.split("Operations\n", 1)[1].split("\n\n", 1)[0]
    listed = {line.split()[0]: line.split(None, 1)[1] for line in section.splitlines()}
    assert set(listed) == {op.name for op in ALLOWLIST}
    unreached = {name for name, status in listed.items() if "no step reached it" in status}
    assert not unreached, f"the allowlist has operations no step reads: {unreached}"


@pytest.mark.spec("req-tenable-observe-9")
def test_without_an_admin_envelope_the_admin_read_says_why(tmp_path, home):
    root = tmp_path / "only-main"
    root.mkdir()
    write_envelope(root, envelope_payload("sc-one"))
    report, _ = observe_run(root, home, instance())
    assert re.search(r"organization_list\s+not read: no administrator envelope", report)


@pytest.mark.spec("req-tenable-observe-10")
def test_the_ledger_names_every_assumption_and_each_gets_a_verdict(secrets, home):
    entries = json.loads(observe.LEDGER_PATH.read_text())["assumptions"]
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)) and all(e["acid"].startswith("req-tenable-") and e["claim"] for e in entries)
    if SPEC.exists():
        spec = SPEC.read_text()
        assert all(e["acid"] in spec for e in entries), [e["acid"] for e in entries if e["acid"] not in spec]
    report, run_dir = observe_run(secrets, home, instance())
    ledger = json.loads((run_dir / "shapes.json").read_text())["ledger"]
    assert [e["id"] for e in ledger] == ids
    assert {e["verdict"] for e in ledger} <= {observe.SETTLED, observe.CONTRADICTED, observe.NOT_REACHED}
    verdicts = {e["id"]: e["verdict"] for e in ledger}
    assert verdicts["valid-filter-names"] == observe.SETTLED
    assert verdicts["host-uniqueness"] == observe.SETTLED
    assert verdicts["accepted-default"] == observe.NOT_REACHED
    for entry in ledger:
        assert entry["id"] in report


@pytest.mark.spec("req-tenable-observe-3")
def test_a_key_echoed_into_printed_or_shaped_text_is_replaced(secrets, home):
    """A compromised or careless instance can echo a key into a version, a field value or a field name."""
    # The hostUniqueness value is printed cut to 60 characters; the key straddles the cut.
    straddling = "repositoryID," + "x" * 40 + ACCESS

    def echoing(sent):
        if sent.body["query"]["tool"] == "vulndetails":
            return ok({"totalRecords": "1", "results": [finding(hostUniqueness=straddling)]})
        return analysis(sent)

    adapter = instance(
        {
            ("GET", "/rest/system"): [ok({"version": "6.4.0"}), ok({"version": f"6.4.0 {SECRET}"})],
            ("GET", "/rest/feed"): [ok({"active": {"updateTime": "1"}, "passive": {"updateTime": "1"}, ADMIN_SECRET: {"updateTime": "1"}})],
            ("POST", "/rest/analysis"): echoing,
        }
    )
    report, run_dir = observe_run(secrets, home, adapter)
    shapes = (run_dir / "shapes.json").read_text()
    for text in (report, shapes):
        for key in (ACCESS, SECRET, ADMIN_SECRET):
            assert key not in text and key[:8] not in text, key


@pytest.mark.spec("req-tenable-observe-4")
def test_the_probes_own_reads_are_recorded_like_every_other_step(secrets, home):
    _, run_dir = observe_run(secrets, home, instance(), "--record-bodies")
    responses = json.loads((run_dir / "shapes.json").read_text())["responses"]
    probe_steps = [r["step"] for r in responses.values() if r["step"].startswith("probe ")]
    assert probe_steps == ["probe system", "probe status", "probe current_user", "probe current_organization", "probe feed", "probe repository_list"]
    assert any(f.name.endswith("probe-repository-list.json") for f in run_dir.iterdir())


@pytest.mark.spec("req-tenable-observe-4")
def test_a_refused_probe_read_is_recorded_as_failed_not_absent(secrets, home):
    refused = raw(403, json.dumps({"error_code": 403, "error_msg": "forbidden"}))
    _, run_dir = observe_run(secrets, home, instance({("GET", "/rest/feed"): [refused]}))
    responses = json.loads((run_dir / "shapes.json").read_text())["responses"]
    feed = [r for r in responses.values() if r["step"] == "probe feed"]
    assert feed and feed[0]["status"] == 403 and feed[0]["failed"]
