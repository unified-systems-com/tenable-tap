"""The credential envelopes: validation, instance identity, pairing and discovery (req-tenable-connection-*)."""

import json
from pathlib import Path

import pytest
from tap.runtime_secrets import SecretEnvelope

from tap_plugin.tenable import credential as cred
from tap_plugin.tenable.tests.fakes import ACCESS, ADMIN_ACCESS, ADMIN_SECRET, SECRET, admin_payload, envelope_payload, write_envelope

EXAMPLES = Path(cred.__file__).resolve().parent / "schemas" / "examples"


def envelope(payload=None, **data):
    payload = payload or envelope_payload(**data)
    return SecretEnvelope(payload["scope"], payload["key"], payload["kind"], "test", payload["data"], {}, Path("/nonexistent"))


@pytest.mark.spec("req-tenable-connection-7")
class TestStrictSchema:
    def test_a_valid_envelope_loads(self):
        c = cred.credential_from_envelope(envelope())
        assert c.instance_key == "https://sc.example:443" and c.network_name == "corp"
        assert c.scan_result_window_days == 30 and c.feed_stale_days == 7 and c.scope == {}

    def test_templates_validate_against_their_schemas(self):
        for path in sorted(EXAMPLES.glob("*.secret.example.json")):
            payload = json.loads(path.read_text())
            env = envelope(payload)
            if payload["kind"] == cred.ADMIN_KIND:
                cred.admin_from_envelope(env)
            else:
                cred.credential_from_envelope(env)

    @pytest.mark.parametrize(
        "change",
        [
            {"extra": "x"},
            {"access_key": None},
            {"secret_key": "has space"},
            {"access_key": "semi;colon=injection"},
            {"ca_bundle": "relative/path.pem"},
            {"scope": {"query_id": "1"}},
            {"scope": {"min_severity": 5}},
            {"scope": {"repository_ids": ["1", "1"]}},
            {"scope": {"risk_status": "accepted"}},
        ],
    )
    def test_invalid_data_is_refused_naming_the_envelope_never_a_value(self, change):
        with pytest.raises(cred.CredentialError) as raised:
            cred.credential_from_envelope(envelope(**change))
        message = str(raised.value)
        assert message.startswith("tenable:sc-one: ")
        assert ACCESS not in message and SECRET not in message

    def test_every_schema_field_is_described(self):
        for path in (cred.SCHEMA_PATH, cred.ADMIN_SCHEMA_PATH):
            schema = json.loads(path.read_text())
            assert schema["description"] and schema["additionalProperties"] is False

            def walk(node, file_name):
                for name, sub in node.get("properties", {}).items():
                    assert sub.get("description"), f"{file_name}: {name} has no description"
                    walk(sub, file_name)

            walk(schema, path.name)

    def test_a_wrong_kind_or_scope_is_refused_without_echoing_it(self):
        for field in ("kind", "scope"):
            payload = envelope_payload()
            payload[field] = ACCESS
            with pytest.raises(cred.CredentialError, match=field) as raised:
                cred.credential_from_envelope(envelope(payload))
            assert ACCESS not in str(raised.value)

    def test_wrong_kind_and_scope_are_refused(self):
        payload = envelope_payload()
        payload["kind"] = "anchore_api_credential"
        with pytest.raises(cred.CredentialError, match="kind"):
            cred.credential_from_envelope(envelope(payload))
        payload = envelope_payload()
        payload["scope"] = "anchore"
        with pytest.raises(cred.CredentialError, match="scope"):
            cred.credential_from_envelope(envelope(payload))


@pytest.mark.spec("req-tenable-connection-10")
def test_network_name_is_required_and_non_empty():
    for value in (None, ""):
        with pytest.raises(cred.CredentialError, match="network_name|schema"):
            cred.credential_from_envelope(envelope(network_name=value))


@pytest.mark.spec("req-tenable-connection-5")
@pytest.mark.parametrize("url", ["https://u:p@sc.example", "https://sc.example?x=1", "https://sc.example#f", "https://sc.example:0", "https://sc.example./", "https://sc.example/a/../b", "https://sc.example/%2e"])
def test_ambiguous_base_urls_are_refused_before_any_request(url):
    with pytest.raises(cred.CredentialError):
        cred.credential_from_envelope(envelope(base_url=url))


@pytest.mark.spec("req-tenable-connection-5")
def test_one_instance_one_key_however_spelled():
    keys = {cred.credential_from_envelope(envelope(base_url=u)).instance_key for u in ("https://SC.example", "https://sc.example:443", "HTTPS://sc.example:443/")}
    assert keys == {"https://sc.example:443"}


@pytest.mark.spec("req-tenable-connection-2")
def test_no_repr_shows_a_key():
    c = cred.credential_from_envelope(envelope())
    admin = cred.admin_from_envelope(envelope(admin_payload()))
    c = c.with_admin(admin)
    for text in (repr(c), repr(c.keys), repr(admin), repr(admin.keys), str(c)):
        for key in (ACCESS, SECRET, ADMIN_ACCESS, ADMIN_SECRET):
            assert key not in text


@pytest.mark.spec("req-tenable-connection-2")
def test_redaction_replaces_every_form_and_never_reproduces_a_key():
    c = cred.credential_from_envelope(envelope()).with_admin(cred.admin_from_envelope(envelope(admin_payload())))
    text = f"a {ACCESS} b {SECRET} c accessKey={ACCESS}; secretKey={SECRET} d {ADMIN_SECRET}"
    cleaned, count = c.redact(text)
    assert count == 4
    for key in (ACCESS, SECRET, ADMIN_SECRET):
        assert key not in cleaned


@pytest.mark.spec("req-tenable-connection-4")
@pytest.mark.spec("req-tenable-connection-9")
def test_settings_imply_their_warnings():
    assert cred.credential_from_envelope(envelope()).warnings() == []
    assert cred.credential_from_envelope(envelope(ssl_verify=False)).warnings() == ["TLS_VERIFICATION_DISABLED"]
    plain = cred.credential_from_envelope(envelope(base_url="http://sc.example"))
    assert plain.instance_key == "http://sc.example:80" and plain.warnings() == ["PLAINTEXT_TRANSPORT"]


@pytest.mark.spec("req-tenable-connection-3")
def test_verification_is_explicit_and_on_by_default():
    assert cred.credential_from_envelope(envelope()).verify is True
    assert cred.credential_from_envelope(envelope(ca_bundle="/etc/ca.pem")).verify == "/etc/ca.pem"
    assert cred.credential_from_envelope(envelope(ssl_verify=False, ca_bundle="/etc/ca.pem")).verify is False


@pytest.mark.spec("req-tenable-connection-6")
class TestDiscovery:
    def test_each_envelope_is_one_instance(self, tmp_path):
        write_envelope(tmp_path, envelope_payload("a"))
        write_envelope(tmp_path, envelope_payload("b", base_url="https://sc.example:8443"))
        usable, errors = cred.discover(tmp_path)
        assert sorted(c.key for c in usable) == ["a", "b"] and errors == []

    def test_two_envelopes_for_one_instance_refuse_both_naming_both(self, tmp_path):
        write_envelope(tmp_path, envelope_payload("a"))
        write_envelope(tmp_path, envelope_payload("b", base_url="HTTPS://SC.EXAMPLE:443/"))
        usable, errors = cred.discover(tmp_path)
        assert usable == [] and len(errors) == 2
        assert all("tenable:a" in str(e) and "tenable:b" in str(e) for e in errors)

    def test_a_malformed_envelope_fails_only_itself(self, tmp_path):
        write_envelope(tmp_path, envelope_payload("a"))
        write_envelope(tmp_path, envelope_payload("b", base_url="https://other.example", network_name=None))
        usable, errors = cred.discover(tmp_path)
        assert [c.key for c in usable] == ["a"] and [e.qualified for e in errors] == ["tenable:b"]

    def test_examples_and_other_scopes_are_never_read(self, tmp_path):
        (tmp_path / "x.secret.example.json").write_text(json.dumps(envelope_payload("x")))
        other = envelope_payload("y")
        other["scope"] = "anchore"
        write_envelope(tmp_path, other)
        assert cred.discover(tmp_path) == ([], [])

    def test_a_missing_root_is_an_error_not_an_empty_success(self, tmp_path):
        usable, errors = cred.discover(tmp_path / "nope")
        assert usable == [] and len(errors) == 1


@pytest.mark.spec("req-tenable-connection-11")
class TestAdminPairing:
    def test_an_admin_envelope_attaches_to_its_main_envelope(self, tmp_path):
        write_envelope(tmp_path, envelope_payload("sc-one"))
        write_envelope(tmp_path, admin_payload())
        usable, errors = cred.discover(tmp_path)
        assert errors == [] and usable[0].admin is not None and usable[0].admin.qualified == "tenable:sc-one-admin"

    def test_an_admin_envelope_for_another_instance_is_refused_naming_both_keys(self, tmp_path):
        write_envelope(tmp_path, envelope_payload("sc-one"))
        write_envelope(tmp_path, admin_payload(base_url="https://other.example"))
        usable, errors = cred.discover(tmp_path)
        assert usable[0].admin is None
        assert len(errors) == 1 and "tenable:sc-one-admin" in str(errors[0]) and "tenable:sc-one" in str(errors[0])
        assert ADMIN_ACCESS not in str(errors[0])

    def test_an_admin_envelope_naming_no_main_envelope_is_refused(self, tmp_path):
        write_envelope(tmp_path, admin_payload(for_key="missing"))
        assert [e.qualified for e in cred.discover(tmp_path)[1]] == ["tenable:sc-one-admin"]

    def test_two_admin_envelopes_for_one_instance_are_both_refused(self, tmp_path):
        write_envelope(tmp_path, envelope_payload("sc-one"))
        write_envelope(tmp_path, admin_payload("adm-a"))
        write_envelope(tmp_path, admin_payload("adm-b"))
        usable, errors = cred.discover(tmp_path)
        assert usable[0].admin is None and len(errors) == 2

    def test_disabled_verification_on_the_admin_envelope_is_warned(self, tmp_path):
        write_envelope(tmp_path, envelope_payload("sc-one"))
        write_envelope(tmp_path, admin_payload(ssl_verify=False))
        assert cred.discover(tmp_path)[0][0].warnings() == ["TLS_VERIFICATION_DISABLED"]


@pytest.mark.spec("req-tenable-connection-8")
def test_no_credential_pattern_was_added_for_these_credentials():
    """These credentials have no scannable shape; silence would look like coverage."""
    import tap.credential_patterns as patterns

    text = " ".join(str(p) for p in patterns.CREDENTIAL_PATTERNS).lower()
    assert "tenable" not in text and "accesskey=" not in text


@pytest.mark.spec("req-tenable-connection-1")
def test_no_model_declares_a_connection_setting():
    """No node type carries an API key, a TLS setting or a filter."""
    from tap_plugin.tenable import models

    forbidden = {"access_key", "secret_key", "ssl_verify", "ca_bundle", "scope", "base_url", "password"}
    for name in models.__all__:
        model = getattr(models, name)
        fields = {f.name for f in model._meta.get_fields()}
        assert not (fields & forbidden), f"{name} declares {fields & forbidden}"
