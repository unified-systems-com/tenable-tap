"""The key derivations every Tenable model checks its stored key against (tap_plugin.tenable.identity).

Pure functions, no database: the canonical root that is the instance key, the short instance
dimension, the host key from a record's own hostUniqueness list, and the assertion key.
"""

import pytest

from tap_plugin.tenable.identity import (
    FREE_TEXT_CEILING_BYTES,
    UnkeyableError,
    assertion_key,
    canonical_root,
    host_key,
    instance_dimension,
    text_within_ceiling,
)

IPV4 = {"repository_id": "1", "ip": "10.0.0.5", "dns_name": "web01.corp"}


@pytest.mark.spec("req-tenable-connection-5")
class TestCanonicalRoot:
    @pytest.mark.parametrize(
        "spelling",
        ["https://sc.example", "HTTPS://SC.Example/", "https://sc.example:443", "https://sc.example:443/"],
    )
    def test_one_console_one_key_however_spelled(self, spelling):
        assert canonical_root(spelling) == "https://sc.example:443"

    def test_path_is_kept_without_trailing_slash(self):
        assert canonical_root("https://sc.example/tenable/") == "https://sc.example:443/tenable"

    def test_plain_http_defaults_to_80(self):
        assert canonical_root("http://sc.example") == "http://sc.example:80"

    @pytest.mark.parametrize(
        "url",
        ["https://user:secret@sc.example", "https://sc.example?x=1", "https://sc.example#frag", "ftp://sc.example", "https://"],
    )
    def test_refused_before_any_request(self, url):
        with pytest.raises(ValueError):
            canonical_root(url)


@pytest.mark.spec("req-tenable-scanner-run-2")
class TestDistinctRoots:
    def test_port_and_path_make_distinct_consoles(self):
        keys = {
            canonical_root("https://sc.example"),
            canonical_root("https://sc.example:8443"),
            canonical_root("https://sc.example/other"),
            canonical_root("http://sc.example"),
        }
        assert len(keys) == 4

    def test_key_carries_no_credential(self):
        key = canonical_root("https://sc.example:8443/x")
        assert "@" not in key and "secret" not in key


class TestInstanceDimension:
    def test_default_port_dropped(self):
        assert instance_dimension("https://sc.example:443") == "sc.example"

    def test_other_port_kept(self):
        assert instance_dimension("https://sc.example:8443/x") == "sc.example:8443"


@pytest.mark.spec("req-tenable-findings-11")
@pytest.mark.spec("req-tenable-findings-12")
class TestHostKey:
    def test_reordered_or_duplicated_list_is_the_same_key(self):
        assert host_key("repositoryID,ip,dnsName", IPV4) == host_key("dnsName, ip,repositoryID,ip", IPV4)

    def test_universal_and_agent_records(self):
        universal = host_key("repositoryID,hostUUID", {"repository_id": "2", "host_uuid": "h-1"})
        agent = host_key("repositoryID,uuid", {"repository_id": "3", "agent_uuid": "a-1"})
        assert universal != agent

    def test_repository_always_hashed_in(self):
        """Equal addresses in two repositories never become one host, even when the list omits repositoryID."""
        one = host_key("ip", {**IPV4, "repository_id": "1"})
        two = host_key("ip", {**IPV4, "repository_id": "2"})
        assert one != two

    @pytest.mark.parametrize("uniqueness", ["", None, " , ", "repositoryID,agentUUID"])
    def test_empty_or_unknown_list_is_unkeyable(self, uniqueness):
        with pytest.raises(UnkeyableError):
            host_key(uniqueness, IPV4)

    @pytest.mark.parametrize("missing", ["ip", "dns_name", "repository_id"])
    def test_named_field_absent_or_empty_is_unkeyable(self, missing):
        with pytest.raises(UnkeyableError):
            host_key("repositoryID,ip,dnsName", {**IPV4, missing: None})
        with pytest.raises(UnkeyableError):
            host_key("repositoryID,ip,dnsName", {**IPV4, missing: ""})

    def test_unnamed_fields_do_not_move_the_key(self):
        assert host_key("repositoryID,ip", IPV4) == host_key("repositoryID,ip", {**IPV4, "dns_name": "renamed"})


@pytest.mark.spec("req-tenable-findings-1")
@pytest.mark.spec("req-tenable-findings-7")
class TestAssertionKey:
    def test_fixed_length_hex(self):
        key = assertion_key("1", "h" * 64, "19506", "0", "TCP")
        assert len(key) == 64 and int(key, 16) >= 0

    @pytest.mark.parametrize("position", range(5))
    def test_any_missing_part_is_unkeyable(self, position):
        parts = ["1", "h" * 64, "19506", "0", "TCP"]
        parts[position] = None
        with pytest.raises(UnkeyableError):
            assertion_key(*parts)

    def test_port_and_protocol_are_as_returned(self):
        assert assertion_key("1", "h", "1", "0", "TCP") != assertion_key("1", "h", "1", "0", "tcp")


@pytest.mark.spec("req-tenable-findings-10")
class TestCeiling:
    def test_ceiling_is_four_mebibytes_of_utf8(self):
        assert text_within_ceiling("a" * FREE_TEXT_CEILING_BYTES)
        assert not text_within_ceiling("a" * (FREE_TEXT_CEILING_BYTES + 1))
        assert not text_within_ceiling("é" * (FREE_TEXT_CEILING_BYTES // 2 + 1))

    def test_null_is_unobserved_and_fits(self):
        assert text_within_ceiling(None)
