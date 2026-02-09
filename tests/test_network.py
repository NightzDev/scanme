"""Tests for scanme.utils.network."""

from scanme.utils.network import (
    parse_ports,
    resolve_target,
    validate_target,
    PORT_SERVICES,
    TOP_100_PORTS,
)


class TestValidateTarget:
    def test_valid_domain(self):
        assert validate_target("example.com") is True

    def test_valid_subdomain(self):
        assert validate_target("www.example.com") is True

    def test_valid_ip(self):
        assert validate_target("192.168.1.1") is True

    def test_valid_url(self):
        assert validate_target("https://example.com") is True

    def test_valid_url_with_path(self):
        assert validate_target("https://example.com/path") is True

    def test_empty(self):
        assert validate_target("") is False

    def test_whitespace(self):
        assert validate_target("   ") is False

    def test_invalid_ip_octet(self):
        assert validate_target("999.999.999.999") is False

    def test_single_word(self):
        # No TLD
        assert validate_target("localhost") is False


class TestParseports:
    def test_range(self):
        assert parse_ports("1-1024") == (1, 1024)

    def test_single(self):
        assert parse_ports("80") == (80, 80)

    def test_comma_separated(self):
        result = parse_ports("80,443,8080")
        assert result == (80, 8080)

    def test_whitespace(self):
        assert parse_ports("  1 - 100  ") == (1, 100)


class TestResolveTarget:
    def test_bare_hostname(self):
        t = resolve_target("example.com")
        assert t.host == "example.com"
        assert t.url == "http://example.com"
        assert t.raw == "example.com"
        # IP should be resolved (or fallback to host)
        assert t.ip != ""

    def test_url_input(self):
        t = resolve_target("https://example.com/path")
        assert t.host == "example.com"
        assert t.url == "https://example.com/path"

    def test_custom_port_range(self):
        t = resolve_target("example.com", port_range=(80, 443))
        assert t.port_range == (80, 443)

    def test_ip_input(self):
        t = resolve_target("127.0.0.1")
        assert t.host == "127.0.0.1"
        assert t.ip == "127.0.0.1"


class TestConstants:
    def test_top_100_ports_count(self):
        assert len(TOP_100_PORTS) >= 90  # at least ~100 ports

    def test_common_ports_in_services(self):
        assert PORT_SERVICES[80] == "http"
        assert PORT_SERVICES[443] == "https"
        assert PORT_SERVICES[22] == "ssh"
        assert PORT_SERVICES[3306] == "mysql"

    def test_top_ports_include_common(self):
        assert 80 in TOP_100_PORTS
        assert 443 in TOP_100_PORTS
        assert 22 in TOP_100_PORTS
