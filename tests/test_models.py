"""Tests for scanme.core.models."""

import time

from scanme.core.models import (
    DNSRecord,
    PortInfo,
    ScanResult,
    ScanTarget,
    SSLInfo,
    SubdomainInfo,
    VulnInfo,
)


class TestScanTarget:
    def test_defaults(self):
        t = ScanTarget(raw="example.com")
        assert t.raw == "example.com"
        assert t.host == ""
        assert t.ip == ""
        assert t.port_range == (1, 1024)

    def test_to_dict(self):
        t = ScanTarget(raw="example.com", host="example.com", ip="1.2.3.4")
        d = t.to_dict()
        assert d["raw"] == "example.com"
        assert d["host"] == "example.com"
        assert d["ip"] == "1.2.3.4"
        assert d["port_range"] == [1, 1024]


class TestPortInfo:
    def test_defaults(self):
        p = PortInfo(port=80)
        assert p.port == 80
        assert p.state == "open"
        assert p.service == "unknown"
        assert p.banner == ""

    def test_to_dict_minimal(self):
        p = PortInfo(port=443, service="https")
        d = p.to_dict()
        assert d == {"port": 443, "state": "open", "service": "https"}
        assert "banner" not in d
        assert "version" not in d

    def test_to_dict_with_banner(self):
        p = PortInfo(port=22, service="ssh", banner="OpenSSH_8.9", version="8.9")
        d = p.to_dict()
        assert d["banner"] == "OpenSSH_8.9"
        assert d["version"] == "8.9"


class TestVulnInfo:
    def test_defaults(self):
        v = VulnInfo(title="Test vuln")
        assert v.severity == "info"
        assert v.description == ""

    def test_to_dict(self):
        v = VulnInfo(
            title="Missing HSTS",
            severity="low",
            description="No HSTS header",
            remediation="Add Strict-Transport-Security header",
        )
        d = v.to_dict()
        assert d["title"] == "Missing HSTS"
        assert d["severity"] == "low"
        assert d["remediation"] == "Add Strict-Transport-Security header"


class TestDNSRecord:
    def test_to_dict(self):
        r = DNSRecord(hostname="example.com", record_type="A", value="1.2.3.4", ttl=300)
        d = r.to_dict()
        assert d["type"] == "A"
        assert d["value"] == "1.2.3.4"
        assert d["ttl"] == 300


class TestSSLInfo:
    def test_empty(self):
        s = SSLInfo()
        d = s.to_dict()
        assert d == {}

    def test_partial(self):
        s = SSLInfo(version="TLSv1.3", cipher="AES256-GCM", bits=256)
        d = s.to_dict()
        assert d["version"] == "TLSv1.3"
        assert d["cipher"] == "AES256-GCM"
        assert d["bits"] == 256
        assert "san" not in d

    def test_with_san(self):
        s = SSLInfo(version="TLSv1.3", san=["example.com", "www.example.com"])
        d = s.to_dict()
        assert d["san"] == ["example.com", "www.example.com"]


class TestSubdomainInfo:
    def test_to_dict(self):
        s = SubdomainInfo(subdomain="www.example.com", ip="1.2.3.4")
        d = s.to_dict()
        assert d["subdomain"] == "www.example.com"
        assert d["ip"] == "1.2.3.4"

    def test_to_dict_no_ip(self):
        s = SubdomainInfo(subdomain="test.example.com")
        d = s.to_dict()
        assert "ip" not in d


class TestScanResult:
    def test_minimal(self):
        r = ScanResult(module="test", target="example.com")
        assert r.module == "test"
        assert r.target == "example.com"
        assert isinstance(r.timestamp, float)

    def test_to_dict_minimal(self):
        r = ScanResult(module="netscan", target="example.com")
        d = r.to_dict()
        assert d["module"] == "netscan"
        assert d["target"] == "example.com"
        assert "timestamp" in d
        # Empty collections should not appear
        assert "ports" not in d
        assert "vulns" not in d

    def test_to_dict_with_data(self):
        r = ScanResult(module="netscan", target="example.com")
        r.ports = [PortInfo(port=80, service="http"), PortInfo(port=443, service="https")]
        r.vulns = [VulnInfo(title="Open port", severity="medium")]
        r.waf = "Cloudflare"
        r.technologies = ["Nginx", "PHP"]

        d = r.to_dict()
        assert len(d["ports"]) == 2
        assert d["ports"][0]["port"] == 80
        assert len(d["vulns"]) == 1
        assert d["waf"] == "Cloudflare"
        assert d["technologies"] == ["Nginx", "PHP"]

    def test_to_dict_with_ssl(self):
        r = ScanResult(module="webscan", target="example.com")
        r.ssl = SSLInfo(version="TLSv1.3")
        d = r.to_dict()
        assert d["ssl"]["version"] == "TLSv1.3"
