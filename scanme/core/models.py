"""Data models for scan results and targets."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class ScanTarget:
    """Normalized scan target."""

    raw: str
    host: str = ""
    ip: str = ""
    url: str = ""
    port_range: tuple[int, int] = (1, 1024)

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "host": self.host,
            "ip": self.ip,
            "url": self.url,
            "port_range": list(self.port_range),
        }


@dataclass
class PortInfo:
    """Information about a scanned port."""

    port: int
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    version: str = ""

    def to_dict(self) -> dict:
        d: dict = {"port": self.port, "state": self.state, "service": self.service}
        if self.banner:
            d["banner"] = self.banner
        if self.version:
            d["version"] = self.version
        return d


@dataclass
class VulnInfo:
    """Vulnerability finding."""

    title: str
    severity: str = "info"  # info, low, medium, high, critical
    description: str = ""
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class DNSRecord:
    """DNS record entry."""

    hostname: str
    record_type: str
    value: str
    ttl: int = 0

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
        }


@dataclass
class SSLInfo:
    """SSL/TLS certificate information."""

    version: str = ""
    cipher: str = ""
    bits: int = 0
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {}
        for k in ("version", "cipher", "bits", "issuer", "subject", "not_before", "not_after"):
            v = getattr(self, k)
            if v:
                d[k] = v
        if self.san:
            d["san"] = self.san
        return d


@dataclass
class SubdomainInfo:
    """Discovered subdomain."""

    subdomain: str
    ip: str = ""

    def to_dict(self) -> dict:
        d: dict = {"subdomain": self.subdomain}
        if self.ip:
            d["ip"] = self.ip
        return d


@dataclass
class ScanResult:
    """Aggregated result from a scan module."""

    module: str
    target: str
    timestamp: float = field(default_factory=time.time)
    ports: list[PortInfo] = field(default_factory=list)
    dns_records: list[DNSRecord] = field(default_factory=list)
    subdomains: list[SubdomainInfo] = field(default_factory=list)
    vulns: list[VulnInfo] = field(default_factory=list)
    ssl: SSLInfo | None = None
    headers: dict = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    whois_data: dict = field(default_factory=dict)
    waf: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {
            "module": self.module,
            "target": self.target,
            "timestamp": self.timestamp,
        }
        if self.ports:
            d["ports"] = [p.to_dict() for p in self.ports]
        if self.dns_records:
            d["dns_records"] = [r.to_dict() for r in self.dns_records]
        if self.subdomains:
            d["subdomains"] = [s.to_dict() for s in self.subdomains]
        if self.vulns:
            d["vulns"] = [v.to_dict() for v in self.vulns]
        if self.ssl:
            d["ssl"] = self.ssl.to_dict()
        if self.headers:
            d["headers"] = self.headers
        if self.technologies:
            d["technologies"] = self.technologies
        if self.whois_data:
            d["whois"] = self.whois_data
        if self.waf:
            d["waf"] = self.waf
        if self.extra:
            d.update(self.extra)
        return d
