"""Network utility functions."""

from __future__ import annotations

import re
import socket
from urllib.parse import urlparse

from scanme.core.models import ScanTarget


def resolve_target(raw: str, port_range: tuple[int, int] = (1, 1024)) -> ScanTarget:
    """Parse a raw user input into a normalized ScanTarget."""
    raw = raw.strip()
    target = ScanTarget(raw=raw, port_range=port_range)

    # If it looks like a URL, extract host from it
    if "://" in raw:
        parsed = urlparse(raw)
        target.host = parsed.hostname or raw
        target.url = raw
    else:
        # Remove any trailing paths/ports from bare hostnames
        target.host = raw.split("/")[0].split(":")[0]
        target.url = f"http://{target.host}"

    # Resolve IP
    try:
        target.ip = socket.gethostbyname(target.host)
    except socket.gaierror:
        target.ip = target.host  # might already be an IP

    return target


def validate_target(target: str) -> bool:
    """Validate that the target looks like a valid host, IP, or URL."""
    target = target.strip()
    if not target:
        return False

    # Strip scheme if present
    if "://" in target:
        target = urlparse(target).hostname or target

    # Remove port/path
    target = target.split("/")[0].split(":")[0]

    # Check IPv4
    ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_re.match(target):
        parts = target.split(".")
        return all(0 <= int(p) <= 255 for p in parts)

    # Check hostname (allows internationalized domains)
    host_re = re.compile(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$")
    return bool(host_re.match(target))


def parse_ports(spec: str) -> tuple[int, int]:
    """Parse a port specification like '1-1024' or '80,443' into a range tuple.

    For comma-separated lists, returns (min, max) of the set.
    """
    spec = spec.strip()

    if "-" in spec:
        parts = spec.split("-", 1)
        return (int(parts[0]), int(parts[1]))

    if "," in spec:
        ports = [int(p.strip()) for p in spec.split(",")]
        return (min(ports), max(ports))

    # Single port
    p = int(spec)
    return (p, p)


# Top 100 ports (nmap-style quick scan)
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    27017, 32768, 49152, 49153, 49154, 49155, 49156,
]

# Common port-to-service mapping
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    119: "nntp", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 543: "klogin", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 873: "rsync",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2181: "zookeeper", 3000: "dev",
    3128: "squid", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 6379: "redis", 6667: "irc",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9090: "prometheus",
    9200: "elasticsearch", 9418: "git", 11211: "memcached",
    27017: "mongodb", 50000: "db2",
}
