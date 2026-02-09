"""Network Scanner — async port scan, banner grab, service fingerprint."""

from __future__ import annotations

import asyncio
import socket

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import PortInfo, ScanResult, ScanTarget, VulnInfo
from scanme.ui.console import CyberConsole
from scanme.utils.network import PORT_SERVICES, TOP_100_PORTS

# Probes sent to grab banners from common services
SERVICE_PROBES: dict[str, bytes] = {
    "http": b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "ftp": b"",           # FTP sends banner on connect
    "ssh": b"",           # SSH sends banner on connect
    "smtp": b"",          # SMTP sends banner on connect
    "pop3": b"",          # POP3 sends banner on connect
    "imap": b"",          # IMAP sends banner on connect
    "mysql": b"",         # MySQL sends greeting on connect
    "redis": b"INFO\r\n",
    "mongodb": b"",       # MongoDB has a binary protocol
}

# Patterns to identify services from banners
BANNER_SIGNATURES: list[tuple[str, str]] = [
    ("SSH-", "ssh"),
    ("220 ", "ftp/smtp"),
    ("HTTP/", "http"),
    ("+OK", "pop3"),
    ("* OK", "imap"),
    ("mysql", "mysql"),
    ("MariaDB", "mariadb"),
    ("PostgreSQL", "postgresql"),
    ("redis_version", "redis"),
    ("MongoDB", "mongodb"),
    ("Microsoft FTP", "microsoft-ftp"),
    ("vsftpd", "vsftpd"),
    ("OpenSSH", "openssh"),
    ("Apache", "apache"),
    ("nginx", "nginx"),
    ("IIS", "iis"),
]


class NetScanner(AsyncScanEngine):
    """Async port scanner with banner grabbing and service detection."""

    name = "netscan"

    def __init__(
        self,
        concurrency: int = 500,
        timeout: float = 2.0,
        retries: int = 2,
        proxy: str | None = None,
        grab_banners: bool = True,
    ):
        super().__init__(concurrency=concurrency, timeout=timeout, retries=retries, proxy=proxy)
        self.grab_banners = grab_banners

    async def run(self, target: ScanTarget, ui: CyberConsole | None = None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)

        ip = target.ip
        start, end = target.port_range

        if ui:
            ui.scan_header(f"{target.host} ({ip})", self.name)
            ui.section("Port Scan")

        # Determine port list
        if start == 1 and end <= 100:
            ports = TOP_100_PORTS
        else:
            ports = list(range(start, end + 1))

        # Scan all ports concurrently
        open_ports = await self._scan_ports(ip, ports, ui)

        # Banner grab on open ports
        if self.grab_banners and open_ports:
            if ui:
                ui.section("Banner Grabbing")
            open_ports = await self._grab_banners(ip, open_ports, ui)

        result.ports = open_ports

        # Check for risky open ports
        risky = {21, 23, 445, 3389, 5900, 1433, 3306, 5432, 6379, 27017, 9200}
        for p in open_ports:
            if p.port in risky:
                result.vulns.append(VulnInfo(
                    title=f"Sensitive port open: {p.port}/{p.service}",
                    severity="medium",
                    description=f"Port {p.port} ({p.service}) is open and commonly targeted.",
                    remediation="Restrict access via firewall rules if not needed.",
                ))

        if ui:
            ui.port_table(result.ports)
            if result.vulns:
                ui.vuln_panel(result.vulns)
            ui.scan_summary(result)

        return result

    async def _scan_ports(
        self, ip: str, ports: list[int], ui: CyberConsole | None
    ) -> list[PortInfo]:
        """Scan ports concurrently with progress."""
        open_ports: list[PortInfo] = []

        if ui and not ui.json_mode:
            with ui.progress() as progress:
                task = progress.add_task(f"Scanning {len(ports)} ports", total=len(ports))

                async def _check(port: int):
                    result = await self._check_port(ip, port)
                    progress.advance(task)
                    return result

                tasks = [_check(p) for p in ports]
                results = await asyncio.gather(*tasks)
        else:
            tasks = [self._check_port(ip, p) for p in ports]
            results = await asyncio.gather(*tasks)

        for r in results:
            if r is not None:
                open_ports.append(r)
                if ui and not ui.json_mode:
                    ui.success("OPEN", f"{r.port}/tcp — {r.service}")

        return open_ports

    async def _check_port(self, ip: str, port: int) -> PortInfo | None:
        """Check if a single port is open."""
        async with self._semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()

                service = PORT_SERVICES.get(port, "unknown")
                return PortInfo(port=port, state="open", service=service)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def _grab_banners(
        self, ip: str, ports: list[PortInfo], ui: CyberConsole | None
    ) -> list[PortInfo]:
        """Grab banners from open ports."""
        tasks = [self._grab_banner(ip, p) for p in ports]
        results = await asyncio.gather(*tasks)

        for port_info in results:
            if port_info.banner and ui and not ui.json_mode:
                banner_preview = port_info.banner[:80].replace("\n", " ")
                ui.info("BANNER", f"{port_info.port}/tcp — {banner_preview}")

        return results

    async def _grab_banner(self, ip: str, port_info: PortInfo) -> PortInfo:
        """Grab banner from a single service."""
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port_info.port),
                    timeout=self.timeout,
                )

                # Determine probe
                probe = SERVICE_PROBES.get(port_info.service, b"")
                if probe:
                    probe = probe.replace(b"target", ip.encode())
                    writer.write(probe)
                    await writer.drain()

                # Read banner
                banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                banner_text = banner.decode("utf-8", errors="replace").strip()

                writer.close()
                await writer.wait_closed()

                if banner_text:
                    port_info.banner = banner_text
                    # Try to fingerprint from banner
                    for sig, svc in BANNER_SIGNATURES:
                        if sig.lower() in banner_text.lower():
                            port_info.version = _extract_version(banner_text, sig)
                            if port_info.service == "unknown":
                                port_info.service = svc
                            break

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError, UnicodeDecodeError):
                pass

        return port_info


def _extract_version(banner: str, sig: str) -> str:
    """Try to extract a version string near a signature match."""
    idx = banner.lower().find(sig.lower())
    if idx == -1:
        return ""
    # Grab a chunk around the match
    chunk = banner[idx:idx + 60].split("\n")[0].split("\r")[0]
    return chunk.strip()
