"""Reconnaissance module — WHOIS, reverse DNS, IP info."""

from __future__ import annotations

import asyncio
import socket

import whois as python_whois

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import ScanResult, ScanTarget
from scanme.ui.console import CyberConsole


class ReconScanner(AsyncScanEngine):
    """General reconnaissance: WHOIS, reverse DNS, IP information."""

    name = "recon"

    async def run(self, target: ScanTarget, ui: CyberConsole | None = None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)

        if ui:
            ui.scan_header(target.host, self.name)

        # Run tasks in parallel
        await asyncio.gather(
            self._whois_lookup(target, result, ui),
            self._reverse_dns(target, result, ui),
            self._ip_info(target, result, ui),
            return_exceptions=True,
        )

        if ui:
            ui.scan_summary(result)

        return result

    async def _whois_lookup(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Perform WHOIS lookup."""
        if ui:
            ui.section("WHOIS Lookup")

        loop = asyncio.get_running_loop()

        try:
            w = await loop.run_in_executor(None, lambda: python_whois.whois(target.host))

            # Convert to a clean dict
            data: dict = {}
            fields = [
                "domain_name", "registrar", "creation_date", "expiration_date",
                "updated_date", "name_servers", "status", "emails", "org",
                "address", "city", "state", "country", "dnssec",
            ]

            for field in fields:
                val = getattr(w, field, None)
                if val is not None:
                    if isinstance(val, list):
                        # Deduplicate and stringify
                        val = list(dict.fromkeys(str(v) for v in val))
                    else:
                        val = str(val)
                    data[field] = val

            result.whois_data = data

            if ui:
                ui.whois_panel(data)

        except Exception as e:
            if ui:
                ui.error("WHOIS", f"Lookup failed: {e}")

    async def _reverse_dns(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Reverse DNS lookup on the target IP."""
        if ui:
            ui.section("Reverse DNS")

        loop = asyncio.get_running_loop()

        try:
            hostname, aliases, addrs = await loop.run_in_executor(
                None, lambda: socket.gethostbyaddr(target.ip)
            )

            result.extra["reverse_dns"] = {
                "hostname": hostname,
                "aliases": aliases,
                "addresses": addrs,
            }

            if ui:
                ui.success("PTR", f"{target.ip} -> {hostname}")
                for alias in aliases:
                    ui.info("ALIAS", alias)

        except (socket.herror, socket.gaierror) as e:
            if ui:
                ui.info("PTR", f"No reverse DNS for {target.ip}")

    async def _ip_info(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Gather basic IP information."""
        if ui:
            ui.section("IP Information")

        try:
            loop = asyncio.get_running_loop()

            # Get all addresses (IPv4 + IPv6)
            infos = await loop.getaddrinfo(target.host, None)
            addresses = list({info[4][0] for info in infos})

            result.extra["ip_addresses"] = addresses

            if ui:
                for addr in addresses:
                    family = "IPv6" if ":" in addr else "IPv4"
                    ui.info(family, addr)

        except Exception as e:
            if ui:
                ui.error("IP", str(e))
