"""DNS Scanner — records enumeration, zone transfer, subdomain bruteforce."""

from __future__ import annotations

import asyncio
import socket

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import DNSRecord, ScanResult, ScanTarget, SubdomainInfo, VulnInfo
from scanme.ui.console import CyberConsole

# Record types to query
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

# Subdomain wordlist for bruteforce
DNS_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m",
    "dev", "staging", "test", "beta", "alpha", "demo", "api", "v1", "v2",
    "admin", "secure", "vpn", "ssh", "remote", "cloud", "cdn", "static",
    "media", "images", "img", "assets", "files", "download", "blog", "forum",
    "shop", "store", "portal", "dashboard", "panel", "db", "database",
    "mysql", "postgres", "mongo", "redis", "backup", "git", "ci", "jenkins",
    "grafana", "prometheus", "elk", "kibana", "docker", "k8s", "registry",
    "auth", "sso", "login", "signup", "owa", "exchange", "intranet",
    "internal", "stage", "uat", "preprod", "prod", "mobile", "app",
    "docs", "wiki", "help", "support", "status", "monitor", "mx", "relay",
    "gateway", "proxy", "cache", "node", "worker", "queue", "mq",
]


class DNSScanner(AsyncScanEngine):
    """DNS reconnaissance module."""

    name = "dnsscan"

    def __init__(
        self,
        concurrency: int = 100,
        timeout: float = 5.0,
        retries: int = 2,
        proxy: str | None = None,
        zone_transfer: bool = True,
        bruteforce: bool = True,
        wordlist: list[str] | None = None,
    ):
        super().__init__(concurrency=concurrency, timeout=timeout, retries=retries, proxy=proxy)
        self.zone_transfer = zone_transfer
        self.bruteforce = bruteforce
        self.wordlist = wordlist or DNS_WORDLIST

    async def run(self, target: ScanTarget, ui: CyberConsole | None = None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)

        if ui:
            ui.scan_header(target.host, self.name)

        # Phase 1: DNS records
        if ui:
            ui.section("DNS Records")
        await self._query_records(target, result, ui)

        # Phase 2: Zone transfer
        if self.zone_transfer:
            if ui:
                ui.section("Zone Transfer Test")
            await self._test_zone_transfer(target, result, ui)

        # Phase 3: Subdomain bruteforce
        if self.bruteforce:
            if ui:
                ui.section("Subdomain Bruteforce")
            await self._bruteforce_subdomains(target, result, ui)

        # Phase 4: Reverse DNS on found IPs
        if result.subdomains:
            if ui:
                ui.section("Reverse DNS")
            await self._reverse_dns(result, ui)

        if ui:
            ui.dns_table(result.dns_records)
            ui.subdomain_table(result.subdomains)
            ui.scan_summary(result)

        return result

    async def _query_records(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Query all standard DNS record types."""
        loop = asyncio.get_running_loop()
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout

        for rtype in RECORD_TYPES:
            try:
                answers = await loop.run_in_executor(
                    None, lambda rt=rtype: resolver.resolve(target.host, rt)
                )
                for rdata in answers:
                    record = DNSRecord(
                        hostname=target.host,
                        record_type=rtype,
                        value=rdata.to_text(),
                        ttl=answers.rrset.ttl,
                    )
                    result.dns_records.append(record)
                    if ui:
                        ui.success(rtype, f"{rdata.to_text()} (TTL: {answers.rrset.ttl})")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except dns.exception.Timeout:
                if ui:
                    ui.warning(rtype, "Timeout")
            except Exception as e:
                if ui:
                    ui.error(rtype, str(e))

    async def _test_zone_transfer(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Attempt zone transfer (AXFR) on each nameserver."""
        loop = asyncio.get_running_loop()

        # Get nameservers
        ns_records = [r for r in result.dns_records if r.record_type == "NS"]
        if not ns_records:
            try:
                resolver = dns.resolver.Resolver()
                answers = await loop.run_in_executor(
                    None, lambda: resolver.resolve(target.host, "NS")
                )
                ns_records = [
                    DNSRecord(hostname=target.host, record_type="NS", value=r.to_text())
                    for r in answers
                ]
            except Exception:
                if ui:
                    ui.info("AXFR", "No nameservers found")
                return

        for ns in ns_records:
            ns_host = ns.value.rstrip(".")
            try:
                def _try_axfr(nameserver=ns_host):
                    z = dns.zone.from_xfr(
                        dns.query.xfr(nameserver, target.host, lifetime=self.timeout)
                    )
                    return z

                zone = await loop.run_in_executor(None, _try_axfr)
                names = zone.nodes.keys()

                result.vulns.append(VulnInfo(
                    title="Zone transfer allowed (AXFR)",
                    severity="high",
                    description=f"Nameserver {ns_host} allows zone transfer, exposing all DNS records.",
                    remediation="Restrict zone transfers to authorized secondary nameservers.",
                ))

                if ui:
                    ui.error("AXFR", f"Zone transfer ALLOWED on {ns_host} — {len(names)} records!")

                for name in names:
                    fqdn = f"{name}.{target.host}"
                    result.subdomains.append(SubdomainInfo(subdomain=fqdn))

            except Exception:
                if ui:
                    ui.info("AXFR", f"{ns_host} — Transfer denied (good)")

    async def _bruteforce_subdomains(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Bruteforce subdomains via async DNS."""
        existing = {s.subdomain for s in result.subdomains}
        found: list[SubdomainInfo] = []

        async def _check(sub: str):
            async with self._semaphore:
                fqdn = f"{sub}.{target.host}"
                if fqdn in existing:
                    return
                try:
                    loop = asyncio.get_running_loop()
                    infos = await loop.getaddrinfo(fqdn, None)
                    if infos:
                        ip = infos[0][4][0]
                        info = SubdomainInfo(subdomain=fqdn, ip=ip)
                        found.append(info)
                        if ui:
                            ui.success("FOUND", f"{fqdn} -> {ip}")
                except (socket.gaierror, OSError):
                    pass

        tasks = [_check(sub) for sub in self.wordlist]

        if ui and not ui.json_mode:
            with ui.progress() as progress:
                task_id = progress.add_task("Bruteforcing subdomains", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        else:
            await asyncio.gather(*tasks)

        result.subdomains.extend(found)

    async def _reverse_dns(self, result: ScanResult, ui: CyberConsole | None):
        """Perform reverse DNS on discovered IPs."""
        loop = asyncio.get_running_loop()
        seen_ips: set[str] = set()

        for sub in result.subdomains:
            if sub.ip and sub.ip not in seen_ips:
                seen_ips.add(sub.ip)
                try:
                    hostname, _, _ = await loop.run_in_executor(
                        None, lambda ip=sub.ip: socket.gethostbyaddr(ip)
                    )
                    if ui:
                        ui.info("PTR", f"{sub.ip} -> {hostname}")
                except (socket.herror, socket.gaierror):
                    pass
