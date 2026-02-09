"""Web Scanner — HTTP headers, SSL/TLS, WAF detection, tech fingerprint, subdomains."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import (
    SSLInfo, ScanResult, ScanTarget, SubdomainInfo, VulnInfo,
)
from scanme.ui.console import CyberConsole

# Security headers that should be present
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

# Headers that leak server info
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

# WAF signatures: header/body patterns -> WAF name
WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF": ["x-amzn-requestid", "awselb", "x-amz-cf"],
    "Akamai": ["akamai", "x-akamai"],
    "Imperva/Incapsula": ["incapsula", "_incap_", "x-iinfo"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "F5 BIG-IP": ["bigip", "f5", "x-wa-info"],
    "Barracuda": ["barra_counter_session"],
    "ModSecurity": ["mod_security", "modsecurity"],
}

# Technology patterns in headers and HTML
TECH_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, location, tech_name)
    (r"WordPress", "body", "WordPress"),
    (r"Joomla", "body", "Joomla"),
    (r"Drupal", "body", "Drupal"),
    (r"wp-content", "body", "WordPress"),
    (r"react", "body", "React"),
    (r"vue\.js|vuejs", "body", "Vue.js"),
    (r"angular", "body", "Angular"),
    (r"next\.js|__next", "body", "Next.js"),
    (r"laravel", "body", "Laravel"),
    (r"django", "body", "Django"),
    (r"express", "header", "Express.js"),
    (r"nginx", "header", "Nginx"),
    (r"apache", "header", "Apache"),
    (r"iis", "header", "IIS"),
    (r"cloudflare", "header", "Cloudflare"),
    (r"php", "header", "PHP"),
    (r"asp\.net", "header", "ASP.NET"),
    (r"jquery", "body", "jQuery"),
    (r"bootstrap", "body", "Bootstrap"),
]

# Default subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "blog", "dev", "staging", "test", "api",
    "portal", "vpn", "secure", "store", "shop", "cdn", "static", "media",
    "assets", "images", "app", "mobile", "beta", "demo", "docs", "status",
    "git", "ci", "jenkins", "grafana", "monitor", "ns1", "ns2", "mx",
    "webmail", "remote", "cloud", "db", "backup", "old", "new", "v2",
    "dashboard", "panel", "cpanel", "whm", "autodiscover", "autoconfig",
    "smtp", "pop", "imap", "owa", "exchange", "sso", "auth", "login",
    "signup", "register", "forum", "wiki", "help", "support", "kb",
    "stage", "uat", "preprod", "prod", "internal", "intranet", "extranet",
]


class WebScanner(AsyncScanEngine):
    """Full web analysis suite."""

    name = "webscan"

    def __init__(
        self,
        concurrency: int = 100,
        timeout: float = 10.0,
        retries: int = 2,
        proxy: str | None = None,
        scan_subdomains: bool = False,
        wordlist: list[str] | None = None,
    ):
        super().__init__(concurrency=concurrency, timeout=timeout, retries=retries, proxy=proxy)
        self.scan_subdomains = scan_subdomains
        self.wordlist = wordlist or SUBDOMAIN_WORDLIST

    async def run(self, target: ScanTarget, ui: CyberConsole | None = None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)

        if ui:
            ui.scan_header(target.host, self.name)

        # Run analyses in parallel
        tasks = [
            self._analyze_headers(target, result, ui),
            self._analyze_ssl(target, result, ui),
            self._detect_waf(target, result, ui),
            self._detect_tech(target, result, ui),
        ]
        if self.scan_subdomains:
            tasks.append(self._enumerate_subdomains(target, result, ui))

        await asyncio.gather(*tasks, return_exceptions=True)

        if ui:
            ui.scan_summary(result)

        return result

    async def _analyze_headers(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Analyze HTTP response headers for security issues."""
        if ui:
            ui.section("HTTP Headers")

        try:
            session = await self.get_session()
            async with session.get(target.url) as resp:
                headers = dict(resp.headers)
                result.headers = headers

                # Check missing security headers
                for h in SECURITY_HEADERS:
                    if h not in headers:
                        result.vulns.append(VulnInfo(
                            title=f"Missing header: {h}",
                            severity="low",
                            description=f"The security header '{h}' is not set.",
                            remediation=f"Add the '{h}' header to HTTP responses.",
                        ))
                        if ui:
                            ui.warning("MISSING", h)

                # Check info leak headers
                for h in INFO_LEAK_HEADERS:
                    if h in headers:
                        result.vulns.append(VulnInfo(
                            title=f"Information disclosure: {h}",
                            severity="info",
                            description=f"Header '{h}: {headers[h]}' reveals server info.",
                            remediation=f"Remove or obfuscate the '{h}' header.",
                        ))
                        if ui:
                            ui.info("LEAK", f"{h}: {headers[h]}")

                if ui:
                    ui.headers_table(headers)

        except Exception as e:
            if ui:
                ui.error("ERROR", f"Header analysis failed: {e}")

    async def _analyze_ssl(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Analyze SSL/TLS certificate and configuration."""
        if ui:
            ui.section("SSL/TLS Analysis")

        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_running_loop()

            def _get_ssl_info():
                with socket.create_connection((target.host, 443), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target.host) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()

                        info = SSLInfo(
                            version=version or "",
                            cipher=cipher[0] if cipher else "",
                            bits=cipher[2] if cipher and len(cipher) > 2 else 0,
                        )

                        if cert:
                            issuer = cert.get("issuer", ())
                            subject = cert.get("subject", ())
                            info.issuer = _flatten_cert_field(issuer)
                            info.subject = _flatten_cert_field(subject)
                            info.not_before = cert.get("notBefore", "")
                            info.not_after = cert.get("notAfter", "")

                            # Extract SANs
                            san = cert.get("subjectAltName", ())
                            info.san = [v for _, v in san]

                        return info

            ssl_info = await loop.run_in_executor(None, _get_ssl_info)
            result.ssl = ssl_info

            if ui:
                ui.ssl_panel(ssl_info)

            # Check for weak TLS
            weak_versions = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
            if ssl_info.version in weak_versions:
                result.vulns.append(VulnInfo(
                    title=f"Weak TLS version: {ssl_info.version}",
                    severity="high",
                    description=f"Server supports {ssl_info.version} which is deprecated.",
                    remediation="Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
                ))

        except Exception as e:
            if ui:
                ui.info("SSL", f"Not available or failed: {e}")

    async def _detect_waf(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Detect Web Application Firewalls."""
        try:
            session = await self.get_session()
            async with session.get(target.url) as resp:
                headers_str = str(resp.headers).lower()
                body = await resp.text()
                body_lower = body.lower()

                for waf_name, signatures in WAF_SIGNATURES.items():
                    if any(sig in headers_str or sig in body_lower for sig in signatures):
                        result.waf = waf_name
                        if ui:
                            ui.warning("WAF", f"Detected: {waf_name}")
                        return

                if ui:
                    ui.info("WAF", "None detected")

        except Exception:
            pass

    async def _detect_tech(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Detect technologies from headers and HTML content."""
        try:
            session = await self.get_session()
            async with session.get(target.url) as resp:
                headers_str = str(resp.headers).lower()
                body = await resp.text()
                body_lower = body.lower()

                seen = set()
                for pattern, location, tech in TECH_PATTERNS:
                    source = headers_str if location == "header" else body_lower
                    if re.search(pattern, source, re.IGNORECASE) and tech not in seen:
                        result.technologies.append(tech)
                        seen.add(tech)

                if ui and result.technologies:
                    ui.tech_list(result.technologies)

        except Exception:
            pass

    async def _enumerate_subdomains(
        self, target: ScanTarget, result: ScanResult, ui: CyberConsole | None
    ):
        """Bruteforce subdomains via async DNS resolution."""
        if ui:
            ui.section("Subdomain Enumeration")

        found: list[SubdomainInfo] = []

        async def _check(sub: str):
            async with self._semaphore:
                fqdn = f"{sub}.{target.host}"
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
                task_id = progress.add_task("Enumerating subdomains", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        else:
            await asyncio.gather(*tasks)

        result.subdomains = found

        # Check for potential subdomain takeover
        if found:
            await self._check_takeover(found, result, ui)

        if ui:
            ui.subdomain_table(found)

    async def _check_takeover(
        self, subdomains: list[SubdomainInfo], result: ScanResult, ui: CyberConsole | None
    ):
        """Check subdomains for potential takeover via dangling CNAMEs."""
        if ui:
            ui.section("Subdomain Takeover Check")

        # Services known to be vulnerable to subdomain takeover
        takeover_cnames = [
            "amazonaws.com", "cloudfront.net", "heroku.com", "herokuapp.com",
            "ghost.io", "pantheon.io", "zendesk.com", "readme.io",
            "surge.sh", "bitbucket.io", "ghost.org", "helpjuice.com",
            "helpscoutdocs.com", "s3.amazonaws.com", "shopify.com",
            "statuspage.io", "tumblr.com", "wordpress.com",
            "smugmug.com", "strikingly.com", "uptimerobot.com",
            "cargocollective.com", "feedpress.me", "freshdesk.com",
            "github.io", "acquia-test.co", "proposify.com",
            "simplebooklet.com", "tave.com", "teamwork.com",
            "thinkific.com", "uservoice.com", "vend.com",
            "webflow.io", "wishpond.com", "aftership.com",
            "aha.io", "animaapp.com", "azure-api.net",
            "azurewebsites.net", "cloudapp.net",
        ]

        # Error messages indicating unclaimed resources
        takeover_signatures = [
            "NoSuchBucket", "There isn't a GitHub Pages site here",
            "Heroku | No such app", "No settings were found for this company",
            "is not a registered InCloud YouTrack",
            "The thing you were looking for is no longer here",
            "project not found", "do you want to register",
        ]

        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5

        loop = asyncio.get_running_loop()

        for sub in subdomains:
            try:
                # Check CNAME
                answers = await loop.run_in_executor(
                    None, lambda s=sub.subdomain: resolver.resolve(s, "CNAME")
                )
                for rdata in answers:
                    cname = rdata.to_text().rstrip(".")
                    # Check if CNAME points to a vulnerable service
                    for vuln_cname in takeover_cnames:
                        if cname.endswith(vuln_cname):
                            # Try to fetch the page and check for error signatures
                            try:
                                session = await self.get_session()
                                async with session.get(f"http://{sub.subdomain}", allow_redirects=True) as resp:
                                    body = await resp.text()
                                    for sig in takeover_signatures:
                                        if sig.lower() in body.lower():
                                            result.vulns.append(VulnInfo(
                                                title=f"Subdomain takeover: {sub.subdomain}",
                                                severity="high",
                                                description=f"CNAME {cname} points to unclaimed {vuln_cname} resource.",
                                                evidence=sig,
                                                remediation="Remove the dangling CNAME record or claim the resource.",
                                            ))
                                            if ui:
                                                ui.error("TAKEOVER", f"{sub.subdomain} -> {cname} (VULNERABLE)")
                                            break
                                    else:
                                        if ui:
                                            ui.info("CNAME", f"{sub.subdomain} -> {cname}")
                            except Exception:
                                # Can't reach it - possibly vulnerable
                                result.vulns.append(VulnInfo(
                                    title=f"Possible subdomain takeover: {sub.subdomain}",
                                    severity="medium",
                                    description=f"CNAME {cname} points to {vuln_cname} but the resource is unreachable.",
                                    remediation="Investigate and remove the dangling CNAME if the resource is unclaimed.",
                                ))
                                if ui:
                                    ui.warning("POSSIBLE", f"{sub.subdomain} -> {cname} (unreachable)")
                            break
            except (Exception,):
                pass


def _flatten_cert_field(field_tuple: tuple) -> str:
    """Flatten a certificate field tuple into a readable string."""
    parts = []
    for entry in field_tuple:
        if isinstance(entry, tuple):
            for k, v in entry:
                parts.append(f"{k}={v}")
        else:
            parts.append(str(entry))
    return ", ".join(parts)
