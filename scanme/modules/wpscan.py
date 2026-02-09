"""WordPress Scanner — version, themes, plugins, users, security checks."""

from __future__ import annotations

import asyncio
import re

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import ScanResult, ScanTarget, VulnInfo
from scanme.ui.console import CyberConsole

# Top WordPress plugins to check
WP_PLUGINS = [
    "akismet", "jetpack", "wordfence", "yoast-seo", "contact-form-7",
    "woocommerce", "elementor", "classic-editor", "wpforms-lite",
    "really-simple-ssl", "updraftplus", "wp-super-cache", "w3-total-cache",
    "all-in-one-seo-pack", "google-analytics-for-wordpress",
    "wp-mail-smtp", "duplicate-post", "redirection", "tablepress",
    "wordpress-importer", "regenerate-thumbnails", "tinymce-advanced",
    "wp-multibyte-patch", "limit-login-attempts-reloaded",
    "loginizer", "sucuri-scanner", "ithemes-security-pro",
    "wp-smushit", "autoptimize", "async-javascript",
    "broken-link-checker", "better-wp-security", "backwpup",
    "google-sitemap-generator", "all-in-one-wp-migration",
    "custom-post-type-ui", "advanced-custom-fields",
    "shortcodes-ultimate", "nextgen-gallery", "wp-optimize",
    "mailchimp-for-wp", "ninja-forms", "formidable",
    "beaver-builder-lite-version", "brizy", "starter-templates",
    "astra-sites", "royal-elementor-addons", "essential-addons-for-elementor-lite",
    "jetsticky-for-elementor", "premium-addons-for-elementor",
]



class WPScanner(AsyncScanEngine):
    """WordPress-specific vulnerability and enumeration scanner."""

    name = "wpscan"

    def __init__(
        self,
        concurrency: int = 50,
        timeout: float = 10.0,
        retries: int = 2,
        proxy: str | None = None,
        enum_plugins: bool = True,
        enum_users: bool = True,
        enum_themes: bool = True,
    ):
        super().__init__(concurrency=concurrency, timeout=timeout, retries=retries, proxy=proxy)
        self.enum_plugins = enum_plugins
        self.enum_users = enum_users
        self.enum_themes = enum_themes

    async def run(self, target: ScanTarget, ui: CyberConsole | None = None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)
        base_url = target.url.rstrip("/")

        if ui:
            ui.scan_header(target.host, "WordPress Scanner")

        # Phase 0: Detect if it's actually WordPress
        is_wp = await self._detect_wordpress(base_url, ui)
        if not is_wp:
            if ui:
                ui.error("WPSCAN", "Target does not appear to be WordPress")
            return result

        # Run all enumeration in parallel
        tasks = [
            self._detect_version(base_url, result, ui),
            self._check_security(base_url, result, ui),
        ]
        if self.enum_plugins:
            tasks.append(self._enumerate_plugins(base_url, result, ui))
        if self.enum_users:
            tasks.append(self._enumerate_users(base_url, result, ui))
        if self.enum_themes:
            tasks.append(self._detect_theme(base_url, result, ui))

        await asyncio.gather(*tasks, return_exceptions=True)

        if ui:
            if result.vulns:
                ui.vuln_panel(result.vulns)
            ui.scan_summary(result)

        return result

    async def _detect_wordpress(self, base_url: str, ui: CyberConsole | None) -> bool:
        """Check if the target is running WordPress."""
        session = await self.get_session()

        indicators = [
            f"{base_url}/wp-login.php",
            f"{base_url}/wp-admin/",
            f"{base_url}/wp-content/",
        ]

        for url in indicators:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status in (200, 301, 302, 403):
                        if ui:
                            ui.success("DETECT", "WordPress detected")
                        return True
            except Exception:
                continue

        # Check homepage for wp-content references
        try:
            async with session.get(base_url) as resp:
                body = await resp.text()
                if "wp-content" in body or "wp-includes" in body:
                    if ui:
                        ui.success("DETECT", "WordPress detected (via content)")
                    return True
        except Exception:
            pass

        return False

    async def _detect_version(
        self, base_url: str, result: ScanResult, ui: CyberConsole | None
    ):
        """Detect WordPress version from multiple sources."""
        if ui:
            ui.section("Version Detection")

        session = await self.get_session()
        version = None

        # Method 1: Meta generator tag
        try:
            async with session.get(base_url) as resp:
                body = await resp.text()
                match = re.search(
                    r'<meta\s+name="generator"\s+content="WordPress\s+([\d.]+)"',
                    body, re.IGNORECASE,
                )
                if match:
                    version = match.group(1)
        except Exception:
            pass

        # Method 2: Readme file
        if not version:
            try:
                async with session.get(f"{base_url}/readme.html") as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        match = re.search(r"Version\s+([\d.]+)", body)
                        if match:
                            version = match.group(1)
                            result.vulns.append(VulnInfo(
                                title="WordPress readme.html exposed",
                                severity="low",
                                description="The readme.html file is publicly accessible.",
                                remediation="Remove or restrict access to readme.html.",
                            ))
            except Exception:
                pass

        # Method 3: RSS feed
        if not version:
            try:
                async with session.get(f"{base_url}/feed/") as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        match = re.search(r"generator>https://wordpress\.org/\?v=([\d.]+)", body)
                        if match:
                            version = match.group(1)
            except Exception:
                pass

        if version:
            result.extra["wp_version"] = version
            result.technologies.append(f"WordPress {version}")
            if ui:
                ui.success("VERSION", f"WordPress {version}")
        else:
            if ui:
                ui.info("VERSION", "Could not determine version")

    async def _enumerate_plugins(
        self, base_url: str, result: ScanResult, ui: CyberConsole | None
    ):
        """Enumerate installed plugins by probing known paths."""
        if ui:
            ui.section("Plugin Enumeration")

        session = await self.get_session()
        found_plugins: list[str] = []

        async def _check_plugin(plugin: str):
            async with self._semaphore:
                url = f"{base_url}/wp-content/plugins/{plugin}/"
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status in (200, 301, 302, 403):
                            found_plugins.append(plugin)
                            if ui:
                                ui.success("PLUGIN", plugin)
                except Exception:
                    pass

        tasks = [_check_plugin(p) for p in WP_PLUGINS]

        if ui and not ui.json_mode:
            with ui.progress() as progress:
                task_id = progress.add_task(
                    f"Testing {len(WP_PLUGINS)} plugins", total=len(tasks)
                )
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        else:
            await asyncio.gather(*tasks)

        if found_plugins:
            result.extra["wp_plugins"] = found_plugins
            result.technologies.extend(f"WP Plugin: {p}" for p in found_plugins)

    async def _enumerate_users(
        self, base_url: str, result: ScanResult, ui: CyberConsole | None
    ):
        """Enumerate WordPress users via REST API and author archives."""
        if ui:
            ui.section("User Enumeration")

        session = await self.get_session()
        users: list[dict] = []

        # Method 1: REST API
        try:
            async with session.get(f"{base_url}/wp-json/wp/v2/users") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for user in data:
                        user_info = {
                            "id": user.get("id"),
                            "name": user.get("name"),
                            "slug": user.get("slug"),
                        }
                        users.append(user_info)
                        if ui:
                            ui.success("USER", f"ID:{user_info['id']} — {user_info['name']} ({user_info['slug']})")

                    if users:
                        result.vulns.append(VulnInfo(
                            title="User enumeration via REST API",
                            severity="medium",
                            description=f"WordPress REST API exposes {len(users)} user(s).",
                            remediation="Disable the users endpoint or require authentication.",
                        ))
        except Exception:
            pass

        # Method 2: Author archive bruteforce
        if not users:
            for i in range(1, 11):
                try:
                    async with session.get(
                        f"{base_url}/?author={i}", allow_redirects=False
                    ) as resp:
                        if resp.status in (301, 302):
                            location = resp.headers.get("Location", "")
                            match = re.search(r"/author/([^/]+)", location)
                            if match:
                                slug = match.group(1)
                                users.append({"id": i, "slug": slug, "name": slug})
                                if ui:
                                    ui.success("USER", f"ID:{i} — {slug}")
                except Exception:
                    continue

        if users:
            result.extra["wp_users"] = users

    async def _detect_theme(
        self, base_url: str, result: ScanResult, ui: CyberConsole | None
    ):
        """Detect active WordPress theme."""
        if ui:
            ui.section("Theme Detection")

        session = await self.get_session()

        try:
            async with session.get(base_url) as resp:
                body = await resp.text()

                # Look for theme references in HTML
                match = re.search(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", body)
                if match:
                    theme = match.group(1)
                    result.extra["wp_theme"] = theme
                    result.technologies.append(f"WP Theme: {theme}")
                    if ui:
                        ui.success("THEME", theme)

                    # Try to read theme's style.css for version info
                    css_url = f"{base_url}/wp-content/themes/{theme}/style.css"
                    try:
                        async with session.get(css_url) as css_resp:
                            if css_resp.status == 200:
                                css = await css_resp.text()
                                ver_match = re.search(r"Version:\s*([\d.]+)", css[:2000])
                                if ver_match:
                                    if ui:
                                        ui.info("THEME VER", ver_match.group(1))
                    except Exception:
                        pass
                else:
                    if ui:
                        ui.info("THEME", "Could not detect active theme")

        except Exception as e:
            if ui:
                ui.error("THEME", str(e))

    async def _check_security(
        self, base_url: str, result: ScanResult, ui: CyberConsole | None
    ):
        """Check common WordPress security misconfigurations."""
        if ui:
            ui.section("Security Checks")

        session = await self.get_session()

        checks = [
            (f"{base_url}/xmlrpc.php", "XML-RPC enabled", "medium",
             "XML-RPC is enabled, allowing brute-force and DDoS amplification.",
             "Disable XML-RPC or restrict access."),
            (f"{base_url}/wp-config.php.bak", "wp-config backup exposed", "critical",
             "A backup of wp-config.php is publicly accessible.",
             "Remove backup files from the web root."),
            (f"{base_url}/wp-content/debug.log", "Debug log exposed", "high",
             "WordPress debug log is publicly accessible.",
             "Remove debug.log and disable WP_DEBUG_LOG in production."),
            (f"{base_url}/wp-content/uploads/", "Upload directory listing", "low",
             "The uploads directory allows directory listing.",
             "Disable directory listing in web server config."),
            (f"{base_url}/.wp-config.php.swp", "Editor swap file", "high",
             "An editor swap file may contain wp-config credentials.",
             "Remove swap/temporary files from the web root."),
        ]

        for url, title, severity, desc, fix in checks:
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    is_vuln = False
                    if title == "XML-RPC enabled":
                        # XML-RPC returns 405 for GET but means it exists
                        is_vuln = resp.status in (200, 405)
                    elif "directory listing" in title:
                        if resp.status == 200:
                            body = await resp.text()
                            is_vuln = "Index of" in body or "Parent Directory" in body
                    else:
                        is_vuln = resp.status == 200

                    if is_vuln:
                        result.vulns.append(VulnInfo(
                            title=title,
                            severity=severity,
                            description=desc,
                            remediation=fix,
                        ))
                        if ui:
                            style = "error" if severity in ("high", "critical") else "warning"
                            getattr(ui, style)(severity.upper(), title)
                    else:
                        if ui:
                            ui.info("OK", f"{title} — not found")
            except Exception:
                pass
