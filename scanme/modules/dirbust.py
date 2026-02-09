"""Directory & File Bruteforce — async directory/file enumeration."""

from __future__ import annotations

import asyncio

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import ScanResult, ScanTarget, VulnInfo
from scanme.ui.console import CyberConsole

# Default wordlist of common directories and files
DEFAULT_WORDLIST = [
    # Directories
    "admin", "administrator", "login", "wp-admin", "wp-login", "cpanel",
    "dashboard", "panel", "manage", "manager", "control",
    "api", "api/v1", "api/v2", "graphql", "rest", "swagger", "docs",
    "backup", "backups", "bak", "old", "temp", "tmp", "cache",
    "config", "conf", "settings", "setup", "install",
    "upload", "uploads", "media", "files", "images", "img", "static",
    "assets", "css", "js", "scripts", "fonts",
    "test", "testing", "dev", "debug", "staging",
    "private", "secret", "hidden", "internal",
    "database", "db", "sql", "mysql", "phpmyadmin", "adminer",
    "git", "svn", "hg",
    "cgi-bin", "bin", "include", "includes", "lib",
    "vendor", "node_modules", "bower_components",
    "log", "logs", "error", "errors",
    "server-status", "server-info", "status", "health", "info",
    "xmlrpc", "xmlrpc.php", "wp-cron.php",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "humans.txt",
    "favicon.ico", "manifest.json",
    # Files
    ".env", ".env.bak", ".env.local", ".env.production",
    ".git/config", ".git/HEAD", ".gitignore",
    ".htaccess", ".htpasswd",
    "web.config", "Gruntfile.js", "Gulpfile.js", "package.json",
    "composer.json", "composer.lock", "Gemfile",
    "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
    "config.php", "config.php.bak", "config.yml", "config.json",
    "database.yml", "credentials.json",
    "id_rsa", "id_rsa.pub",
    "phpinfo.php", "info.php", "test.php",
    "error_log", "debug.log", "access.log",
    "dump.sql", "backup.sql", "db.sql",
    "README.md", "CHANGELOG.md", "LICENSE",
    "Dockerfile", "docker-compose.yml",
    "Makefile", "Rakefile", "Procfile",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    ".well-known/security.txt",
]


class DirBuster(AsyncScanEngine):
    """Async directory and file bruteforce scanner."""

    name = "dirbust"

    def __init__(
        self,
        concurrency: int = 100,
        timeout: float = 10.0,
        retries: int = 2,
        proxy: str | None = None,
        wordlist_path: str | None = None,
        extensions: list[str] | None = None,
        status_codes: list[int] | None = None,
    ):
        super().__init__(concurrency=concurrency, timeout=timeout, retries=retries, proxy=proxy)
        self.extensions = extensions or []
        self.status_codes = set(status_codes or [200, 301, 302, 403])
        self._wordlist: list[str] = []

        if wordlist_path:
            try:
                with open(wordlist_path) as f:
                    self._wordlist = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except FileNotFoundError:
                self._wordlist = DEFAULT_WORDLIST
        else:
            self._wordlist = DEFAULT_WORDLIST

    async def run(self, target: ScanTarget, ui: CyberConsole | None = None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)
        base_url = target.url.rstrip("/")

        if ui:
            ui.scan_header(target.host, "Directory Bruteforce")
            ui.section("Scanning")

        # Build URL list: base paths + paths with extensions
        urls: list[tuple[str, str]] = []
        for word in self._wordlist:
            path = f"/{word.lstrip('/')}"
            urls.append((f"{base_url}{path}", path))
            for ext in self.extensions:
                ext = ext.lstrip(".")
                urls.append((f"{base_url}{path}.{ext}", f"{path}.{ext}"))

        found: list[dict] = []
        session = await self.get_session()

        async def _check(url: str, path: str):
            async with self._semaphore:
                try:
                    async with session.get(url, allow_redirects=False, proxy=self.proxy) as resp:
                        if resp.status in self.status_codes:
                            size = resp.content_length or 0
                            entry = {
                                "path": path,
                                "status": resp.status,
                                "size": size,
                                "url": url,
                            }
                            found.append(entry)

                            if ui and not ui.json_mode:
                                status_color = "bright_green" if resp.status == 200 else "bright_yellow" if resp.status in (301, 302) else "bright_red"
                                ui._console.print(f"  [{status_color}][{resp.status}][/] {path}  [dim]({size} bytes)[/]")

                            # Flag sensitive findings
                            sensitive = [".env", ".git", ".htpasswd", "config.php", "wp-config",
                                         "id_rsa", "dump.sql", "backup.sql", "credentials", "debug.log"]
                            for s in sensitive:
                                if s in path.lower() and resp.status == 200:
                                    result.vulns.append(VulnInfo(
                                        title=f"Sensitive file exposed: {path}",
                                        severity="high",
                                        description=f"The file {path} is publicly accessible (HTTP {resp.status}).",
                                        remediation="Remove the file or restrict access.",
                                    ))
                                    break
                except (Exception,):
                    pass

        tasks = [_check(url, path) for url, path in urls]

        if ui and not ui.json_mode:
            with ui.progress() as progress:
                task_id = progress.add_task(f"Testing {len(urls)} paths", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        else:
            await asyncio.gather(*tasks)

        # Sort by status code
        found.sort(key=lambda x: (x["status"], x["path"]))
        result.extra["found_paths"] = found

        if ui:
            if found:
                ui.section(f"Found {len(found)} paths")
                # Show results table
                from rich.table import Table
                table = Table(
                    title="Discovered Paths",
                    title_style="bright_magenta",
                    border_style="bright_cyan",
                    padding=(0, 1),
                )
                table.add_column("STATUS", min_width=6)
                table.add_column("PATH", style="white")
                table.add_column("SIZE", style="dim white", justify="right")

                for entry in found:
                    sc = entry["status"]
                    style = "bright_green" if sc == 200 else "bright_yellow" if sc in (301, 302) else "bright_red"
                    from rich.text import Text
                    table.add_row(
                        Text(str(sc), style=style),
                        entry["path"],
                        f"{entry['size']}B",
                    )
                ui._console.print(table)

            if result.vulns:
                ui.vuln_panel(result.vulns)
            ui.scan_summary(result)

        return result
