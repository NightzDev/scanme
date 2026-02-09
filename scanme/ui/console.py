"""Cyberpunk-themed console output using Rich."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from scanme.core.models import PortInfo, VulnInfo, ScanResult

# -- Theme -----------------------------------------------------------------

CYBER_THEME = Theme({
    "cyber.cyan": "bold bright_cyan",
    "cyber.pink": "bold bright_magenta",
    "cyber.green": "bold bright_green",
    "cyber.red": "bold bright_red",
    "cyber.yellow": "bold bright_yellow",
    "cyber.dim": "dim white",
    "cyber.label": "bold bright_cyan",
    "info": "bright_cyan",
    "success": "bright_green",
    "warning": "bright_yellow",
    "error": "bright_red",
    "critical": "bold bright_red",
})

BANNER = r"""
[bright_cyan]
 ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ███╗███████╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗ ████║██╔════╝
 ███████╗██║     ███████║██╔██╗ ██║██╔████╔██║█████╗
 ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╔╝██║██╔══╝
 ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚═╝ ██║███████╗
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚══════╝
[/bright_cyan][bright_magenta]         ╔═══════════════════════════════════╗
         ║  Cybersecurity Recon Toolkit v2.0  ║
         ║          by NightzDev              ║
         ╚═══════════════════════════════════╝[/bright_magenta]
"""

SEVERITY_STYLES = {
    "critical": "bold bright_red",
    "high": "bright_red",
    "medium": "bright_yellow",
    "low": "bright_cyan",
    "info": "dim white",
}


class CyberConsole:
    """Main UI renderer with cyberpunk aesthetics."""

    def __init__(self, no_color: bool = False, json_mode: bool = False):
        self.json_mode = json_mode
        import sys
        # Force UTF-8 output on Windows to avoid legacy codepage issues
        if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        self._console = Console(
            theme=CYBER_THEME,
            no_color=no_color,
            highlight=False,
            force_terminal=True,
        )

    # -- Banners & Headers -------------------------------------------------

    def banner(self):
        if self.json_mode:
            return
        self._console.print(BANNER)

    def scan_header(self, target: str, module: str):
        if self.json_mode:
            return
        self._console.print()
        self._console.print(
            Panel(
                f"[bright_cyan]TARGET:[/] [bold white]{target}[/]",
                title=f"[bright_magenta][ {module.upper()} ][/]",
                border_style="bright_cyan",
                padding=(0, 2),
            )
        )

    def section(self, title: str):
        if self.json_mode:
            return
        self._console.print(f"\n[bright_magenta]{'─' * 3} {title} {'─' * (55 - len(title))}[/]")

    # -- Status Lines ------------------------------------------------------

    def info(self, label: str, message: str):
        if self.json_mode:
            return
        self._console.print(f"  [bright_cyan][{label}][/] {message}")

    def success(self, label: str, message: str):
        if self.json_mode:
            return
        self._console.print(f"  [bright_green][{label}][/] {message}")

    def warning(self, label: str, message: str):
        if self.json_mode:
            return
        self._console.print(f"  [bright_yellow][{label}][/] {message}")

    def error(self, label: str, message: str):
        if self.json_mode:
            return
        self._console.print(f"  [bright_red][{label}][/] {message}")

    # -- Tables ------------------------------------------------------------

    def port_table(self, ports: list[PortInfo]):
        if self.json_mode:
            return
        if not ports:
            self.info("PORTS", "No open ports found")
            return

        table = Table(
            title="Open Ports",
            title_style="bright_magenta",
            border_style="bright_cyan",
            show_lines=False,
            padding=(0, 1),
        )
        table.add_column("PORT", style="bright_green", min_width=8)
        table.add_column("STATE", style="bright_cyan")
        table.add_column("SERVICE", style="bright_magenta")
        table.add_column("VERSION / BANNER", style="white")

        for p in sorted(ports, key=lambda x: x.port):
            version_info = p.version or p.banner[:60] if p.banner else ""
            table.add_row(
                f"{p.port}/tcp",
                p.state,
                p.service,
                version_info,
            )

        self._console.print(table)

    def vuln_panel(self, vulns: list[VulnInfo]):
        if self.json_mode:
            return
        if not vulns:
            self.success("VULNS", "No vulnerabilities detected")
            return

        table = Table(
            title="Vulnerabilities",
            title_style="bright_red",
            border_style="bright_red",
            show_lines=True,
            padding=(0, 1),
        )
        table.add_column("SEV", min_width=8)
        table.add_column("TITLE", style="white")
        table.add_column("DESCRIPTION", style="dim white", max_width=50)

        for v in sorted(vulns, key=lambda x: _sev_order(x.severity)):
            style = SEVERITY_STYLES.get(v.severity, "white")
            table.add_row(
                Text(v.severity.upper(), style=style),
                v.title,
                v.description or "-",
            )

        self._console.print(table)

    def dns_table(self, records: list):
        if self.json_mode:
            return
        if not records:
            self.info("DNS", "No records found")
            return

        table = Table(
            title="DNS Records",
            title_style="bright_magenta",
            border_style="bright_cyan",
            show_lines=False,
            padding=(0, 1),
        )
        table.add_column("TYPE", style="bright_green", min_width=8)
        table.add_column("VALUE", style="white")
        table.add_column("TTL", style="dim white", justify="right")

        for r in records:
            table.add_row(r.record_type, r.value, str(r.ttl))

        self._console.print(table)

    def subdomain_table(self, subdomains: list):
        if self.json_mode:
            return
        if not subdomains:
            return

        table = Table(
            title="Subdomains",
            title_style="bright_magenta",
            border_style="bright_cyan",
            padding=(0, 1),
        )
        table.add_column("SUBDOMAIN", style="bright_green")
        table.add_column("IP", style="white")

        for s in subdomains:
            table.add_row(s.subdomain, s.ip)

        self._console.print(table)

    def whois_panel(self, data: dict):
        if self.json_mode:
            return
        if not data:
            return

        lines: list[str] = []
        for k, v in data.items():
            if v:
                val = ", ".join(v) if isinstance(v, list) else str(v)
                lines.append(f"[bright_cyan]{k}:[/] {val}")

        self._console.print(
            Panel(
                "\n".join(lines),
                title="[bright_magenta][ WHOIS ][/]",
                border_style="bright_cyan",
                padding=(0, 2),
            )
        )

    def headers_table(self, headers: dict):
        if self.json_mode:
            return
        if not headers:
            return

        table = Table(
            title="HTTP Headers",
            title_style="bright_magenta",
            border_style="bright_cyan",
            padding=(0, 1),
        )
        table.add_column("HEADER", style="bright_cyan")
        table.add_column("VALUE", style="white", max_width=60)

        for k, v in headers.items():
            table.add_row(k, str(v))

        self._console.print(table)

    def ssl_panel(self, ssl_info):
        if self.json_mode:
            return
        if not ssl_info:
            return

        d = ssl_info.to_dict() if hasattr(ssl_info, "to_dict") else ssl_info
        lines = [f"[bright_cyan]{k}:[/] {v}" for k, v in d.items() if v]

        self._console.print(
            Panel(
                "\n".join(lines),
                title="[bright_magenta][ SSL/TLS ][/]",
                border_style="bright_cyan",
                padding=(0, 2),
            )
        )

    def tech_list(self, techs: list[str]):
        if self.json_mode:
            return
        if not techs:
            return
        self.section("Technologies Detected")
        for t in techs:
            self._console.print(f"  [bright_green]\u25b8[/] {t}")

    # -- Progress ----------------------------------------------------------

    def progress(self, description: str = "Scanning...") -> Progress:
        return Progress(
            SpinnerColumn("dots", style="bright_cyan"),
            TextColumn("[bright_magenta]{task.description}[/]"),
            BarColumn(bar_width=30, style="bright_cyan", complete_style="bright_green"),
            TextColumn("[bright_cyan]{task.percentage:>3.0f}%[/]"),
            TimeElapsedColumn(),
            console=self._console,
        )

    # -- JSON Output -------------------------------------------------------

    def print_json(self, result: ScanResult):
        print(json.dumps(result.to_dict(), indent=2, default=str))

    # -- Summary -----------------------------------------------------------

    def scan_summary(self, result: ScanResult):
        if self.json_mode:
            self.print_json(result)
            return

        self._console.print(f"\n[bright_cyan]{'═' * 60}[/]")
        self._console.print("[bright_magenta]  SCAN COMPLETE[/]")
        self._console.print(f"[bright_cyan]{'═' * 60}[/]")

        if result.ports:
            self.info("PORTS", f"{len(result.ports)} open")
        if result.dns_records:
            self.info("DNS", f"{len(result.dns_records)} records")
        if result.subdomains:
            self.info("SUBDOMAINS", f"{len(result.subdomains)} found")
        if result.technologies:
            self.info("TECH", f"{len(result.technologies)} detected")
        if result.waf:
            self.warning("WAF", result.waf)

        vuln_count = len(result.vulns)
        if vuln_count:
            self.error("VULNS", f"{vuln_count} detected")
        else:
            self.success("VULNS", "None detected")

        self._console.print()


def _sev_order(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(sev, 5)


# Singleton for easy import
ui = CyberConsole()
