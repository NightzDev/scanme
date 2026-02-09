"""CLI entry point — argparse subcommands + interactive mode."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time

from scanme import __version__
from scanme.core.models import ScanResult
from scanme.ui.console import CyberConsole
from scanme.utils.network import parse_ports, resolve_target, validate_target

# Lazy module imports to keep startup fast
MODULE_MAP = {
    "netscan": "scanme.modules.netscan:NetScanner",
    "webscan": "scanme.modules.webscan:WebScanner",
    "dnsscan": "scanme.modules.dnsscan:DNSScanner",
    "recon": "scanme.modules.recon:ReconScanner",
    "wpscan": "scanme.modules.wpscan:WPScanner",
    "dirbust": "scanme.modules.dirbust:DirBuster",
    "cmsdetect": "scanme.modules.cmsdetect:CMSDetector",
}


def _load_module(name: str):
    """Lazily import and instantiate a scan module."""
    path = MODULE_MAP[name]
    module_path, class_name = path.rsplit(":", 1)
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanme",
        description="ScanMe - Cybersecurity Reconnaissance & Scanning Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run without arguments for interactive mode.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"scanme {__version__}")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (debug logging)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (errors only)")
    parser.add_argument("--proxy", type=str, default=None, help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument(
        "--output", choices=["console", "json", "report"], default="console",
        help="Output format (default: console)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Global timeout in seconds")
    parser.add_argument("--concurrency", type=int, default=200, help="Max concurrent connections")
    parser.add_argument("--retries", type=int, default=2, help="Retry count for failed requests")

    sub = parser.add_subparsers(dest="command")

    # -- netscan -----------------------------------------------------------
    ns = sub.add_parser("netscan", help="Port scan + banner grab + service fingerprint")
    ns.add_argument("target", help="Host, IP, or URL to scan")
    ns.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g. 1-1024, 80,443)")
    ns.add_argument("--quick", action="store_true", help="Scan top 100 ports only")
    ns.add_argument("--full", action="store_true", help="Scan all 65535 ports")
    ns.add_argument("--no-banner", action="store_true", help="Skip banner grabbing")

    # -- webscan -----------------------------------------------------------
    ws = sub.add_parser("webscan", help="Web analysis: headers, SSL, WAF, tech detection")
    ws.add_argument("target", help="Host or URL to scan")
    ws.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")

    # -- dnsscan -----------------------------------------------------------
    ds = sub.add_parser("dnsscan", help="DNS recon: records, zone transfer, subdomain bruteforce")
    ds.add_argument("target", help="Domain to scan")
    ds.add_argument("--no-zone-transfer", action="store_true", help="Skip zone transfer test")
    ds.add_argument("--no-bruteforce", action="store_true", help="Skip subdomain bruteforce")

    # -- recon -------------------------------------------------------------
    rc = sub.add_parser("recon", help="WHOIS + reverse DNS + IP info")
    rc.add_argument("target", help="Host or IP to scan")

    # -- wpscan ------------------------------------------------------------
    wp = sub.add_parser("wpscan", help="WordPress scanner")
    wp.add_argument("target", help="WordPress site URL")
    wp.add_argument(
        "--enum", default="plugins,users,themes",
        help="What to enumerate (comma-separated: plugins,users,themes)",
    )

    # -- dirbust -----------------------------------------------------------
    db = sub.add_parser("dirbust", help="Directory & file bruteforce")
    db.add_argument("target", help="Target URL")
    db.add_argument("-w", "--wordlist", default=None, help="Custom wordlist file path")
    db.add_argument("-x", "--extensions", default="", help="File extensions to test (e.g. php,html,txt)")
    db.add_argument("-s", "--status-codes", default="200,301,302,403", help="Status codes to consider found")

    # -- cmsdetect ---------------------------------------------------------
    cm = sub.add_parser("cmsdetect", help="Detect CMS: WordPress, Joomla, Drupal, etc.")
    cm.add_argument("target", help="Target URL")

    # -- fullscan ----------------------------------------------------------
    fs = sub.add_parser("fullscan", help="Run all scan modules")
    fs.add_argument("target", help="Host or URL to scan")
    fs.add_argument("--quick", action="store_true", help="Use quick port scan")

    return parser


def _common_kwargs(args: argparse.Namespace) -> dict:
    """Extract common engine kwargs from parsed args."""
    return {
        "concurrency": args.concurrency,
        "timeout": args.timeout,
        "retries": args.retries,
        "proxy": args.proxy,
    }


async def _run_scan(args: argparse.Namespace, ui: CyberConsole):
    """Dispatch to the appropriate scan module."""
    cmd = args.command
    target_raw = args.target

    if not validate_target(target_raw):
        ui.error("ERROR", f"Invalid target: {target_raw}")
        sys.exit(1)

    results: list[ScanResult] = []
    common = _common_kwargs(args)

    if cmd == "netscan":
        port_range = (1, 100) if args.quick else (1, 65535) if args.full else parse_ports(args.ports)
        target = resolve_target(target_raw, port_range)

        Scanner = _load_module("netscan")
        async with Scanner(**common, grab_banners=not args.no_banner) as scanner:
            results.append(await scanner.run(target, ui))

    elif cmd == "webscan":
        target = resolve_target(target_raw)
        Scanner = _load_module("webscan")
        async with Scanner(**common, scan_subdomains=args.subdomains) as scanner:
            results.append(await scanner.run(target, ui))

    elif cmd == "dnsscan":
        target = resolve_target(target_raw)
        Scanner = _load_module("dnsscan")
        async with Scanner(
            **common,
            zone_transfer=not args.no_zone_transfer,
            bruteforce=not args.no_bruteforce,
        ) as scanner:
            results.append(await scanner.run(target, ui))

    elif cmd == "recon":
        target = resolve_target(target_raw)
        Scanner = _load_module("recon")
        async with Scanner(**common) as scanner:
            results.append(await scanner.run(target, ui))

    elif cmd == "wpscan":
        target = resolve_target(target_raw)
        enums = args.enum.split(",")
        Scanner = _load_module("wpscan")
        async with Scanner(
            **common,
            enum_plugins="plugins" in enums,
            enum_users="users" in enums,
            enum_themes="themes" in enums,
        ) as scanner:
            results.append(await scanner.run(target, ui))

    elif cmd == "dirbust":
        target = resolve_target(target_raw)
        extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]
        status_codes = [int(c.strip()) for c in args.status_codes.split(",")]
        Scanner = _load_module("dirbust")
        async with Scanner(
            **common,
            wordlist_path=args.wordlist,
            extensions=extensions,
            status_codes=status_codes,
        ) as scanner:
            results.append(await scanner.run(target, ui))

    elif cmd == "cmsdetect":
        target = resolve_target(target_raw)
        Scanner = _load_module("cmsdetect")
        async with Scanner(**common) as scanner:
            results.append(await scanner.run(target, ui))

    elif cmd == "fullscan":
        port_range = (1, 100) if args.quick else (1, 1024)
        target = resolve_target(target_raw, port_range)

        modules = ["cmsdetect", "netscan", "webscan", "dnsscan", "recon"]
        for mod_name in modules:
            Scanner = _load_module(mod_name)
            kwargs = dict(common)
            if mod_name == "netscan":
                kwargs["grab_banners"] = True
            elif mod_name == "webscan":
                kwargs["scan_subdomains"] = True
            async with Scanner(**kwargs) as scanner:
                results.append(await scanner.run(target, ui))

    # Save report if requested
    if args.output == "report" and results:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"scanme_report_{timestamp}.json"
        combined = [r.to_dict() for r in results]
        with open(filename, "w") as f:
            json.dump(combined, f, indent=2, default=str)
        ui.success("SAVED", f"Report: {filename}")


def _interactive_mode(ui: CyberConsole):
    """Interactive menu when no arguments are given."""
    ui.banner()

    menu = """
[bright_cyan]  [1][/] Network Scan    [bright_magenta](port scan + banner + fingerprint)[/]
[bright_cyan]  [2][/] Web Scan        [bright_magenta](headers + SSL + WAF + tech)[/]
[bright_cyan]  [3][/] DNS Scan        [bright_magenta](records + zone transfer + subdomains)[/]
[bright_cyan]  [4][/] Recon           [bright_magenta](WHOIS + reverse DNS + IP info)[/]
[bright_cyan]  [5][/] WordPress Scan  [bright_magenta](version + plugins + users + vulns)[/]
[bright_cyan]  [6][/] Dir Bruteforce  [bright_magenta](directory & file enumeration)[/]
[bright_cyan]  [7][/] CMS Detect      [bright_magenta](WordPress, Joomla, Drupal, etc.)[/]
[bright_cyan]  [8][/] Full Scan       [bright_magenta](all modules)[/]
[bright_cyan]  [0][/] Exit
"""
    ui._console.print(menu)

    try:
        choice = input("\033[36m  Choose an option: \033[0m").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    cmd_map = {
        "1": "netscan",
        "2": "webscan",
        "3": "dnsscan",
        "4": "recon",
        "5": "wpscan",
        "6": "dirbust",
        "7": "cmsdetect",
        "8": "fullscan",
        "0": None,
    }

    cmd = cmd_map.get(choice)
    if cmd is None:
        if choice != "0":
            ui.error("ERROR", "Invalid option")
        return

    try:
        target = input("\033[36m  Target: \033[0m").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not target or not validate_target(target):
        ui.error("ERROR", f"Invalid target: {target}")
        return

    # Build a minimal namespace for _run_scan
    args = argparse.Namespace(
        command=cmd,
        target=target,
        timeout=10.0,
        concurrency=200,
        retries=2,
        proxy=None,
        output="console",
        ports="1-1024",
        quick=False,
        full=False,
        no_banner=False,
        subdomains=True,
        no_zone_transfer=False,
        no_bruteforce=False,
        enum="plugins,users,themes",
        wordlist=None,
        extensions="",
        status_codes="200,301,302,403",
    )

    asyncio.run(_run_scan(args, ui))


def run():
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    verbose = getattr(args, "verbose", False)
    quiet = getattr(args, "quiet", False)
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")
    elif quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.WARNING)

    no_color = getattr(args, "no_color", False)
    output_fmt = getattr(args, "output", "console")
    json_mode = output_fmt == "json"

    ui = CyberConsole(no_color=no_color, json_mode=json_mode)

    if args.command is None:
        _interactive_mode(ui)
    else:
        if not json_mode:
            ui.banner()
        asyncio.run(_run_scan(args, ui))
