```
 ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ███╗███████╗
 ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗ ████║██╔════╝
 ███████╗██║     ███████║██╔██╗ ██║██╔████╔██║█████╗
 ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╔╝██║██╔══╝
 ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚═╝ ██║███████╗
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚══════╝
```

**Cybersecurity Reconnaissance & Scanning Toolkit**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-132%20passed-brightgreen.svg)]()

---

Async-first reconnaissance toolkit with 8 scan modules, 34+ CMS fingerprints, cyberpunk terminal UI, and full proxy/Tor support. Built for authorized pentesting and security research.

## Features

| Module | Command | What it does |
|--------|---------|-------------|
| **Network Scan** | `netscan` | Async port scan (top 100 → full 65535), banner grabbing, service fingerprinting |
| **Web Scan** | `webscan` | Security headers, SSL/TLS analysis, WAF detection (8 WAFs), tech fingerprint, subdomain enum + takeover check |
| **DNS Scan** | `dnsscan` | A/AAAA/MX/NS/TXT/SOA/CNAME/SRV records, zone transfer (AXFR), subdomain bruteforce, reverse DNS |
| **Recon** | `recon` | WHOIS lookup, reverse DNS, IP resolution |
| **WordPress** | `wpscan` | Version detection, plugin enum (50+), user enum (REST API + author archives), theme detection, security checks |
| **Dir Bruteforce** | `dirbust` | Async directory/file enumeration with 80+ built-in paths, custom extensions, sensitive file detection |
| **CMS Detect** | `cmsdetect` | 34 platforms with tier-weighted scoring, cookie analysis, version extraction, mutual-exclusion logic |
| **Full Scan** | `fullscan` | Runs all modules sequentially on one target |

### CMS Detection Coverage

**CMS:** WordPress, Joomla, Drupal, Ghost, PrestaShop, TYPO3, ConcreteCMS, Craft CMS, Umbraco, Kentico, SilverStripe, MediaWiki, Moodle
**E-commerce:** Magento, Shopify, OpenCart, WooCommerce
**Hosted:** Squarespace, Wix, Webflow
**SSG/Frontend:** Hugo, Jekyll, Gatsby, Next.js, Nuxt.js
**Frameworks:** Laravel, Django, Flask, Ruby on Rails, ASP.NET, Express.js, Spring
**Forums:** phpBB, Discourse

## Installation

```bash
# Clone
git clone https://github.com/NightzDev/scanme.git
cd scanme

# Install
pip install -e .

# Or with dev dependencies (pytest, coverage)
pip install -e ".[dev]"
```

**Requirements:** Python 3.10+

## Usage

### CLI Mode

```bash
# Port scan (quick — top 100 ports)
scanme netscan example.com --quick

# Port scan (full range with banners)
scanme netscan example.com --full

# Port scan (custom range)
scanme netscan example.com -p 80,443,8080

# Web analysis with subdomain enumeration
scanme webscan example.com --subdomains

# DNS reconnaissance
scanme dnsscan example.com

# WHOIS + reverse DNS
scanme recon example.com

# WordPress scanner
scanme wpscan example.com --enum plugins,users,themes

# Directory bruteforce with extensions
scanme dirbust example.com -x php,html,txt

# CMS detection
scanme cmsdetect example.com

# Full scan (all modules)
scanme fullscan example.com
```

### Interactive Mode

```bash
# Run without arguments for cyberpunk menu
scanme
```

### Global Options

```bash
# JSON output (for pipelines)
scanme netscan example.com --output json

# Save report to file
scanme webscan example.com --output report

# Through Tor/proxy
scanme webscan example.com --proxy socks5://127.0.0.1:9050

# Custom timeout and concurrency
scanme netscan example.com --timeout 5 --concurrency 500

# Verbose / quiet
scanme dnsscan example.com -v
scanme netscan example.com -q
```

## Project Structure

```
scanme/
├── pyproject.toml
├── scanme/
│   ├── __init__.py          # version
│   ├── __main__.py          # entry point
│   ├── cli.py               # argparse + interactive mode
│   ├── core/
│   │   ├── engine.py        # AsyncScanEngine base class
│   │   └── models.py        # ScanTarget, ScanResult, PortInfo, VulnInfo, etc.
│   ├── modules/
│   │   ├── netscan.py       # port scan + banner + fingerprint
│   │   ├── webscan.py       # headers + SSL + WAF + tech + subdomains
│   │   ├── dnsscan.py       # DNS records + zone transfer + bruteforce
│   │   ├── recon.py         # WHOIS + reverse DNS
│   │   ├── wpscan.py        # WordPress scanner
│   │   ├── dirbust.py       # directory/file bruteforce
│   │   └── cmsdetect.py     # CMS detection (34 platforms)
│   ├── ui/
│   │   └── console.py       # Rich-based cyberpunk UI
│   └── utils/
│       └── network.py       # target resolution, validation, port utils
└── tests/
    ├── test_cli.py           # 29 tests — parser + flags
    ├── test_models.py        # 16 tests — data models
    ├── test_modules.py       # 55 tests — all modules + CMS engine
    └── test_network.py       # 14 tests — network utils
```

## Architecture

All scan modules inherit from `AsyncScanEngine` and implement `run(target, ui) -> ScanResult`:

```python
from scanme.core.engine import AsyncScanEngine
from scanme.core.models import ScanResult, ScanTarget

class MyScanner(AsyncScanEngine):
    name = "myscanner"

    async def run(self, target: ScanTarget, ui=None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)
        session = await self.get_session()  # aiohttp with retry + proxy
        # ... your scan logic ...
        return result
```

Key design decisions:
- **Async-first** — `asyncio` + `aiohttp` for high-concurrency I/O
- **Semaphore-controlled** — configurable concurrency limits per module
- **Proxy-native** — SOCKS5/HTTP proxy on every request
- **Retry with backoff** — configurable retry count with exponential backoff
- **Zero API keys** — works without any external accounts or keys

## Tests

```bash
# Run all 132 tests
pytest -v

# With coverage
pytest --cov=scanme --cov-report=term-missing

# Specific module
pytest tests/test_modules.py -v
```

## Legal Disclaimer

ScanMe is intended for **authorized security testing and educational purposes only**.

- Only scan systems you **own** or have **explicit written permission** to test.
- Unauthorized scanning may violate computer fraud and abuse laws.
- The authors are not responsible for any misuse of this tool.

See [SECURITY.md](SECURITY.md) for the responsible use policy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code guidelines, and how to add new modules.

## License

[MIT](LICENSE) — NightzDev
