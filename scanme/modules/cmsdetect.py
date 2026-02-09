"""CMS Detection — tier-weighted fingerprinting for 34+ platforms.

Detects CMS, frameworks, e-commerce, SSG, forums, and hosted platforms
using a multi-tier confidence scoring system with mutual-exclusion logic,
cookie analysis, and automatic version extraction.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from enum import IntEnum

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import ScanResult, ScanTarget
from scanme.ui.console import CyberConsole


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class CheckTier(IntEnum):
    """Reliability tier for a detection check."""
    DEFINITIVE = 1   # Meta generator, unique header — highest trust
    STRONG = 2       # Unique cookies, CMS-specific file content
    MODERATE = 3     # CMS-specific paths with content matching
    WEAK = 4         # Generic paths (/admin/) with status-only checks


TIER_MULTIPLIERS: dict[int, float] = {
    CheckTier.DEFINITIVE: 3.0,
    CheckTier.STRONG: 2.0,
    CheckTier.MODERATE: 1.0,
    CheckTier.WEAK: 0.5,
}

MINIMUM_REPORT_SCORE = 60
WEAK_PENALTY_FACTOR = 0.8  # reduce 80% of WEAK points for competing CMS


@dataclass
class DetectionCheck:
    """A single fingerprint check."""
    url_path: str
    search_in: str       # "body", "headers", "status", "cookies"
    pattern: str
    base_score: int
    tier: CheckTier
    description: str = ""


@dataclass
class CMSProfile:
    """Complete detection profile for a CMS / framework."""
    name: str
    category: str                                    # cms, framework, ecommerce, ssg, forum, hosted
    checks: list[DetectionCheck]
    version_patterns: list[tuple[str, str, str]] = field(default_factory=list)  # (path, search_in, regex)
    exclusive_group: str = ""


# ---------------------------------------------------------------------------
# CMS Profiles — 34 platforms
# ---------------------------------------------------------------------------

D = CheckTier.DEFINITIVE
S = CheckTier.STRONG
M = CheckTier.MODERATE
W = CheckTier.WEAK

CMS_PROFILES: dict[str, CMSProfile] = {}


def _p(name: str, category: str, checks: list[DetectionCheck],
       version_patterns: list[tuple[str, str, str]] | None = None,
       exclusive_group: str = "") -> None:
    """Register a CMS profile."""
    CMS_PROFILES[name] = CMSProfile(
        name=name, category=category, checks=checks,
        version_patterns=version_patterns or [], exclusive_group=exclusive_group,
    )


# ── CMS ───────────────────────────────────────────────────────────────────

_p("WordPress", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']WordPress', 95, D, "meta generator"),
    DetectionCheck("/", "headers", r"X-Powered-By:.*WordPress", 90, D, "X-Powered-By header"),
    DetectionCheck("/", "body", r"wp-content/|wp-includes/", 80, S, "wp-content/wp-includes in HTML"),
    DetectionCheck("/wp-login.php", "status", "200|302|301", 70, S, "wp-login.php exists"),
    DetectionCheck("/", "cookies", r"wordpress_|wp-settings", 85, S, "WordPress cookies"),
    DetectionCheck("/wp-json/", "status", "200|301", 60, M, "WP REST API"),
    DetectionCheck("/xmlrpc.php", "status", "200|405", 50, M, "XML-RPC endpoint"),
    DetectionCheck("/wp-content/", "status", "200|403|301", 55, M, "wp-content directory"),
    DetectionCheck("/wp-includes/", "status", "200|403", 45, M, "wp-includes directory"),
], version_patterns=[
    ("/", "body", r'content=["\']WordPress\s+([\d.]+)'),
    ("/readme.html", "body", r"Version\s+([\d.]+)"),
    ("/feed/", "body", r"\?v=([\d.]+)"),
    ("/", "body", r"[?&]ver=([\d.]+)"),
], exclusive_group="php_cms")

_p("Joomla", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Joomla', 95, D, "meta generator"),
    DetectionCheck("/", "cookies", r"joomla_", 80, S, "Joomla cookie"),
    DetectionCheck("/media/jui/", "status", "200|403", 65, S, "Joomla UI media"),
    DetectionCheck("/components/com_content/", "status", "200|403", 60, M, "com_content component"),
    DetectionCheck("/language/en-GB/", "status", "200|403", 50, M, "Joomla language dir"),
    DetectionCheck("/administrator/", "status", "200|301|302", 30, W, "admin panel (generic)"),
    DetectionCheck("/configuration.php", "status", "200|403", 40, W, "configuration.php"),
], version_patterns=[
    ("/", "body", r'content=["\']Joomla!\s*([\d.]+)'),
    ("/administrator/manifests/files/joomla.xml", "body", r"<version>([\d.]+)</version>"),
], exclusive_group="php_cms")

_p("Drupal", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Drupal', 95, D, "meta generator"),
    DetectionCheck("/", "headers", r"X-Drupal-Cache|X-Generator.*Drupal", 90, D, "Drupal header"),
    DetectionCheck("/core/misc/drupal.js", "status", "200", 80, S, "drupal.js (core)"),
    DetectionCheck("/", "body", r"Drupal\.settings|drupal\.js", 75, S, "Drupal.settings in body"),
    DetectionCheck("/", "cookies", r"Drupal\.|SESS[a-f0-9]", 70, S, "Drupal session cookie"),
    DetectionCheck("/misc/drupal.js", "status", "200", 65, M, "drupal.js (legacy)"),
    DetectionCheck("/sites/default/", "status", "200|403", 50, M, "sites/default dir"),
    DetectionCheck("/CHANGELOG.txt", "status", "200", 55, M, "CHANGELOG.txt exists"),
    DetectionCheck("/user/login", "status", "200|302", 30, W, "user login (generic)"),
], version_patterns=[
    ("/", "body", r'content=["\']Drupal\s+([\d.]+)'),
    ("/", "headers", r"X-Generator.*Drupal\s+([\d.]+)"),
    ("/CHANGELOG.txt", "body", r"Drupal\s+([\d.]+)"),
], exclusive_group="php_cms")

_p("Ghost", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Ghost', 95, D, "meta generator"),
    DetectionCheck("/ghost/api/", "status", "200|301|401", 75, S, "Ghost API endpoint"),
    DetectionCheck("/", "body", r"ghost-(?:url|post|content)", 65, S, "ghost- CSS/class pattern"),
    DetectionCheck("/ghost/", "status", "200|301|302", 50, M, "Ghost admin panel"),
], version_patterns=[
    ("/", "body", r'content=["\']Ghost\s+([\d.]+)'),
], exclusive_group="node_cms")

_p("PrestaShop", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']PrestaShop', 95, D, "meta generator"),
    DetectionCheck("/", "cookies", r"PrestaShop", 80, S, "PrestaShop cookie"),
    DetectionCheck("/", "body", r"prestashop|/modules/ps_", 65, S, "PrestaShop in body"),
    DetectionCheck("/modules/", "status", "200|403", 30, W, "modules dir (generic)"),
    DetectionCheck("/admin-dev/", "status", "200|302|403", 35, W, "admin-dev panel"),
], version_patterns=[
    ("/", "body", r'content=["\']PrestaShop\s+([\d.]+)'),
], exclusive_group="php_cms")

_p("TYPO3", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']TYPO3', 95, D, "meta generator"),
    DetectionCheck("/", "headers", r"X-TYPO3", 90, D, "X-TYPO3 header"),
    DetectionCheck("/typo3/", "status", "200|302|403", 70, S, "TYPO3 backend"),
    DetectionCheck("/", "body", r"typo3conf/|typo3temp/|EXT:", 65, S, "TYPO3 paths in body"),
    DetectionCheck("/typo3/sysext/", "status", "200|403", 50, M, "TYPO3 sysext"),
], version_patterns=[
    ("/", "body", r'content=["\']TYPO3 CMS\s+([\d.]+)'),
    ("/typo3/sysext/core/ext_emconf.php", "body", r"'version'\s*=>\s*'([\d.]+)'"),
], exclusive_group="php_cms")

_p("ConcreteCMS", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\'](?:concrete5|ConcreteCMS)', 95, D, "meta generator"),
    DetectionCheck("/", "cookies", r"ccm_", 80, S, "ConcreteCMS cookie"),
    DetectionCheck("/", "body", r"/concrete/|ccm-page|ccm_token", 65, S, "ConcreteCMS in body"),
    DetectionCheck("/index.php/dashboard", "status", "200|302", 50, M, "ConcreteCMS dashboard"),
], version_patterns=[
    ("/", "body", r'content=["\']concrete(?:5| CMS)\s+([\d.]+)'),
], exclusive_group="php_cms")

_p("Craft CMS", "cms", [
    DetectionCheck("/", "headers", r"X-Powered-By:.*Craft CMS", 95, D, "X-Powered-By Craft"),
    DetectionCheck("/", "cookies", r"CraftSessionId|CRAFT_CSRF", 80, S, "Craft CMS cookies"),
    DetectionCheck("/", "body", r"cpresources/|/actions/", 60, S, "Craft CMS paths in body"),
    DetectionCheck("/admin/login", "status", "200|302", 30, W, "admin login (generic)"),
], version_patterns=[
    ("/", "headers", r"X-Powered-By:.*Craft CMS\s+([\d.]+)"),
], exclusive_group="php_cms")

_p("Umbraco", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Umbraco', 95, D, "meta generator"),
    DetectionCheck("/", "headers", r"X-Umbraco-Version", 90, D, "X-Umbraco-Version header"),
    DetectionCheck("/", "cookies", r"UMB_UCONTEXT|UMB_SESSION", 80, S, "Umbraco cookies"),
    DetectionCheck("/umbraco/", "status", "200|302", 65, S, "Umbraco backend"),
    DetectionCheck("/umbraco/login", "status", "200|302", 50, M, "Umbraco login"),
], version_patterns=[
    ("/", "headers", r"X-Umbraco-Version:\s*([\d.]+)"),
    ("/", "body", r'content=["\']Umbraco\s+([\d.]+)'),
], exclusive_group="dotnet_cms")

_p("Kentico", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Kentico', 95, D, "meta generator"),
    DetectionCheck("/", "cookies", r"CMSPreferredCulture|CMSCsrfCookie", 80, S, "Kentico cookies"),
    DetectionCheck("/", "body", r"CMSPages/|Kentico", 60, S, "Kentico paths in body"),
], version_patterns=[
    ("/", "body", r'content=["\']Kentico\s+([\d.]+)'),
], exclusive_group="dotnet_cms")

_p("SilverStripe", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']SilverStripe', 95, D, "meta generator"),
    DetectionCheck("/", "headers", r"X-SilverStripe", 90, D, "X-SilverStripe header"),
    DetectionCheck("/Security/login", "status", "200|302", 65, S, "SilverStripe login"),
    DetectionCheck("/", "body", r"silverstripe|SilverStripe", 55, M, "SilverStripe in body"),
], version_patterns=[
    ("/", "body", r'content=["\']SilverStripe\s+([\d.]+)'),
], exclusive_group="php_cms")

_p("MediaWiki", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']MediaWiki', 95, D, "meta generator"),
    DetectionCheck("/api.php", "status", "200", 75, S, "MediaWiki API"),
    DetectionCheck("/", "body", r"mediawiki|wgPageName|mw-", 65, S, "MediaWiki patterns in body"),
    DetectionCheck("/Special:Version", "status", "200|302", 55, M, "Special:Version page"),
], version_patterns=[
    ("/", "body", r'content=["\']MediaWiki\s+([\d.]+)'),
    ("/api.php?action=siteinfo&format=json", "body", r'"generator"\s*:\s*"MediaWiki\s+([\d.]+)"'),
])

_p("Moodle", "cms", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Moodle', 95, D, "meta generator"),
    DetectionCheck("/", "cookies", r"MoodleSession", 85, S, "Moodle session cookie"),
    DetectionCheck("/", "body", r"moodle|M\.core|yui/build", 60, S, "Moodle patterns in body"),
    DetectionCheck("/login/index.php", "status", "200|302", 50, M, "Moodle login page"),
], version_patterns=[
    ("/", "body", r'content=["\']Moodle\s+([\d.]+)'),
])


# ── E-commerce ────────────────────────────────────────────────────────────

_p("Magento", "ecommerce", [
    DetectionCheck("/", "body", r"Mage\.Cookies|mage/cookies", 90, D, "Mage.Cookies in body"),
    DetectionCheck("/", "headers", r"X-Magento-", 90, D, "X-Magento header"),
    DetectionCheck("/", "cookies", r"frontend=|adminhtml=", 75, S, "Magento cookies"),
    DetectionCheck("/skin/frontend/", "status", "200|403|301", 60, S, "Magento skin dir"),
    DetectionCheck("/", "body", r"static/version|/static/frontend/", 55, S, "Magento static paths"),
    DetectionCheck("/pub/static/", "status", "200|403", 45, M, "Magento pub/static"),
    DetectionCheck("/downloader/", "status", "200|302|403", 40, M, "Magento downloader"),
    DetectionCheck("/admin/", "status", "200|302", 20, W, "admin panel (generic)"),
], version_patterns=[
    ("/magento_version", "body", r"Magento/([\d.]+)"),
    ("/", "body", r"magentoVersion.*?[\"']([\d.]+)[\"']"),
], exclusive_group="php_ecommerce")

_p("Shopify", "ecommerce", [
    DetectionCheck("/", "headers", r"X-ShopId|x-shopify", 95, D, "Shopify header"),
    DetectionCheck("/", "body", r"Shopify\.theme|cdn\.shopify\.com", 85, S, "Shopify in body"),
    DetectionCheck("/", "cookies", r"_shopify_s|_shopify_y", 80, S, "Shopify cookies"),
], exclusive_group="hosted_ecommerce")

_p("OpenCart", "ecommerce", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']OpenCart', 95, D, "meta generator"),
    DetectionCheck("/", "cookies", r"OCSESSID", 85, S, "OpenCart session cookie"),
    DetectionCheck("/", "body", r"catalog/view/|route=common/home", 60, S, "OpenCart paths in body"),
    DetectionCheck("/admin/", "status", "200|302", 20, W, "admin panel (generic)"),
], version_patterns=[
    ("/", "body", r'content=["\']OpenCart\s+([\d.]+)'),
], exclusive_group="php_ecommerce")

_p("WooCommerce", "ecommerce", [
    DetectionCheck("/", "body", r"woocommerce|wc-ajax|wp-content/plugins/woocommerce", 80, S, "WooCommerce in body"),
    DetectionCheck("/", "body", r"wc-block-|wc_add_to_cart", 65, S, "WooCommerce blocks/cart"),
    DetectionCheck("/wp-json/wc/", "status", "200|301|401", 70, M, "WooCommerce REST API"),
], version_patterns=[
    ("/", "body", r"woocommerce.*?ver=([\d.]+)"),
])


# ── Hosted platforms ──────────────────────────────────────────────────────

_p("Squarespace", "hosted", [
    DetectionCheck("/", "headers", r"X-ServedBy.*squarespace", 95, D, "X-ServedBy Squarespace"),
    DetectionCheck("/", "body", r"squarespace\.com|static\.squarespace", 75, S, "Squarespace in body"),
    DetectionCheck("/", "cookies", r"ss_cid|ss_cpvisit", 70, S, "Squarespace cookies"),
], exclusive_group="hosted_platform")

_p("Wix", "hosted", [
    DetectionCheck("/", "headers", r"X-Wix", 95, D, "X-Wix header"),
    DetectionCheck("/", "body", r"wix\.com|wixstatic\.com|X-Wix", 80, S, "Wix in body"),
    DetectionCheck("/", "cookies", r"_wixCIDX|_wix_browser_sess", 70, S, "Wix cookies"),
], exclusive_group="hosted_platform")

_p("Webflow", "hosted", [
    DetectionCheck("/", "headers", r"X-Powered-By:.*Webflow", 95, D, "X-Powered-By Webflow"),
    DetectionCheck("/", "body", r"webflow\.com|w-nav|w-container", 75, S, "Webflow in body"),
    DetectionCheck("/", "cookies", r"wf_", 60, S, "Webflow cookies"),
], exclusive_group="hosted_platform")


# ── Static Site Generators / Frontend ─────────────────────────────────────

_p("Hugo", "ssg", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Hugo', 95, D, "meta generator"),
    DetectionCheck("/", "body", r"hugo-|powered by Hugo", 60, S, "Hugo patterns in body"),
], version_patterns=[
    ("/", "body", r'content=["\']Hugo\s+([\d.]+)'),
])

_p("Jekyll", "ssg", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Jekyll', 95, D, "meta generator"),
    DetectionCheck("/", "body", r"jekyll|Powered by Jekyll", 60, S, "Jekyll patterns"),
], version_patterns=[
    ("/", "body", r'content=["\']Jekyll\s+v?([\d.]+)'),
])

_p("Gatsby", "ssg", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Gatsby', 95, D, "meta generator"),
    DetectionCheck("/", "body", r'id=["\']___gatsby["\']|gatsby-', 80, S, "Gatsby root div / classes"),
    DetectionCheck("/", "body", r"/page-data/|gatsby-chunk", 65, S, "Gatsby page-data paths"),
], version_patterns=[
    ("/", "body", r'content=["\']Gatsby\s+([\d.]+)'),
])

_p("Next.js", "ssg", [
    DetectionCheck("/", "body", r'id=["\']__next["\']', 80, S, "__next root div"),
    DetectionCheck("/", "body", r"/_next/static|/_next/data", 75, S, "_next paths in body"),
    DetectionCheck("/", "headers", r"x-nextjs|x-middleware", 85, S, "Next.js headers"),
    DetectionCheck("/", "body", r"__NEXT_DATA__", 70, S, "NEXT_DATA script"),
])

_p("Nuxt.js", "ssg", [
    DetectionCheck("/", "body", r'id=["\']__nuxt["\']|__NUXT__', 80, S, "__nuxt root div / data"),
    DetectionCheck("/", "body", r"/_nuxt/", 75, S, "_nuxt paths in body"),
    DetectionCheck("/", "headers", r"x-nuxt", 85, S, "Nuxt headers"),
])


# ── Frameworks ────────────────────────────────────────────────────────────

_p("Laravel", "framework", [
    DetectionCheck("/", "cookies", r"laravel_session", 95, D, "laravel_session cookie"),
    DetectionCheck("/", "headers", r"X-Powered-By:.*Laravel", 90, D, "X-Powered-By Laravel"),
    DetectionCheck("/", "cookies", r"XSRF-TOKEN", 50, M, "XSRF-TOKEN cookie"),
], exclusive_group="php_framework")

_p("Django", "framework", [
    DetectionCheck("/", "body", r"csrfmiddlewaretoken", 90, D, "csrfmiddlewaretoken (unique)"),
    DetectionCheck("/", "cookies", r"csrftoken", 75, S, "Django csrftoken cookie"),
    DetectionCheck("/admin/", "body", r"Django administration|django", 60, S, "Django admin page"),
    DetectionCheck("/admin/", "status", "200|302", 20, W, "admin panel (generic)"),
], exclusive_group="python_framework")

_p("Flask", "framework", [
    DetectionCheck("/", "headers", r"Server:.*Werkzeug", 90, D, "Werkzeug server header"),
    DetectionCheck("/", "cookies", r"session=ey", 60, S, "Flask-style JWT session"),
    DetectionCheck("/", "headers", r"X-Powered-By:.*Flask", 85, S, "Flask header"),
], exclusive_group="python_framework")

_p("Ruby on Rails", "framework", [
    DetectionCheck("/", "headers", r"X-Runtime", 60, S, "X-Runtime header"),
    DetectionCheck("/", "cookies", r"_session_id=", 55, S, "Rails session cookie"),
    DetectionCheck("/", "body", r'name=["\']csrf-param["\'].*?name=["\']csrf-token["\']', 70, S, "Rails CSRF pattern"),
    DetectionCheck("/", "headers", r"X-Request-Id", 35, M, "X-Request-Id header"),
], exclusive_group="ruby_framework")

_p("ASP.NET", "framework", [
    DetectionCheck("/", "headers", r"X-AspNet-Version|X-Powered-By:.*ASP\.NET", 95, D, "ASP.NET header"),
    DetectionCheck("/", "cookies", r"ASP\.NET_SessionId|\.AspNetCore\.", 80, S, "ASP.NET session cookie"),
    DetectionCheck("/", "body", r"__VIEWSTATE|__EVENTVALIDATION", 75, S, "__VIEWSTATE in body"),
    DetectionCheck("/", "body", r"\.aspx|\.ashx|\.asmx", 45, M, ".aspx extensions in body"),
], version_patterns=[
    ("/", "headers", r"X-AspNet-Version:\s*([\d.]+)"),
    ("/", "headers", r"X-AspNetMvc-Version:\s*([\d.]+)"),
], exclusive_group="dotnet_framework")

_p("Express.js", "framework", [
    DetectionCheck("/", "headers", r"X-Powered-By:.*Express", 95, D, "X-Powered-By Express"),
    DetectionCheck("/", "cookies", r"connect\.sid", 60, S, "Express session cookie"),
], exclusive_group="node_framework")

_p("Spring", "framework", [
    DetectionCheck("/", "headers", r"X-Application-Context", 80, S, "Spring context header"),
    DetectionCheck("/", "cookies", r"JSESSIONID", 50, M, "JSESSIONID cookie"),
    DetectionCheck("/actuator/health", "status", "200", 75, S, "Spring Actuator health"),
    DetectionCheck("/", "body", r"spring-|springframework", 55, M, "Spring patterns in body"),
], exclusive_group="java_framework")


# ── Forums ────────────────────────────────────────────────────────────────

_p("phpBB", "forum", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']phpBB', 95, D, "meta generator"),
    DetectionCheck("/", "body", r"Powered by.*phpBB|phpbb", 70, S, "phpBB in body"),
    DetectionCheck("/", "cookies", r"phpbb_", 80, S, "phpBB cookies"),
    DetectionCheck("/viewforum.php", "status", "200", 60, S, "viewforum.php exists"),
    DetectionCheck("/memberlist.php", "status", "200", 45, M, "memberlist.php exists"),
], version_patterns=[
    ("/", "body", r'content=["\']phpBB\s+([\d.]+)'),
], exclusive_group="php_forum")

_p("Discourse", "forum", [
    DetectionCheck("/", "body", r'<meta name=["\']generator["\'] content=["\']Discourse', 95, D, "meta generator"),
    DetectionCheck("/", "body", r"discourse-|Discourse\.", 70, S, "Discourse in body"),
    DetectionCheck("/", "cookies", r"_forum_session|_t=", 65, S, "Discourse cookies"),
    DetectionCheck("/categories.json", "status", "200", 60, S, "Discourse categories API"),
], version_patterns=[
    ("/", "body", r'content=["\']Discourse\s+([\d.]+)'),
], exclusive_group="node_forum")


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class CMSDetector(AsyncScanEngine):
    """Detect CMS, frameworks, and web platforms with tier-weighted scoring."""

    name = "cmsdetect"

    def __init__(
        self,
        concurrency: int = 200,
        timeout: float = 10.0,
        retries: int = 2,
        proxy: str | None = None,
        min_confidence: str = "low",
        extract_versions: bool = True,
    ):
        super().__init__(concurrency=concurrency, timeout=timeout, retries=retries, proxy=proxy)
        self.min_confidence = min_confidence
        self.extract_versions = extract_versions

    async def run(self, target: ScanTarget, ui: CyberConsole | None = None) -> ScanResult:
        result = ScanResult(module=self.name, target=target.host)
        base_url = target.url.rstrip("/")

        if ui:
            ui.scan_header(target.host, "CMS Detection")

        session = await self.get_session()

        # -- Page cache: (status, headers, body, cookies) --
        page_cache: dict[str, tuple[int, dict, str, dict]] = {}

        async def _fetch(path: str) -> tuple[int, dict, str, dict]:
            if path in page_cache:
                return page_cache[path]
            url = f"{base_url}{path}"
            try:
                async with session.get(url, allow_redirects=False, proxy=self.proxy) as resp:
                    status = resp.status
                    headers = dict(resp.headers)
                    body = ""
                    if status in (200, 301, 302, 403, 405):
                        raw = await resp.content.read(102_400)  # cap 100 KB
                        body = raw.decode(errors="replace")
                    cookies = {k: v.value for k, v in resp.cookies.items()}
                    page_cache[path] = (status, headers, body, cookies)
                    return status, headers, body, cookies
            except Exception:
                page_cache[path] = (0, {}, "", {})
                return 0, {}, "", {}

        # -- Phase 1: collect unique paths and pre-fetch in parallel --
        all_paths: set[str] = {"/", "/robots.txt"}
        for prof in CMS_PROFILES.values():
            for chk in prof.checks:
                all_paths.add(chk.url_path)
            for vp_path, _, _ in prof.version_patterns:
                all_paths.add(vp_path)

        if ui:
            ui.section(f"Fingerprinting ({len(all_paths)} paths)")

        await asyncio.gather(*[_fetch(p) for p in all_paths], return_exceptions=True)

        # -- Phase 2: tier-weighted scoring --
        scores: dict[str, float] = {}
        raw_scores: dict[str, float] = {}
        evidence_map: dict[str, list[str]] = {}
        tier_points: dict[str, dict[int, float]] = {}
        has_definitive: dict[str, bool] = {}

        for prof_name, prof in CMS_PROFILES.items():
            score = 0.0
            raw = 0.0
            evidence: list[str] = []
            tpts: dict[int, float] = {1: 0, 2: 0, 3: 0, 4: 0}
            defn = False

            for chk in prof.checks:
                status, headers, body, cookies = await _fetch(chk.url_path)
                matched = _match_check(chk, status, headers, body, cookies)

                if matched:
                    weighted = chk.base_score * TIER_MULTIPLIERS[chk.tier]
                    raw += chk.base_score
                    score += weighted
                    tpts[chk.tier] += weighted
                    desc = chk.description or chk.pattern[:30]
                    evidence.append(f"{chk.url_path} ({chk.search_in}: {desc})")
                    if chk.tier == CheckTier.DEFINITIVE:
                        defn = True

            if score > 0:
                scores[prof_name] = score
                raw_scores[prof_name] = raw
                evidence_map[prof_name] = evidence
                tier_points[prof_name] = tpts
                has_definitive[prof_name] = defn

        # -- Phase 3: mutual exclusion (negative scoring) --
        strong_names = {
            n for n in scores
            if has_definitive.get(n) or tier_points.get(n, {}).get(2, 0) > 100
        }

        for strong_name in strong_names:
            strong_prof = CMS_PROFILES[strong_name]
            if not strong_prof.exclusive_group:
                continue
            for other_name in list(scores):
                if other_name == strong_name:
                    continue
                other_prof = CMS_PROFILES[other_name]
                if other_prof.exclusive_group == strong_prof.exclusive_group:
                    weak_pts = tier_points.get(other_name, {}).get(4, 0)
                    penalty = weak_pts * WEAK_PENALTY_FACTOR
                    scores[other_name] = max(0, scores[other_name] - penalty)

        # -- Phase 4: filter and assign confidence --
        conf_order = {"definitive": 0, "high": 1, "medium": 2, "low": 3}
        ranked: list[tuple[str, float, str]] = []

        for name, sc in sorted(scores.items(), key=lambda x: -x[1]):
            if sc < MINIMUM_REPORT_SCORE:
                continue

            if has_definitive.get(name):
                conf = "definitive"
            elif sc >= 200:
                conf = "high"
            elif sc >= 120:
                conf = "medium"
            else:
                conf = "low"

            # Apply min_confidence filter
            if conf_order.get(conf, 99) > conf_order.get(self.min_confidence, 3):
                continue

            ranked.append((name, sc, conf))

        # -- Phase 5: version extraction for top candidates --
        versions: dict[str, str | None] = {}
        if self.extract_versions:
            for name, _, _ in ranked[:3]:
                prof = CMS_PROFILES[name]
                versions[name] = await _extract_version(prof, _fetch)

        # -- Phase 6: build results --
        if ranked:
            primary_name, primary_score, primary_conf = ranked[0]
            primary_version = versions.get(primary_name)
            primary_cat = CMS_PROFILES[primary_name].category

            version_str = f" {primary_version}" if primary_version else ""
            result.technologies.append(f"{primary_name}{version_str}")
            result.extra["cms_detected"] = primary_name
            result.extra["cms_confidence"] = primary_conf
            result.extra["cms_version"] = primary_version
            result.extra["cms_category"] = primary_cat
            result.extra["cms_scores"] = {
                n: {
                    "score": int(s),
                    "confidence": c,
                    "version": versions.get(n),
                }
                for n, s, c in ranked
            }

            if ui:
                ui.success(
                    "CMS",
                    f"{primary_name}{version_str} "
                    f"(confidence: {primary_conf}, score: {int(primary_score)})",
                )

                for name, sc, conf in ranked[1:]:
                    ver = versions.get(name)
                    ver_str = f" {ver}" if ver else ""
                    ui.info("ALSO", f"{name}{ver_str} (confidence: {conf}, score: {int(sc)})")

                if evidence_map.get(primary_name):
                    ui.section(f"Evidence for {primary_name}")
                    for ev in evidence_map[primary_name][:12]:
                        ui.info("MATCH", ev)
        else:
            if ui:
                ui.info("CMS", "No CMS detected")

        if ui:
            ui.scan_summary(result)

        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match_check(
    chk: DetectionCheck,
    status: int,
    headers: dict,
    body: str,
    cookies: dict,
) -> bool:
    """Evaluate a single detection check against fetched page data."""
    if chk.search_in == "status":
        valid_codes = [int(c) for c in chk.pattern.split("|")]
        return status in valid_codes

    if chk.search_in == "body":
        return bool(re.search(chk.pattern, body, re.IGNORECASE))

    if chk.search_in == "headers":
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())
        return bool(re.search(chk.pattern, headers_str, re.IGNORECASE))

    if chk.search_in == "cookies":
        cookies_str = " ".join(f"{k}={v}" for k, v in cookies.items())
        return bool(re.search(chk.pattern, cookies_str, re.IGNORECASE))

    return False


async def _extract_version(
    profile: CMSProfile,
    fetch_fn,
) -> str | None:
    """Try to extract version from a CMS profile's version patterns."""
    for vp_path, search_in, pattern in profile.version_patterns:
        status, headers, body, cookies = await fetch_fn(vp_path)
        source = ""
        if search_in == "body":
            source = body
        elif search_in == "headers":
            source = " ".join(f"{k}: {v}" for k, v in headers.items())

        match = re.search(pattern, source, re.IGNORECASE)
        if match:
            try:
                return match.group(1)
            except IndexError:
                continue
    return None
