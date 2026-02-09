"""Smoke tests for scan modules — verifies they instantiate and have correct structure."""

import asyncio
import pytest

from scanme.core.engine import AsyncScanEngine
from scanme.core.models import ScanTarget
from scanme.modules.netscan import NetScanner
from scanme.modules.webscan import WebScanner
from scanme.modules.dnsscan import DNSScanner
from scanme.modules.recon import ReconScanner
from scanme.modules.wpscan import WPScanner
from scanme.modules.dirbust import DirBuster
from scanme.modules.cmsdetect import CMSDetector


ALL_SCANNERS = [NetScanner, WebScanner, DNSScanner, ReconScanner, WPScanner, DirBuster, CMSDetector]


class TestModuleStructure:
    """Verify all modules follow the expected interface."""

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_inherits_from_engine(self, cls):
        assert issubclass(cls, AsyncScanEngine)

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_has_name(self, cls):
        assert hasattr(cls, "name")
        assert isinstance(cls.name, str)
        assert len(cls.name) > 0

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_has_run_method(self, cls):
        assert hasattr(cls, "run")
        assert callable(cls.run)

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_instantiates_with_defaults(self, cls):
        instance = cls()
        assert instance.concurrency > 0
        assert instance.timeout > 0
        assert instance.retries >= 0

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    def test_instantiates_with_custom_params(self, cls):
        instance = cls(concurrency=50, timeout=5.0, retries=3, proxy="http://localhost:8080")
        assert instance.concurrency == 50
        assert instance.timeout == 5.0
        assert instance.retries == 3
        assert instance.proxy == "http://localhost:8080"


class TestModuleNames:
    """Ensure module names are unique and match expected values."""

    def test_unique_names(self):
        names = [cls.name for cls in ALL_SCANNERS]
        assert len(names) == len(set(names)), f"Duplicate module names: {names}"

    def test_expected_names(self):
        names = {cls.name for cls in ALL_SCANNERS}
        expected = {"netscan", "webscan", "dnsscan", "recon", "wpscan", "dirbust", "cmsdetect"}
        assert names == expected


class TestAsyncContextManager:
    """Verify async context manager works for all modules."""

    @pytest.mark.parametrize("cls", ALL_SCANNERS)
    @pytest.mark.asyncio
    async def test_context_manager(self, cls):
        async with cls() as scanner:
            assert scanner is not None
            assert isinstance(scanner, AsyncScanEngine)


class TestNetScannerSpecifics:
    def test_grab_banners_flag(self):
        s = NetScanner(grab_banners=False)
        assert s.grab_banners is False

        s2 = NetScanner(grab_banners=True)
        assert s2.grab_banners is True


class TestWebScannerSpecifics:
    def test_subdomains_flag(self):
        s = WebScanner(scan_subdomains=True)
        assert s.scan_subdomains is True

    def test_custom_wordlist(self):
        s = WebScanner(wordlist=["test", "dev"])
        assert s.wordlist == ["test", "dev"]


class TestDNSScannerSpecifics:
    def test_zone_transfer_flag(self):
        s = DNSScanner(zone_transfer=False)
        assert s.zone_transfer is False

    def test_bruteforce_flag(self):
        s = DNSScanner(bruteforce=False)
        assert s.bruteforce is False


class TestWPScannerSpecifics:
    def test_enum_flags(self):
        s = WPScanner(enum_plugins=False, enum_users=True, enum_themes=False)
        assert s.enum_plugins is False
        assert s.enum_users is True
        assert s.enum_themes is False


class TestDirBusterSpecifics:
    def test_default_wordlist(self):
        s = DirBuster()
        assert len(s._wordlist) > 0

    def test_custom_extensions(self):
        s = DirBuster(extensions=["php", "html"])
        assert s.extensions == ["php", "html"]

    def test_custom_status_codes(self):
        s = DirBuster(status_codes=[200, 404])
        assert s.status_codes == {200, 404}


class TestCMSDetectorSpecifics:
    """Test the overhauled CMS detection engine."""

    def test_default_options(self):
        d = CMSDetector()
        assert d.min_confidence == "low"
        assert d.extract_versions is True

    def test_custom_min_confidence(self):
        d = CMSDetector(min_confidence="high")
        assert d.min_confidence == "high"

    def test_extract_versions_flag(self):
        d = CMSDetector(extract_versions=False)
        assert d.extract_versions is False

    def test_profiles_count(self):
        from scanme.modules.cmsdetect import CMS_PROFILES
        assert len(CMS_PROFILES) >= 30

    def test_all_profiles_have_checks(self):
        from scanme.modules.cmsdetect import CMS_PROFILES
        for name, profile in CMS_PROFILES.items():
            assert len(profile.checks) > 0, f"{name} has no checks"
            assert profile.category in ("cms", "ecommerce", "hosted", "ssg", "framework", "forum"), \
                f"{name} has invalid category: {profile.category}"

    def test_tier_multipliers(self):
        from scanme.modules.cmsdetect import TIER_MULTIPLIERS, CheckTier
        assert CheckTier.DEFINITIVE in TIER_MULTIPLIERS
        assert CheckTier.WEAK in TIER_MULTIPLIERS
        assert TIER_MULTIPLIERS[CheckTier.DEFINITIVE] > TIER_MULTIPLIERS[CheckTier.WEAK]

    def test_match_check_status(self):
        from scanme.modules.cmsdetect import DetectionCheck, CheckTier, _match_check
        chk = DetectionCheck("/", "status", "200|302", 50, CheckTier.MODERATE)
        assert _match_check(chk, 200, {}, "", {}) is True
        assert _match_check(chk, 302, {}, "", {}) is True
        assert _match_check(chk, 404, {}, "", {}) is False

    def test_match_check_body(self):
        from scanme.modules.cmsdetect import DetectionCheck, CheckTier, _match_check
        chk = DetectionCheck("/", "body", r"WordPress", 90, CheckTier.DEFINITIVE)
        assert _match_check(chk, 200, {}, '<meta generator="WordPress 6.4">', {}) is True
        assert _match_check(chk, 200, {}, "<html>nothing here</html>", {}) is False

    def test_match_check_headers(self):
        from scanme.modules.cmsdetect import DetectionCheck, CheckTier, _match_check
        chk = DetectionCheck("/", "headers", r"X-Powered-By:.*Express", 95, CheckTier.DEFINITIVE)
        assert _match_check(chk, 200, {"X-Powered-By": "Express"}, "", {}) is True
        assert _match_check(chk, 200, {"Server": "nginx"}, "", {}) is False

    def test_match_check_cookies(self):
        from scanme.modules.cmsdetect import DetectionCheck, CheckTier, _match_check
        chk = DetectionCheck("/", "cookies", r"laravel_session", 95, CheckTier.DEFINITIVE)
        assert _match_check(chk, 200, {}, "", {"laravel_session": "abc123"}) is True
        assert _match_check(chk, 200, {}, "", {"PHPSESSID": "xyz"}) is False

    def test_profiles_have_valid_search_in(self):
        from scanme.modules.cmsdetect import CMS_PROFILES
        valid = {"body", "headers", "status", "cookies"}
        for name, profile in CMS_PROFILES.items():
            for chk in profile.checks:
                assert chk.search_in in valid, f"{name} check has invalid search_in: {chk.search_in}"


class TestEngineRetry:
    """Test engine base class retry/proxy config."""

    def test_retry_config(self):
        s = NetScanner(retries=5)
        assert s.retries == 5

    def test_proxy_config(self):
        s = NetScanner(proxy="socks5://127.0.0.1:9050")
        assert s.proxy == "socks5://127.0.0.1:9050"

    @pytest.mark.asyncio
    async def test_session_creation(self):
        async with NetScanner() as scanner:
            session = await scanner.get_session()
            assert session is not None
            assert not session.closed
        # After exit, session should be closed
