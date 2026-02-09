"""Tests for scanme.cli parser and flags."""

from scanme.cli import build_parser


class TestParser:
    def setup_method(self):
        self.parser = build_parser()

    def test_no_args_returns_none_command(self):
        args = self.parser.parse_args([])
        assert args.command is None

    def test_version_flag(self):
        import pytest
        with pytest.raises(SystemExit) as exc:
            self.parser.parse_args(["--version"])
        assert exc.value.code == 0

    def test_netscan_basic(self):
        args = self.parser.parse_args(["netscan", "example.com"])
        assert args.command == "netscan"
        assert args.target == "example.com"
        assert args.ports == "1-1024"
        assert args.quick is False
        assert args.full is False
        assert args.no_banner is False

    def test_netscan_quick(self):
        args = self.parser.parse_args(["netscan", "example.com", "--quick"])
        assert args.quick is True

    def test_netscan_full(self):
        args = self.parser.parse_args(["netscan", "example.com", "--full"])
        assert args.full is True

    def test_netscan_custom_ports(self):
        args = self.parser.parse_args(["netscan", "example.com", "-p", "80,443"])
        assert args.ports == "80,443"

    def test_webscan_basic(self):
        args = self.parser.parse_args(["webscan", "example.com"])
        assert args.command == "webscan"
        assert args.subdomains is False

    def test_webscan_subdomains(self):
        args = self.parser.parse_args(["webscan", "example.com", "--subdomains"])
        assert args.subdomains is True

    def test_dnsscan_basic(self):
        args = self.parser.parse_args(["dnsscan", "example.com"])
        assert args.command == "dnsscan"
        assert args.no_zone_transfer is False
        assert args.no_bruteforce is False

    def test_dnsscan_skip_options(self):
        args = self.parser.parse_args(["dnsscan", "example.com", "--no-zone-transfer", "--no-bruteforce"])
        assert args.no_zone_transfer is True
        assert args.no_bruteforce is True

    def test_recon_basic(self):
        args = self.parser.parse_args(["recon", "example.com"])
        assert args.command == "recon"

    def test_wpscan_basic(self):
        args = self.parser.parse_args(["wpscan", "example.com"])
        assert args.command == "wpscan"
        assert args.enum == "plugins,users,themes"

    def test_wpscan_custom_enum(self):
        args = self.parser.parse_args(["wpscan", "example.com", "--enum", "plugins,users"])
        assert args.enum == "plugins,users"

    def test_dirbust_basic(self):
        args = self.parser.parse_args(["dirbust", "example.com"])
        assert args.command == "dirbust"
        assert args.wordlist is None
        assert args.extensions == ""

    def test_dirbust_with_options(self):
        args = self.parser.parse_args(["dirbust", "example.com", "-x", "php,html", "-w", "/tmp/words.txt"])
        assert args.extensions == "php,html"
        assert args.wordlist == "/tmp/words.txt"

    def test_cmsdetect_basic(self):
        args = self.parser.parse_args(["cmsdetect", "example.com"])
        assert args.command == "cmsdetect"

    def test_fullscan_basic(self):
        args = self.parser.parse_args(["fullscan", "example.com"])
        assert args.command == "fullscan"
        assert args.quick is False

    def test_fullscan_quick(self):
        args = self.parser.parse_args(["fullscan", "example.com", "--quick"])
        assert args.quick is True


class TestGlobalFlags:
    def setup_method(self):
        self.parser = build_parser()

    def test_defaults(self):
        args = self.parser.parse_args(["recon", "example.com"])
        assert args.timeout == 10.0
        assert args.concurrency == 200
        assert args.retries == 2
        assert args.proxy is None
        assert args.no_color is False
        assert args.verbose is False
        assert args.quiet is False

    def test_verbose(self):
        args = self.parser.parse_args(["-v", "recon", "example.com"])
        assert args.verbose is True

    def test_quiet(self):
        args = self.parser.parse_args(["-q", "recon", "example.com"])
        assert args.quiet is True

    def test_proxy(self):
        args = self.parser.parse_args(["--proxy", "socks5://127.0.0.1:9050", "recon", "example.com"])
        assert args.proxy == "socks5://127.0.0.1:9050"

    def test_timeout(self):
        args = self.parser.parse_args(["--timeout", "30", "recon", "example.com"])
        assert args.timeout == 30.0

    def test_concurrency(self):
        args = self.parser.parse_args(["--concurrency", "500", "recon", "example.com"])
        assert args.concurrency == 500

    def test_retries(self):
        args = self.parser.parse_args(["--retries", "5", "recon", "example.com"])
        assert args.retries == 5

    def test_output_json(self):
        args = self.parser.parse_args(["--output", "json", "recon", "example.com"])
        assert args.output == "json"

    def test_output_report(self):
        args = self.parser.parse_args(["--output", "report", "recon", "example.com"])
        assert args.output == "report"

    def test_no_color(self):
        args = self.parser.parse_args(["--no-color", "recon", "example.com"])
        assert args.no_color is True
