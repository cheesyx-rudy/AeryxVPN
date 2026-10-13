import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
import blocklist_filter


class BlocklistFilterTests(unittest.TestCase):
    def test_parse_ipv4_ipv6_and_cidr(self):
        got = blocklist_filter.parse_networks(
            "# comment\n8.8.8.8\n1.1.1.0/24\n2606:4700::/32\ninvalid\n"
        )
        self.assertEqual(
            {item.with_prefixlen for item in got},
            {"8.8.8.8/32", "1.1.1.0/24", "2606:4700::/32"},
        )

    def test_matches_direct_ip_against_subnet(self):
        networks = blocklist_filter.parse_networks("8.8.8.0/24\n")
        index = blocklist_filter.build_network_index(networks)
        self.assertEqual(blocklist_filter.find_blocked_ips("8.8.8.8", index), ["8.8.8.8"])
        self.assertEqual(blocklist_filter.find_blocked_ips("9.9.9.9", index), [])

    def test_empty_cache_and_url_skips_without_error(self):
        with tempfile.TemporaryDirectory() as temp:
            networks, status = blocklist_filter.load_networks("", Path(temp) / "cache.txt")
        self.assertEqual(networks, [])
        self.assertEqual(status, "disabled_no_url")

    def test_non_https_url_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                blocklist_filter.load_networks("http://example.com/list.txt", Path(temp) / "cache.txt")


if __name__ == "__main__":
    unittest.main()
