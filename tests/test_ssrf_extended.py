"""
Extended Unit tests for SSRF Protection Engine & Socket Pinning (vcurl/ssrf.py)
"""

import unittest
import socket
from vcurl.ssrf import (
    validate_url,
    is_ip_allowed,
    SSRFError
)


class TestSSRFExtended(unittest.TestCase):

    def test_private_ipv4_range_blocks(self):
        blocked_ips = [
            "127.0.0.1",
            "127.0.0.254",
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.255.254",
            "169.254.169.254", # AWS Cloud Metadata
            "100.64.0.1",     # Carrier-Grade NAT
            "0.0.0.0"
        ]
        for ip in blocked_ips:
            self.assertFalse(is_ip_allowed(ip), f"Failed to block private IP: {ip}")

    def test_private_ipv6_range_blocks(self):
        blocked_v6 = [
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1"
        ]
        for ip in blocked_v6:
            self.assertFalse(is_ip_allowed(ip), f"Failed to block private IPv6: {ip}")

    def test_public_ipv4_allows(self):
        allowed_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "140.82.121.4" # GitHub public IP
        ]
        for ip in allowed_ips:
            self.assertTrue(is_ip_allowed(ip), f"Public IP {ip} was incorrectly blocked.")

    def test_disallowed_schemes(self):
        invalid_urls = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:70",
            "dict://locahost:2628",
            "ftp://example.com/file",
            "javascript:alert(1)"
        ]
        for url in invalid_urls:
            with self.assertRaises(SSRFError):
                validate_url(url)

    def test_dns_resolution_and_socket_pinning(self):
        scheme, host, port, resolved_ips = validate_url("https://api.github.com/issues")
        self.assertEqual(scheme, "https")
        self.assertEqual(host, "api.github.com")
        self.assertEqual(port, 443)
        self.assertGreaterEqual(len(resolved_ips), 1)
        for ip in resolved_ips:
            self.assertTrue(is_ip_allowed(ip))


if __name__ == "__main__":
    unittest.main()
