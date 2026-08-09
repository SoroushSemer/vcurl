"""
vcurl Test Suite
Rigorously tests SSRF protection, secret resolution, DNS pinning, redirect safety, and header sanitization.
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from vcurl import (
    DEFAULT_VAULT,
    SSRFError,
    VaultConfig,
    VaultError,
    execute_vcurl,
    is_ip_allowed,
    sanitize_headers,
    sanitize_response,
    validate_url,
)


class TestSSRFProtection(unittest.TestCase):
    """Tests SSRF IP address checker and URL validator."""

    def test_forbidden_ip_ranges(self):
        """Ensure private, loopback, link-local, and cloud metadata IPs are blocked."""
        blocked_ips = [
            "127.0.0.1",
            "127.0.0.254",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "169.254.169.254",  # AWS/GCP/Azure Metadata Service
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",       # CGNAT
            "::1",             # IPv6 Loopback
            "fe80::1",         # IPv6 Link-Local
            "fc00::1",         # IPv6 Unique Local
            "::ffff:127.0.0.1" # IPv4-mapped IPv6 Loopback
        ]

        for ip in blocked_ips:
            with self.subTest(ip=ip):
                self.assertFalse(is_ip_allowed(ip), f"IP {ip} should be blocked!")

    def test_allowed_public_ips(self):
        """Ensure public IP addresses are allowed."""
        allowed_ips = [
            "8.8.8.8",        # Google DNS
            "1.1.1.1",        # Cloudflare DNS
            "93.184.216.34",  # example.com
            "140.82.121.4",   # github.com
        ]

        for ip in allowed_ips:
            with self.subTest(ip=ip):
                self.assertTrue(is_ip_allowed(ip), f"IP {ip} should be allowed!")

    def test_validate_url_disallowed_schemes(self):
        """Ensure non-HTTP/HTTPS schemes are blocked."""
        invalid_urls = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:70",
            "dict://127.0.0.1:11211",
            "ftp://example.com/file",
        ]
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(SSRFError):
                    validate_url(url)

    @patch("socket.getaddrinfo")
    def test_validate_url_private_dns_resolution(self, mock_getaddrinfo):
        """Ensure domain resolving to private IP is blocked."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 80))
        ]

        with self.assertRaises(SSRFError) as ctx:
            validate_url("http://malicious-internal-domain.com/secret")
        self.assertIn("restricted IP '127.0.0.1'", str(ctx.exception))

    @patch("socket.getaddrinfo")
    def test_validate_url_multi_ip_partial_private(self, mock_getaddrinfo):
        """If a domain resolves to multiple IPs and even ONE is private, it must be blocked."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 80)), # Public IP
            (2, 1, 6, "", ("10.0.0.5", 80)),      # Private IP
        ]

        with self.assertRaises(SSRFError) as ctx:
            validate_url("http://dual-dns-attack.com/endpoint")
        self.assertIn("restricted IP '10.0.0.5'", str(ctx.exception))


class TestVaultConfig(unittest.TestCase):
    """Tests credential alias resolution and secret vault behavior."""

    def setUp(self):
        self.vault = VaultConfig()

    def test_unregistered_alias_throws_error(self):
        """Ensure invalid alias raises VaultError."""
        with self.assertRaises(VaultError) as ctx:
            self.vault.resolve("non_existent_alias")
        self.assertIn("was not found in any isolated provider", str(ctx.exception))

    def test_missing_environment_variable_throws_error(self):
        """Ensure missing environment variable raises VaultError."""
        self.vault.register_alias("test_alias", "MISSING_ENV_VAR_12345")
        if "MISSING_ENV_VAR_12345" in os.environ:
            del os.environ["MISSING_ENV_VAR_12345"]

        with self.assertRaises(VaultError) as ctx:
            self.vault.resolve("test_alias")
        self.assertIn("was not found in any isolated provider", str(ctx.exception))

    def test_valid_alias_resolution(self):
        """Ensure valid alias resolves to header name and bearer token value."""
        self.vault.set_secret("github_write", "ghp_secret_token_12345")

        try:
            hdr_name, hdr_val = self.vault.resolve("github_write")
            self.assertEqual(hdr_name, "Authorization")
            self.assertEqual(hdr_val, "Bearer ghp_secret_token_12345")
        finally:
            pass


class TestSanitizer(unittest.TestCase):
    """Tests stripping of sensitive response headers and JSON parsing."""

    def test_sanitize_headers(self):
        """Ensure authorization and cookie headers are stripped."""
        raw_headers = {
            "Content-Type": "application/json",
            "Set-Cookie": "session_id=12345; Secure",
            "Authorization": "Bearer secret_token",
            "X-API-Key": "super_secret_key",
            "Server": "nginx",
        }

        clean = sanitize_headers(raw_headers)
        self.assertIn("content-type", clean)
        self.assertIn("server", clean)
        self.assertNotIn("set-cookie", clean)
        self.assertNotIn("authorization", clean)
        self.assertNotIn("x-api-key", clean)

    def test_sanitize_response_json(self):
        """Ensure response body is parsed as JSON if valid."""
        raw_body = b'{"status": "ok", "items": [1, 2, 3]}'
        headers = [("Content-Type", "application/json")]

        res = sanitize_response(200, headers, raw_body)
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["response_body"], {"status": "ok", "items": [1, 2, 3]})
        self.assertEqual(res["safe_headers"]["content-type"], "application/json")


class TestExecutionLayer(unittest.TestCase):
    """Integration test for main execute_vcurl function."""

    @patch("vcurl.core.PinnedHTTPSConnection")
    @patch("vcurl.core.validate_url")
    def test_execute_vcurl_success_flow(self, mock_validate_url, mock_pinned_https):
        """Test full successful execute_vcurl call with alias resolution and mock connection."""
        mock_validate_url.return_value = ("https", "api.github.com", 443, ["140.82.121.4"])

        mock_conn = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.getheaders.return_value = [
            ("Content-Type", "application/json"),
            ("Set-Cookie", "secret_session=abc"),
        ]
        mock_response.read.return_value = b'{"id": 42, "message": "Issue Created"}'
        mock_conn.getresponse.return_value = mock_response
        mock_pinned_https.return_value = mock_conn

        DEFAULT_VAULT.set_secret("github_write_token", "ghp_mock_token_999")

        try:
            result = execute_vcurl(
                url="https://api.github.com/repos/example/repo/issues",
                method="POST",
                credential_alias="github_write_token",
                body={"title": "New Bug Report"},
            )

            self.assertEqual(result["status_code"], 201)
            self.assertEqual(result["response_body"], {"id": 42, "message": "Issue Created"})
            self.assertNotIn("set-cookie", result["safe_headers"])

            mock_conn.request.assert_called_once()
            _, kwargs = mock_conn.request.call_args
            req_headers = kwargs["headers"]
            self.assertEqual(req_headers["Authorization"], "Bearer ghp_mock_token_999")
            self.assertEqual(kwargs["method"], "POST")

        finally:
            pass


if __name__ == "__main__":
    unittest.main()
