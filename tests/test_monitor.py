import unittest
from unittest.mock import patch

from pulsewatch import monitor
from pulsewatch.monitor import (
    UrlValidationError,
    classify_headers,
    perform_check,
    resolve_public_address,
    validate_url,
)

real_request_once = monitor._request_once


class UrlValidationTests(unittest.TestCase):
    def test_accepts_http_and_https_standard_ports(self):
        self.assertEqual(
            validate_url("https://example.com/health"),
            ("https://example.com/health", "https", 443, "example.com"),
        )
        self.assertEqual(
            validate_url("http://example.com"),
            ("http://example.com/", "http", 80, "example.com"),
        )
        self.assertEqual(
            validate_url("https://[2606:4700:4700::1111]/"),
            ("https://[2606:4700:4700::1111]/", "https", 443, "2606:4700:4700::1111"),
        )

    def test_rejects_credentials_queries_fragments_and_nonstandard_ports(self):
        invalid = (
            "https://user:password@example.com/",
            "https://example.com/path?token=secret",
            "https://example.com/path#fragment",
            "https://example.com:8443/",
            "file:///etc/passwd",
        )
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(UrlValidationError):
                validate_url(url)

    def test_rejects_local_and_single_label_hostnames(self):
        for url in ("http://localhost/", "http://printer/", "http://service.local/"):
            with self.subTest(url=url), self.assertRaises(UrlValidationError):
                validate_url(url)

    def test_rejects_private_or_reserved_ip_literals(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"):
            with self.subTest(address=address), self.assertRaises(UrlValidationError):
                resolve_public_address(address, 443)

    @patch("pulsewatch.monitor.socket.getaddrinfo")
    def test_rejects_mixed_public_and_private_dns_answers(self, getaddrinfo):
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.8", 443)),
        ]
        with self.assertRaises(UrlValidationError):
            resolve_public_address("example.com", 443)

    @patch("pulsewatch.monitor.socket.getaddrinfo")
    def test_uses_resolved_public_address(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        self.assertEqual(resolve_public_address("example.com", 443), "93.184.216.34")

    def test_header_presence_and_http_hsts_limitation(self):
        result = classify_headers({"x-frame-options": "DENY"}, "http")
        self.assertEqual(result["x-frame-options"], "present")
        self.assertEqual(result["content-security-policy"], "missing")
        self.assertEqual(result["strict-transport-security"], "not_applicable")

    @patch("pulsewatch.monitor._request_once")
    def test_check_result_distinguishes_success_from_server_failure(self, request):
        response = {
            "status_code": 200,
            "headers": {"content-security-policy": "default-src 'self'"},
            "response_time_ms": 24.5,
            "certificate": {"valid": True},
            "location": None,
        }
        request.return_value = response
        healthy = perform_check("https://example.com/")
        self.assertTrue(healthy["success"])
        self.assertEqual(healthy["response_time_ms"], 24.5)
        self.assertEqual(healthy["headers"]["content-security-policy"], "present")

        request.return_value = {**response, "status_code": 503}
        unhealthy = perform_check("https://example.com/")
        self.assertFalse(unhealthy["success"])
        self.assertEqual(unhealthy["error"], "HTTP 503")

    @patch("pulsewatch.monitor.socket.create_connection")
    @patch("pulsewatch.monitor._request_once")
    def test_redirect_to_private_address_is_blocked_before_connection(self, request, connect):
        first_response = {
            "status_code": 302,
            "headers": {"location": "http://127.0.0.1/"},
            "response_time_ms": 8.0,
            "certificate": {},
            "location": "http://127.0.0.1/",
        }

        def guarded_request(url):
            if request.call_count == 1:
                return first_response
            return real_request_once(url)

        request.side_effect = guarded_request
        result = perform_check("https://example.com/")
        self.assertFalse(result["success"])
        self.assertIn("non-public", result["error"])
        self.assertEqual(request.call_count, 2)
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
