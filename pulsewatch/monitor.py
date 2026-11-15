from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

logger = logging.getLogger(__name__)

MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 8
ALLOWED_PORTS = {"http": 80, "https": 443}
BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home",
    ".lan",
    ".test",
    ".invalid",
)
HEADER_NAMES = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


class UrlValidationError(ValueError):
    pass


def _hostname(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        normalized = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UrlValidationError("Hostname is not valid.") from exc

    if not normalized or len(normalized) > 253:
        raise UrlValidationError("Hostname is not valid.")
    if any(not label or len(label) > 63 for label in normalized.split(".")):
        raise UrlValidationError("Hostname is not valid.")
    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+",
        normalized,
    ):
        raise UrlValidationError("Hostname is not valid.")
    if normalized.endswith(BLOCKED_SUFFIXES):
        raise UrlValidationError("Local and reserved hostnames are not allowed.")
    return normalized


def validate_url(value: str) -> tuple[str, str, int, str]:
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        raise UrlValidationError("Enter a valid HTTP or HTTPS URL.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value) or any(
        char.isspace() for char in value
    ):
        raise UrlValidationError("Whitespace and control characters are not allowed.")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise UrlValidationError("The URL or port is not valid.") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_PORTS:
        raise UrlValidationError("Only HTTP and HTTPS URLs are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise UrlValidationError("URLs containing a username or password are not allowed.")
    if parsed.query or parsed.fragment:
        raise UrlValidationError("Query strings and fragments are not supported.")
    if not parsed.hostname:
        raise UrlValidationError("A hostname is required.")

    host = _hostname(parsed.hostname)
    expected_port = ALLOWED_PORTS[scheme]
    if port is not None and port != expected_port:
        raise UrlValidationError("Only the standard HTTP and HTTPS ports are supported.")

    path = parsed.path or "/"
    if not path.startswith("/") or "\\" in path:
        raise UrlValidationError("The URL path is not valid.")
    canonical_host = f"[{host}]" if ":" in host else host
    canonical = urlunsplit((scheme, canonical_host, path, "", ""))
    return canonical, scheme, expected_port, host


def resolve_public_address(host: str, port: int) -> str:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise OSError("DNS lookup failed.") from exc
        addresses = list(dict.fromkeys(record[4][0] for record in records))

    if not addresses:
        raise OSError("The hostname did not resolve to an address.")
    parsed_addresses = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise OSError("DNS returned an invalid address.") from exc
        if not parsed.is_global:
            raise UrlValidationError("The hostname resolves to a non-public address.")
        parsed_addresses.append((parsed.version, str(parsed)))

    # Reject mixed public/private DNS answers instead of selecting the public one.
    return parsed_addresses[0][1]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(host, port, timeout=REQUEST_TIMEOUT_SECONDS)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self.address, self.port), self.timeout
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(
            host,
            port,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl.create_default_context(),
        )
        self.address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self.address, self.port), self.timeout
        )
        try:
            self.sock = self._context.wrap_socket(
                raw_socket, server_hostname=self.host
            )
        except Exception:
            raw_socket.close()
            raise


def _certificate_details(connection: http.client.HTTPConnection) -> dict:
    if not isinstance(connection, _PinnedHTTPSConnection) or connection.sock is None:
        return {}
    certificate = connection.sock.getpeercert()
    not_after = certificate.get("notAfter")
    not_before = certificate.get("notBefore")
    issuer = certificate.get("issuer", ())

    def iso_date(value: str | None) -> str | None:
        if not value:
            return None
        return datetime.fromtimestamp(
            ssl.cert_time_to_seconds(value), timezone.utc
        ).isoformat()

    return {
        "valid": True,
        "not_before": iso_date(not_before),
        "expires_at": iso_date(not_after),
        "issuer": ", ".join(
            f"{key}={value}" for group in issuer for key, value in group
        ),
    }


def _request_once(url: str) -> dict:
    canonical, scheme, port, host = validate_url(url)
    address = resolve_public_address(host, port)
    parsed = urlsplit(canonical)
    path = parsed.path or "/"
    if scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
            host, port, address
        )
    else:
        connection = _PinnedHTTPConnection(host, port, address)

    start = time.monotonic()
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": parsed.netloc,
                "User-Agent": "PulseWatch/0.1",
                "Accept": "*/*",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "Range": f"bytes=0-{MAX_RESPONSE_BYTES - 1}",
            },
        )
        response = connection.getresponse()
        response_headers: dict[str, str] = {}
        for name, value in response.getheaders():
            lowered = name.lower()
            response_headers[lowered] = (
                f"{response_headers[lowered]}, {value}"
                if lowered in response_headers
                else value
            )
        response.read(MAX_RESPONSE_BYTES + 1)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        return {
            "status_code": response.status,
            "headers": response_headers,
            "response_time_ms": elapsed_ms,
            "certificate": _certificate_details(connection),
            "location": response_headers.get("location"),
        }
    finally:
        connection.close()


def classify_headers(headers: dict[str, str], scheme: str) -> dict[str, str]:
    result = {}
    for name in HEADER_NAMES:
        if name == "strict-transport-security" and scheme != "https":
            result[name] = "not_applicable"
        else:
            result[name] = "present" if headers.get(name, "").strip() else "missing"
    return result


def perform_check(url: str) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()
    current_url = url
    redirects = 0
    try:
        current_url, _, _, _ = validate_url(current_url)
        while True:
            response = _request_once(current_url)
            status = response["status_code"]
            location = response["location"]
            if status in {301, 302, 303, 307, 308} and location:
                if redirects >= MAX_REDIRECTS:
                    raise UrlValidationError("The redirect limit was exceeded.")
                current_url = urljoin(current_url, location)
                current_url, _, _, _ = validate_url(current_url)
                redirects += 1
                continue

            _, scheme, _, _ = validate_url(current_url)
            return {
                "checked_at": started_at,
                "success": 200 <= status < 400,
                "status_code": status,
                "response_time_ms": response["response_time_ms"],
                "error": None if 200 <= status < 400 else f"HTTP {status}",
                "final_url": current_url,
                "redirect_count": redirects,
                "headers": classify_headers(response["headers"], scheme),
                "certificate": response["certificate"],
            }
    except (
        UrlValidationError,
        OSError,
        http.client.HTTPException,
        ssl.SSLError,
        TimeoutError,
    ) as exc:
        logger.info("Monitoring check failed: %s", exc)
        return {
            "checked_at": started_at,
            "success": False,
            "status_code": None,
            "response_time_ms": None,
            "error": str(exc),
            "final_url": current_url,
            "redirect_count": redirects,
            "headers": {},
            "certificate": {},
        }


def details_json(result: dict) -> str:
    return json.dumps(
        {
            "headers": result["headers"],
            "certificate": result["certificate"],
        },
        separators=(",", ":"),
    )
