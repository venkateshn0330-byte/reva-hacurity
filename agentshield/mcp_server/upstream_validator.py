"""
AgentShield Upstream Endpoint Validator & SSRF Firewall
Validates user-configured upstream MCP endpoints to prevent SSRF, DNS rebinding,
private network probing, and cloud metadata access.
"""

import ipaddress
import os
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse


class SSRFValidationError(Exception):
    """Raised when an upstream URL fails SSRF security validation."""
    pass


def is_production_mode() -> bool:
    return os.environ.get("AGENTSHIELD_ENV", "development").lower() in ("production", "prod")


def is_loopback_allowed() -> bool:
    """Loopback upstream is allowed ONLY when explicitly enabled in non-production test mode."""
    if is_production_mode():
        return False
    return os.environ.get("AGENTSHIELD_ALLOW_LOOPBACK_UPSTREAM", "0") == "1"


def assert_valid_upstream_url(url_str: str) -> str:
    """Validate URL and raise SSRFValidationError on failure, or return sanitized URL."""
    valid, reason, sanitized = validate_upstream_url(url_str)
    if not valid:
        raise SSRFValidationError(reason)
    return sanitized or url_str


def validate_upstream_url(url_str: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate upstream server URL against SSRF and network egress boundaries.
    Returns (is_valid: bool, error_reason: str, sanitized_url: Optional[str]).
    """
    if not url_str or not isinstance(url_str, str):
        return False, "Upstream URL cannot be empty.", None

    url_str = url_str.strip()
    try:
        parsed = urlparse(url_str)
    except Exception as exc:
        return False, f"Malformed URL format: {str(exc)}", None

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are permitted for MCP Streamable HTTP transport.", None

    # In production, require HTTPS termination
    if is_production_mode() and scheme != "https":
        return False, "Production policy violation: Upstream MCP servers must use HTTPS.", None

    # Block embedded credentials
    if parsed.username or parsed.password:
        return False, "URL must not contain embedded user credentials (e.g. user:pass@host). Use the authorization token field instead.", None

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, "Missing hostname in upstream URL.", None

    # Check port bounds
    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        return False, f"Invalid port {port}. Port must be between 1 and 65535.", None

    # Check loopback exception for local sandbox mock testing
    allow_loopback = is_loopback_allowed()
    if allow_loopback and hostname in ("127.0.0.1", "localhost", "::1"):
        return True, "OK (Loopback permitted for testing sandbox)", url_str

    # Resolve IP addresses for SSRF checks
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for upstream host '{hostname}': {str(exc)}", None
    except Exception as exc:
        return False, f"Network inspection error: {str(exc)}", None

    if not addr_info:
        return False, f"Host '{hostname}' could not be resolved to an IP address.", None

    resolved_ips = set()
    for item in addr_info:
        sockaddr = item[4]
        if sockaddr and len(sockaddr) > 0:
            resolved_ips.add(sockaddr[0])

    for ip_str in resolved_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid resolved IP address: {ip_str}", None

        if ip.is_loopback:
            if not allow_loopback:
                return False, f"SSRF Protection: Host '{hostname}' resolves to loopback address ({ip}). Access denied.", None

        if ip.is_private:
            return False, f"SSRF Protection: Host '{hostname}' resolves to private/internal RFC1918 network ({ip}). Access denied.", None

        if ip.is_link_local:
            return False, f"SSRF Protection: Host '{hostname}' resolves to link-local address ({ip}). Cloud metadata access is strictly forbidden.", None

        if str(ip) in ("169.254.169.254", "fd00:ec2::254"):
            return False, "SSRF Protection: Direct cloud instance metadata access is blocked.", None

        if ip.is_reserved:
            return False, f"SSRF Protection: Host resolves to reserved address space ({ip}). Access denied.", None

        if ip.is_multicast:
            return False, f"SSRF Protection: Host resolves to multicast address ({ip}). Access denied.", None

        if ip.is_unspecified:
            return False, f"SSRF Protection: Host resolves to 0.0.0.0 or unspecified address ({ip}). Access denied.", None

    return True, "OK", url_str
