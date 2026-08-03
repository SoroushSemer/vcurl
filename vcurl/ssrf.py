"""
vcurl SSRF Protection Module
Provides URL validation, IP range checking against private/reserved networks,
and DNS-pinned socket connections to prevent DNS Rebinding (TOCTOU) attacks.
"""

import ipaddress
import socket
import ssl
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection
from typing import List, Tuple


class SSRFError(PermissionError):
    """Raised when a URL or resolved IP violates SSRF security policies."""
    pass


# Private, loopback, link-local, and cloud metadata IP ranges to block
FORBIDDEN_NETWORKS = [
    # IPv4 Private & Special Ranges
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (this host)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private-Use
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Transition Space (CGNAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private-Use
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (Documentation)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private-Use
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (Documentation)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (Documentation)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 Special Ranges
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),           # Discard-Only Address Block
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]


def is_ip_allowed(ip_str: str) -> bool:
    """
    Evaluates whether an IP address string is public and safe to access.
    
    Returns False for private, loopback, link-local, multicast, reserved,
    or cloud metadata IP addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    # Check built-in properties
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return False

    # Explicit check against defined forbidden subnets
    for network in FORBIDDEN_NETWORKS:
        if ip in network:
            return False

    return True


def validate_url(url: str) -> Tuple[str, str, int, List[str]]:
    """
    Parses and validates a target URL against SSRF policy.
    
    Resolves DNS for the target hostname and ensures that ALL resolved IP addresses
    belong to public internet space.

    Returns:
        Tuple of (scheme, hostname, port, resolved_ips)
    
    Raises:
        SSRFError: If the scheme is non-HTTP/HTTPS, hostname is invalid,
                   or DNS resolves to any private/restricted IP address.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()

    if scheme not in ("http", "https"):
        raise SSRFError(f"Blocked URL: Scheme '{scheme}' is not supported. Only http and https are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("Blocked URL: Missing hostname.")

    # Remove brackets from IPv6 hostnames if present
    clean_hostname = hostname.strip("[]")

    port = parsed.port
    if not port:
        port = 443 if scheme == "https" else 80

    # Resolve DNS to get all candidate IP addresses
    try:
        addr_info = socket.getaddrinfo(clean_hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFError(f"DNS Resolution failed for host '{clean_hostname}': {e}") from e

    resolved_ips: List[str] = []
    for family, _, _, _, sockaddr in addr_info:
        ip = sockaddr[0]
        if ip not in resolved_ips:
            resolved_ips.append(ip)

    if not resolved_ips:
        raise SSRFError(f"DNS Resolution returned no IP addresses for host '{clean_hostname}'.")

    # Validate EVERY resolved IP address to prevent split-horizon/multi-A-record bypasses
    for ip in resolved_ips:
        if not is_ip_allowed(ip):
            raise SSRFError(
                f"SSRF Protection Block: Host '{clean_hostname}' resolved to restricted IP '{ip}'."
            )

    return scheme, clean_hostname, port, resolved_ips


class PinnedHTTPConnection(HTTPConnection):
    """
    HTTPConnection subclass that connects directly to a pre-validated IP address
    while keeping the original HTTP Host header intact, eliminating DNS Rebinding.
    """
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float = 10.0):
        super().__init__(host=host, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        # Establish TCP connection directly to the verified IP address
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(HTTPSConnection):
    """
    HTTPSConnection subclass that connects directly to a pre-validated IP address
    and performs TLS handshake using TLS SNI and Certificate Verification for original host.
    """
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float = 10.0, ssl_context=None):
        super().__init__(host=host, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip
        self.ssl_context = ssl_context or ssl.create_default_context()

    def connect(self):
        # Create raw socket connected directly to verified IP
        raw_sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = raw_sock
            self._tunnel()
            raw_sock = self.sock

        # Perform TLS Handshake using original hostname for SNI and Hostname validation
        self.sock = self.ssl_context.wrap_socket(
            raw_sock,
            server_hostname=self.host
        )
