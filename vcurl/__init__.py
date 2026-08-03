"""
vcurl (Vault Curl) - Zero-Knowledge Fetch for AI Agents
"""

from .core import execute_vcurl
from .sanitizer import sanitize_headers, sanitize_response
from .ssrf import SSRFError, is_ip_allowed, validate_url
from .vault import DEFAULT_VAULT, VaultConfig, VaultError

__version__ = "0.1.0"
__all__ = [
    "execute_vcurl",
    "VaultConfig",
    "DEFAULT_VAULT",
    "SSRFError",
    "VaultError",
    "is_ip_allowed",
    "validate_url",
    "sanitize_headers",
    "sanitize_response",
]
