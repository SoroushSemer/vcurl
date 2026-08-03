"""
vcurl top-level module wrapper for convenience.
Exposes `execute_vcurl` directly.
"""

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
