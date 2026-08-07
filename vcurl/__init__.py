"""
vcurl (Vault Curl) - Zero-Knowledge Fetch for AI Agents
"""

from .audit import AUDIT_TRACKER, AuditRecord, AuditTracker
from .core import execute_vcurl
from .integrations import (
    run_interactive_wizard,
    setup_antigravity,
    setup_autogen,
    setup_claude_mcp,
    setup_codex,
    setup_cursor,
    setup_langchain,
)
from .providers import (
    AWSSecretProvider,
    AzureKeyVaultProvider,
    BaseSecretProvider,
    EncryptedFileProvider,
    EnvSecretProvider,
    GCPSecretProvider,
    HashiCorpVaultProvider,
)
from .sanitizer import sanitize_headers, sanitize_response
from .ssrf import SSRFError, is_ip_allowed, validate_url
from .ui import start_ui_server
from .vault import DEFAULT_VAULT, VaultConfig, VaultError

__version__ = "0.2.0"
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
    "AUDIT_TRACKER",
    "AuditRecord",
    "AuditTracker",
    "BaseSecretProvider",
    "EnvSecretProvider",
    "AWSSecretProvider",
    "HashiCorpVaultProvider",
    "GCPSecretProvider",
    "AzureKeyVaultProvider",
    "EncryptedFileProvider",
    "run_interactive_wizard",
    "setup_claude_mcp",
    "setup_codex",
    "setup_antigravity",
    "setup_langchain",
    "setup_autogen",
    "setup_cursor",
    "start_ui_server",
]
