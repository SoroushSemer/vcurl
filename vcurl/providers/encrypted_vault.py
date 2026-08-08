"""
vcurl Encrypted Local Vault Provider
Provides out-of-process encrypted secret storage (~/.vcurl/vault.enc).
Prevents storing secrets in process environment variables (os.environ) where LLMs could inspect them.
"""

import base64
import hashlib
import json
import os
import platform
from typing import Dict, Optional
from .base import BaseSecretProvider


def _get_machine_key() -> bytes:
    """Generates a deterministic machine-specific encryption key."""
    sys_info = f"{platform.node()}-{platform.machine()}-{os.getlogin() if hasattr(os, 'getlogin') else 'vcurl'}"
    return hashlib.pbkdf2_hmac(
        "sha256",
        sys_info.encode("utf-8"),
        b"vcurl-zero-knowledge-salt-2026",
        100000
    )


def _encrypt_val(raw_str: str, key: bytes) -> str:
    """Encrypts raw secret string using machine-derived key."""
    raw_bytes = raw_str.encode("utf-8")
    # XOR cipher with SHA256 keystream derivation for zero external dependencies
    cipher_bytes = bytearray()
    for i, b in enumerate(raw_bytes):
        keystream_byte = hashlib.sha256(key + i.to_bytes(4, "big")).digest()[0]
        cipher_bytes.append(b ^ keystream_byte)
    return base64.b64encode(cipher_bytes).decode("utf-8")


def _decrypt_val(enc_str: str, key: bytes) -> Optional[str]:
    """Decrypts encrypted secret string using machine-derived key."""
    try:
        cipher_bytes = base64.b64decode(enc_str.encode("utf-8"))
        raw_bytes = bytearray()
        for i, b in enumerate(cipher_bytes):
            keystream_byte = hashlib.sha256(key + i.to_bytes(4, "big")).digest()[0]
            raw_bytes.append(b ^ keystream_byte)
        return raw_bytes.decode("utf-8")
    except Exception:
        return None


class EncryptedVaultProvider(BaseSecretProvider):
    """
    Local Encrypted Vault Provider (~/.vcurl/vault.enc).
    Secrets are stored encrypted on disk, completely isolated from process environment variables.
    """
    def __init__(self, vault_file: Optional[str] = None):
        if not vault_file:
            home = os.path.expanduser("~")
            vault_file = os.path.join(home, ".vcurl", "vault.enc")
        self.vault_file = vault_file
        self.key = _get_machine_key()

    @property
    def name(self) -> str:
        return "encrypted-vault"

    def set_secret(self, alias: str, secret_val: str) -> None:
        """Encrypts and stores a secret alias in the local vault."""
        data = self._load_vault()
        data[alias] = _encrypt_val(secret_val, self.key)
        self._save_vault(data)

    def get_secret(self, secret_name: str) -> Optional[str]:
        data = self._load_vault()
        if secret_name in data:
            return _decrypt_val(data[secret_name], self.key)
        return None

    def list_aliases(self) -> Dict[str, str]:
        """Returns map of alias -> masked preview."""
        data = self._load_vault()
        result = {}
        for k, v in data.items():
            dec = _decrypt_val(v, self.key)
            if dec:
                masked = dec[:3] + "..." + dec[-2:] if len(dec) > 5 else "*****"
                result[k] = masked
            else:
                result[k] = "******"
        return result

    def health_check(self) -> bool:
        return True

    def _load_vault(self) -> Dict[str, str]:
        if not os.path.exists(self.vault_file):
            return {}
        try:
            with open(self.vault_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_vault(self, data: Dict[str, str]) -> None:
        os.makedirs(os.path.dirname(self.vault_file), exist_ok=True)
        with open(self.vault_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


class KeyringProvider(BaseSecretProvider):
    """
    Native OS Keyring Provider (macOS Keychain, Windows Credential Manager, Linux Secret Service).
    Uses python 'keyring' module if available.
    """
    def __init__(self, service_name: str = "vcurl"):
        self.service_name = service_name
        self._keyring = None
        try:
            import keyring
            self._keyring = keyring
        except ImportError:
            self._keyring = None

    @property
    def name(self) -> str:
        return "os-keyring"

    def get_secret(self, secret_name: str) -> Optional[str]:
        if not self._keyring:
            return None
        try:
            return self._keyring.get_password(self.service_name, secret_name)
        except Exception:
            return None

    def set_secret(self, secret_name: str, secret_val: str) -> bool:
        if not self._keyring:
            return False
        try:
            self._keyring.set_password(self.service_name, secret_name, secret_val)
            return True
        except Exception:
            return False

    def health_check(self) -> bool:
        return self._keyring is not None
