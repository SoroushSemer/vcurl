"""
vcurl Vault Module
Provides credential alias configuration, secret isolation via Encrypted Vault and OS Keyring,
pluggable cloud providers (AWS, Vault, GCP, Azure), and secure header injection.
"""

import os
from typing import Dict, List, Optional, Tuple, Union

from .providers.base import BaseSecretProvider
from .providers.cloud_providers import EncryptedFileProvider
from .providers.encrypted_vault import EncryptedVaultProvider, KeyringProvider
from .providers.env_provider import EnvSecretProvider


class VaultError(PermissionError):
    """Raised when secret resolution fails or alias is unauthorized/missing."""
    pass


DEFAULT_ENCRYPTED_VAULT = EncryptedVaultProvider()


class VaultConfig:
    """
    Manages mappings between safe credential aliases (used by LLMs)
    and actual secrets stored in isolated Encrypted Vaults or OS Keyring.
    
    Prevents storing secrets in process environment variables (os.environ)
    where LLMs or prompt injections could exfiltrate them via shell printenv.
    """
    def __init__(
        self,
        mapping: Optional[Dict[str, Union[str, Dict[str, str]]]] = None,
        providers: Optional[List[BaseSecretProvider]] = None,
    ):
        self._mapping: Dict[str, Union[str, Dict[str, str]]] = {}
        if mapping:
            self._mapping.update(mapping)

        # Default provider order prioritizes isolated encrypted vaults & keyring OVER environment variables
        self.providers: List[BaseSecretProvider] = providers if providers is not None else [
            KeyringProvider(),
            DEFAULT_ENCRYPTED_VAULT,
            EncryptedFileProvider(),
            EnvSecretProvider(),
        ]

    def add_provider(self, provider: BaseSecretProvider) -> None:
        """Registers an external secret provider (e.g. AWS, HashiCorp Vault, GCP, Azure)."""
        self.providers.insert(0, provider)  # Top priority

    def register_alias(
        self,
        alias: str,
        env_var: Optional[str] = None,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer ",
        raw_secret: Optional[str] = None,
    ) -> None:
        """
        Registers a credential alias mapping.
        
        If raw_secret is provided, it is stored safely in the local encrypted vault
        without ever polluting os.environ!
        """
        target_key = env_var or alias
        self._mapping[alias] = {
            "env": target_key,
            "header": header_name,
            "prefix": header_prefix
        }

        if raw_secret:
            # Store directly in encrypted local vault
            DEFAULT_ENCRYPTED_VAULT.set_secret(alias, raw_secret)
            DEFAULT_ENCRYPTED_VAULT.set_secret(target_key, raw_secret)

    def set_secret(self, alias: str, secret_val: str) -> None:
        """Saves a secret value directly into the encrypted local vault."""
        DEFAULT_ENCRYPTED_VAULT.set_secret(alias, secret_val)
        if alias not in self._mapping:
            self.register_alias(alias, alias)

    def get_mapping(self, alias: str) -> Union[str, Dict[str, str]]:
        """Retrieves configuration mapping for an alias."""
        if alias not in self._mapping:
            # Auto-register default fallback mapping for alias
            return {"env": alias, "header": "Authorization", "prefix": "Bearer "}
        return self._mapping[alias]

    def resolve(self, alias: str) -> Tuple[str, str]:
        """
        Resolves an alias to a header name and secret value from active isolated providers.
        
        Returns:
            Tuple[header_name, header_value]
        """
        config = self.get_mapping(alias)

        if isinstance(config, str):
            env_var = config
            header_name = "Authorization"
            header_prefix = "Bearer "
        elif isinstance(config, dict):
            env_var = config.get("env", alias)
            header_name = config.get("header", "Authorization")
            header_prefix = config.get("prefix", "Bearer " if header_name.lower() == "authorization" else "")
        else:
            env_var = alias
            header_name = "Authorization"
            header_prefix = "Bearer "

        # Query chained secret providers (Keyring, EncryptedVault, Cloud Providers, Env)
        secret: Optional[str] = None
        # Check alias name directly first
        for provider in self.providers:
            val = provider.get_secret(alias)
            if val:
                secret = val
                break

        # Check env_var mapping if alias check did not return secret
        if not secret:
            for provider in self.providers:
                val = provider.get_secret(env_var)
                if val:
                    secret = val
                    break

        if not secret:
            raise VaultError(
                f"Secret resolution failed: Secret key '{alias}' (or '{env_var}') was not found in any isolated provider (Encrypted Vault, OS Keyring, AWS, HashiCorp Vault, GCP, Azure)."
            )

        header_value = f"{header_prefix}{secret}" if header_prefix else secret
        return header_name, header_value


# Global default vault instance initialized from standard conventions
DEFAULT_VAULT = VaultConfig({
    "github_write_token": "GITHUB_TOKEN",
    "github_token": "GITHUB_TOKEN",
    "openai_api_key": "OPENAI_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "slack_bot_token": "SLACK_BOT_TOKEN",
    "default_bearer": "VCURL_DEFAULT_TOKEN",
})
