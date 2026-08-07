"""
vcurl Vault Module
Provides credential alias configuration, pluggable secret provider resolution
(Env, AWS, Vault, GCP, Azure, Encrypted Store), and secure header injection.
"""

import os
from typing import Dict, List, Optional, Tuple, Union

from .providers.base import BaseSecretProvider
from .providers.cloud_providers import EncryptedFileProvider
from .providers.env_provider import EnvSecretProvider


class VaultError(PermissionError):
    """Raised when secret resolution fails or alias is unauthorized/missing."""
    pass


class VaultConfig:
    """
    Manages mappings between safe credential aliases (used by LLMs)
    and actual environment variables or external secret management providers.
    """
    def __init__(
        self,
        mapping: Optional[Dict[str, Union[str, Dict[str, str]]]] = None,
        providers: Optional[List[BaseSecretProvider]] = None,
    ):
        self._mapping: Dict[str, Union[str, Dict[str, str]]] = {}
        if mapping:
            self._mapping.update(mapping)

        self.providers: List[BaseSecretProvider] = providers if providers is not None else [
            EnvSecretProvider(),
            EncryptedFileProvider(),
        ]

    def add_provider(self, provider: BaseSecretProvider) -> None:
        """Registers an external secret provider (e.g. AWS, HashiCorp Vault, GCP, Azure)."""
        self.providers.insert(0, provider)  # Higher priority

    def register_alias(
        self,
        alias: str,
        env_var: str,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer "
    ) -> None:
        """Registers a credential alias mapping."""
        self._mapping[alias] = {
            "env": env_var,
            "header": header_name,
            "prefix": header_prefix
        }

    def get_mapping(self, alias: str) -> Union[str, Dict[str, str]]:
        """Retrieves raw configuration mapping for an alias."""
        if alias not in self._mapping:
            raise VaultError(
                f"Unauthorized credential alias '{alias}'. Alias is not registered in vcurl vault."
            )
        return self._mapping[alias]

    def resolve(self, alias: str) -> Tuple[str, str]:
        """
        Resolves an alias to a header name and secret header value by querying configured providers.
        
        Returns:
            Tuple[header_name, header_value]
        
        Raises:
            VaultError: If alias is not registered or secret cannot be resolved from any provider.
        """
        config = self.get_mapping(alias)

        if isinstance(config, str):
            env_var = config
            header_name = "Authorization"
            header_prefix = "Bearer "
        elif isinstance(config, dict):
            env_var = config.get("env", "")
            header_name = config.get("header", "Authorization")
            header_prefix = config.get("prefix", "Bearer " if header_name.lower() == "authorization" else "")
        else:
            raise VaultError(f"Invalid vault configuration for alias '{alias}'.")

        if not env_var:
            raise VaultError(f"Configuration for alias '{alias}' is missing target secret key name.")

        # Query chained secret providers in order
        secret: Optional[str] = None
        for provider in self.providers:
            val = provider.get_secret(env_var)
            if val:
                secret = val
                break

        if not secret:
            raise VaultError(
                f"Secret resolution failed: Secret key '{env_var}' for alias '{alias}' was not found in any active provider (Env, AWS, Vault, GCP, Azure, Encrypted Store)."
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
