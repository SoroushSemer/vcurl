"""
vcurl Vault Module
Provides credential alias configuration, environment secret resolution,
and secure header injection without exposing secrets to LLM callers.
"""

import os
from typing import Dict, Optional, Tuple, Union


class VaultError(PermissionError):
    """Raised when secret resolution fails or alias is unauthorized/missing."""
    pass


class VaultConfig:
    """
    Manages mappings between safe credential aliases (used by LLMs)
    and actual environment variables or secrets.
    """
    def __init__(self, mapping: Optional[Dict[str, Union[str, Dict[str, str]]]] = None):
        """
        Initialize VaultConfig with a mapping.
        
        Examples of mapping entries:
            "github_write_token": "GITHUB_TOKEN"
            "slack_bot": "SLACK_BOT_TOKEN"
            "custom_api": {
                "env": "MY_CUSTOM_API_KEY",
                "header": "X-API-Key",
                "prefix": ""
            }
        """
        self._mapping: Dict[str, Union[str, Dict[str, str]]] = {}
        if mapping:
            self._mapping.update(mapping)

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
        Resolves an alias to a header name and secret header value.
        
        Returns:
            Tuple[header_name, header_value]
        
        Raises:
            VaultError: If alias is not registered or secret environment variable is missing.
        """
        config = self.get_mapping(alias)

        if isinstance(config, str):
            # Default convention: maps alias to env variable name, uses Authorization: Bearer <token>
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
            raise VaultError(f"Configuration for alias '{alias}' is missing target environment variable name.")

        secret = os.environ.get(env_var)
        if not secret:
            raise VaultError(
                f"Secret resolution failed: Environment variable '{env_var}' for alias '{alias}' is not set or empty."
            )

        header_value = f"{header_prefix}{secret}" if header_prefix else secret
        return header_name, header_value


# Global default vault instance initialized from environment variable conventions
DEFAULT_VAULT = VaultConfig({
    "github_write_token": "GITHUB_TOKEN",
    "github_token": "GITHUB_TOKEN",
    "openai_api_key": "OPENAI_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "slack_bot_token": "SLACK_BOT_TOKEN",
    "default_bearer": "VCURL_DEFAULT_TOKEN",
})
