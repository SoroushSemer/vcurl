"""
vcurl Pluggable Secret Provider Interface
Defines the base abstraction for secret management providers (Env, AWS, GCP, Azure, Vault, etc.).
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseSecretProvider(ABC):
    """Abstract base class for all secret storage providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the secret provider (e.g. 'env', 'aws-sm', 'hashicorp-vault')."""
        pass

    @abstractmethod
    def get_secret(self, secret_name: str) -> Optional[str]:
        """
        Retrieves the secret value for a given secret name or key.
        Returns None if key is not found in this provider.
        """
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Returns True if the provider is properly configured and reachable."""
        pass

    def to_dict(self) -> Dict[str, Any]:
        """Returns configuration summary (without sensitive tokens)."""
        return {
            "name": self.name,
            "healthy": self.health_check(),
        }
