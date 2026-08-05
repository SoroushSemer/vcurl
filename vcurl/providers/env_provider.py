"""
vcurl Environment Variable Secret Provider
Retrieves secrets directly from process environment variables.
"""

import os
from typing import Optional
from .base import BaseSecretProvider


class EnvSecretProvider(BaseSecretProvider):
    """Secret provider backed by system environment variables."""

    @property
    def name(self) -> str:
        return "env"

    def get_secret(self, secret_name: str) -> Optional[str]:
        if not secret_name:
            return None
        val = os.environ.get(secret_name)
        return val if val else None

    def health_check(self) -> bool:
        return True
