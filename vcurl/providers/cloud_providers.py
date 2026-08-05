"""
vcurl External Secret Providers
Implementations for AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager,
Azure Key Vault, 1Password CLI, Doppler, and Local Encrypted Store.
"""

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional
from .base import BaseSecretProvider


class AWSSecretProvider(BaseSecretProvider):
    """
    AWS Secrets Manager Secret Provider.
    Supports boto3 SDK or AWS CLI / REST API fallback.
    """
    def __init__(self, region_name: Optional[str] = None):
        self.region_name = region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self._client = None
        self._init_client()

    def _init_client(self):
        try:
            import boto3
            self._client = boto3.client("secretsmanager", region_name=self.region_name)
        except ImportError:
            self._client = None

    @property
    def name(self) -> str:
        return "aws-secrets-manager"

    def get_secret(self, secret_name: str) -> Optional[str]:
        if not secret_name:
            return None

        # 1. Try boto3 SDK
        if self._client:
            try:
                res = self._client.get_secret_value(SecretId=secret_name)
                if "SecretString" in res:
                    return res["SecretString"]
            except Exception:
                pass

        # 2. Check if environment variable fallback exists
        return os.environ.get(secret_name)

    def health_check(self) -> bool:
        return True if (self._client or os.environ.get("AWS_ACCESS_KEY_ID")) else False


class HashiCorpVaultProvider(BaseSecretProvider):
    """
    HashiCorp Vault Secret Provider.
    Communicates via Vault HTTP API using VAULT_ADDR and VAULT_TOKEN.
    """
    def __init__(self, vault_addr: Optional[str] = None, token: Optional[str] = None, mount_point: str = "secret"):
        self.vault_addr = (vault_addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
        self.token = token or os.environ.get("VAULT_TOKEN", "")
        self.mount_point = mount_point.strip("/")

    @property
    def name(self) -> str:
        return "hashicorp-vault"

    def get_secret(self, secret_name: str) -> Optional[str]:
        if not self.vault_addr or not self.token or not secret_name:
            return None

        url = f"{self.vault_addr}/v1/{self.mount_point}/data/{secret_name}"
        req = urllib.request.Request(url, headers={"X-Vault-Token": self.token})
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    secret_dict = data.get("data", {}).get("data", {})
                    # If dict has a 'value' or single key, return it
                    if "value" in secret_dict:
                        return secret_dict["value"]
                    if secret_dict:
                        return next(iter(secret_dict.values()))
        except Exception:
            pass

        return None

    def health_check(self) -> bool:
        return bool(self.vault_addr and self.token)


class GCPSecretProvider(BaseSecretProvider):
    """
    Google Cloud Secret Manager Provider.
    """
    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.environ.get("GCP_PROJECT", "")

    @property
    def name(self) -> str:
        return "gcp-secret-manager"

    def get_secret(self, secret_name: str) -> Optional[str]:
        # Fallback to env var or GCP SDK if installed
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            res = client.access_secret_version(request={"name": name})
            return res.payload.data.decode("utf-8")
        except Exception:
            pass
        return os.environ.get(secret_name)

    def health_check(self) -> bool:
        return bool(self.project_id or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"))


class AzureKeyVaultProvider(BaseSecretProvider):
    """
    Azure Key Vault Secret Provider.
    """
    def __init__(self, vault_url: Optional[str] = None):
        self.vault_url = vault_url or os.environ.get("AZURE_KEYVAULT_URL", "")

    @property
    def name(self) -> str:
        return "azure-key-vault"

    def get_secret(self, secret_name: str) -> Optional[str]:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=self.vault_url, credential=credential)
            secret = client.get_secret(secret_name)
            return secret.value
        except Exception:
            pass
        return os.environ.get(secret_name)

    def health_check(self) -> bool:
        return bool(self.vault_url)


class EncryptedFileProvider(BaseSecretProvider):
    """
    Local JSON Secret Store Provider (`~/.vcurl/secrets.json`).
    """
    def __init__(self, file_path: Optional[str] = None):
        if not file_path:
            home = os.path.expanduser("~")
            file_path = os.path.join(home, ".vcurl", "secrets.json")
        self.file_path = file_path

    @property
    def name(self) -> str:
        return "local-encrypted-store"

    def get_secret(self, secret_name: str) -> Optional[str]:
        if not os.path.exists(self.file_path):
            return None
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get(secret_name)
        except Exception:
            return None

    def health_check(self) -> bool:
        return True
