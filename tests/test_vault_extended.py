"""
Extended Unit tests for Encrypted Vault Engine & Cloud Secret Providers
"""

import os
import tempfile
import unittest
from vcurl.vault import VaultConfig
from vcurl.providers.encrypted_vault import EncryptedVaultProvider
from vcurl.providers.cloud_providers import (
    AWSSecretProvider,
    HashiCorpVaultProvider,
    GCPSecretProvider,
    AzureKeyVaultProvider
)


class TestVaultExtended(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_file = os.path.join(self.temp_dir.name, "test_vault.enc")
        self.provider = EncryptedVaultProvider(vault_file=self.vault_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypted_vault_crud(self):
        self.assertIsNone(self.provider.get_secret("nonexistent_alias"))
        
        # Save secret
        self.provider.set_secret("github_write_token", "ghp_securesecret123")
        
        # Verify resolution
        secret = self.provider.get_secret("github_write_token")
        self.assertEqual(secret, "ghp_securesecret123")
        
        # Verify file exists on disk and is encrypted (not plain text)
        self.assertTrue(os.path.exists(self.vault_file))
        with open(self.vault_file, "r") as f:
            content = f.read()
            self.assertNotIn("ghp_securesecret123", content)

    def test_vault_config_provider_priority(self):
        config = VaultConfig()
        config.add_provider(self.provider)
        
        self.provider.set_secret("test_key", "encrypted_vault_value")
        
        # Ensure VaultConfig resolves secret correctly via resolve()
        hdr_name, hdr_val = config.resolve("test_key")
        self.assertIn("encrypted_vault_value", hdr_val)

    def test_cloud_providers_graceful_fallback(self):
        aws = AWSSecretProvider(region_name="us-east-1")
        vault = HashiCorpVaultProvider(vault_addr="http://localhost:8200", token="test")
        gcp = GCPSecretProvider(project_id="test-proj")
        azure = AzureKeyVaultProvider(vault_url="https://test.vault.azure.net")

        # When services are unavailable, return None gracefully without throwing uncaught exceptions
        self.assertIsNone(aws.get_secret("missing_key"))
        self.assertIsNone(vault.get_secret("missing_key"))
        self.assertIsNone(gcp.get_secret("missing_key"))
        self.assertIsNone(azure.get_secret("missing_key"))


if __name__ == "__main__":
    unittest.main()
