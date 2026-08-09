"""
vcurl Feature Test Suite
Tests Secret Providers, Encrypted Vault isolation, Audit Tracker, Setup Wizard, and Web UI REST API handlers.
"""

import json
import os
import shutil
import tempfile
import unittest

from vcurl import (
    AUDIT_TRACKER,
    AuditRecord,
    EncryptedFileProvider,
    EncryptedVaultProvider,
    EnvSecretProvider,
    KeyringProvider,
    VaultConfig,
    setup_antigravity,
    setup_codex,
    setup_cursor,
    setup_langchain,
)


class TestSecretProviders(unittest.TestCase):
    """Tests pluggable secret provider architecture and secret isolation."""

    def test_encrypted_vault_isolation(self):
        temp_dir = tempfile.mkdtemp()
        vault_file = os.path.join(temp_dir, "test_vault.enc")
        provider = EncryptedVaultProvider(vault_file=vault_file)

        try:
            # Store secret out of process
            provider.set_secret("github_write_token", "ghp_isolated_secret_token_999")
            
            # Verify secret can be decrypted
            res = provider.get_secret("github_write_token")
            self.assertEqual(res, "ghp_isolated_secret_token_999")

            # Verify secret is NOT in process environment variables!
            self.assertNotIn("ghp_isolated_secret_token_999", os.environ.values())
        finally:
            shutil.rmtree(temp_dir)

    def test_env_provider_fallback(self):
        provider = EnvSecretProvider()
        os.environ["TEST_SECRET_KEY"] = "secret_val_123"
        try:
            self.assertEqual(provider.get_secret("TEST_SECRET_KEY"), "secret_val_123")
            self.assertIsNone(provider.get_secret("NON_EXISTENT_KEY"))
        finally:
            del os.environ["TEST_SECRET_KEY"]

    def test_vault_config_isolation_resolution(self):
        temp_dir = tempfile.mkdtemp()
        vault_file = os.path.join(temp_dir, "test_vault.enc")
        enc_provider = EncryptedVaultProvider(vault_file=vault_file)
        enc_provider.set_secret("slack_token", "xoxb-isolated-slack-secret")

        vault = VaultConfig(providers=[enc_provider])
        vault.register_alias("slack_token", "slack_token")

        try:
            hdr_name, hdr_val = vault.resolve("slack_token")
            self.assertEqual(hdr_name, "Authorization")
            self.assertEqual(hdr_val, "Bearer xoxb-isolated-slack-secret")

            # Ensure environment was not polluted
            self.assertNotIn("xoxb-isolated-slack-secret", os.environ.values())
        finally:
            shutil.rmtree(temp_dir)


class TestAuditTracker(unittest.TestCase):
    """Tests request audit logger."""

    def test_record_and_get(self):
        AUDIT_TRACKER.clear()
        rec = AuditRecord(
            url="https://api.github.com/zen",
            method="GET",
            credential_alias="github_write_token",
            ssrf_status="ALLOWED",
            resolved_ip="140.82.121.4",
            status_code=200,
            latency_ms=45.2,
        )
        AUDIT_TRACKER.record(rec)

        records = AUDIT_TRACKER.get_records(limit=10)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["url"], "https://api.github.com/zen")
        self.assertEqual(records[0]["ssrf_status"], "ALLOWED")


class TestIntegrations(unittest.TestCase):
    """Tests AI tool setup wizard integration generators."""

    def test_setup_codex(self):
        msg = setup_codex()
        self.assertIn("Created OpenAI Codex tool specification", msg)
        if os.path.exists("vcurl_openai_tool.json"):
            os.remove("vcurl_openai_tool.json")

    def test_setup_antigravity(self):
        msg = setup_antigravity()
        self.assertIn("Created Antigravity Skill definition", msg)
        skill_file = os.path.abspath(".agents/skills/vcurl/SKILL.md")
        self.assertTrue(os.path.exists(skill_file))

    def test_setup_langchain(self):
        msg = setup_langchain()
        self.assertIn("Created LangChain tool wrapper", msg)
        if os.path.exists("vcurl_langchain.py"):
            os.remove("vcurl_langchain.py")

    def test_setup_cursor(self):
        msg = setup_cursor()
        self.assertIn("Created Cursor security rules", msg)
        rules_file = os.path.abspath(".cursor/rules/vcurl-security.mdc")
        self.assertTrue(os.path.exists(rules_file))


if __name__ == "__main__":
    unittest.main()
