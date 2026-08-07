"""
vcurl Feature Test Suite
Tests Secret Providers, Audit Tracker, Setup Wizard, and Web UI REST API handlers.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from vcurl import (
    AUDIT_TRACKER,
    AWSSecretProvider,
    AuditRecord,
    EncryptedFileProvider,
    EnvSecretProvider,
    HashiCorpVaultProvider,
    VaultConfig,
    execute_vcurl,
    run_interactive_wizard,
    setup_antigravity,
    setup_claude_mcp,
    setup_codex,
    setup_cursor,
    setup_langchain,
)
from vcurl.ui.server import UIRequestHandler


class TestSecretProviders(unittest.TestCase):
    """Tests pluggable secret provider architecture."""

    def test_env_provider(self):
        provider = EnvSecretProvider()
        os.environ["TEST_SECRET_KEY"] = "secret_val_123"
        try:
            self.assertEqual(provider.get_secret("TEST_SECRET_KEY"), "secret_val_123")
            self.assertIsNone(provider.get_secret("NON_EXISTENT_KEY"))
        finally:
            del os.environ["TEST_SECRET_KEY"]

    def test_encrypted_file_provider(self):
        temp_dir = tempfile.mkdtemp()
        secrets_file = os.path.join(temp_dir, "secrets.json")
        with open(secrets_file, "w", encoding="utf-8") as f:
            json.dump({"my_alias": "super_secret_token"}, f)

        try:
            provider = EncryptedFileProvider(file_path=secrets_file)
            self.assertEqual(provider.get_secret("my_alias"), "super_secret_token")
            self.assertIsNone(provider.get_secret("other_key"))
        finally:
            shutil.rmtree(temp_dir)

    def test_vault_config_provider_chaining(self):
        vault = VaultConfig({"test_alias": "CUSTOM_ENV_KEY"})
        
        temp_dir = tempfile.mkdtemp()
        secrets_file = os.path.join(temp_dir, "secrets.json")
        with open(secrets_file, "w", encoding="utf-8") as f:
            json.dump({"CUSTOM_ENV_KEY": "from_file_store"}, f)

        try:
            vault.add_provider(EncryptedFileProvider(file_path=secrets_file))
            hdr_name, hdr_val = vault.resolve("test_alias")
            self.assertEqual(hdr_name, "Authorization")
            self.assertEqual(hdr_val, "Bearer from_file_store")
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
        self.assertTrue(os.path.exists("vcurl_openai_tool.json"))
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
        self.assertTrue(os.path.exists("vcurl_langchain.py"))
        if os.path.exists("vcurl_langchain.py"):
            os.remove("vcurl_langchain.py")

    def test_setup_cursor(self):
        msg = setup_cursor()
        self.assertIn("Created Cursor security rules", msg)
        rules_file = os.path.abspath(".cursor/rules/vcurl-security.mdc")
        self.assertTrue(os.path.exists(rules_file))


if __name__ == "__main__":
    unittest.main()
