"""
Unit tests for AI Tool Setup Wizard (vcurl/integrations/wizard.py)
"""

import json
import os
import unittest
from vcurl.integrations.wizard import (
    setup_claude_mcp,
    setup_codex,
    setup_antigravity,
    setup_langchain,
    setup_autogen,
    setup_cursor
)


class TestWizardIntegrations(unittest.TestCase):

    def test_setup_claude_mcp(self):
        msg = setup_claude_mcp()
        self.assertIn("Successfully", msg)

    def test_setup_codex(self):
        msg = setup_codex()
        self.assertIn("vcurl_openai_tool.json", msg)
        if os.path.exists("vcurl_openai_tool.json"):
            os.remove("vcurl_openai_tool.json")

    def test_setup_antigravity(self):
        msg = setup_antigravity()
        self.assertIn("Antigravity", msg)

    def test_setup_langchain(self):
        msg = setup_langchain()
        self.assertIn("vcurl_langchain.py", msg)
        if os.path.exists("vcurl_langchain.py"):
            os.remove("vcurl_langchain.py")

    def test_setup_autogen(self):
        msg = setup_autogen()
        self.assertIn("vcurl_agent_tools.py", msg)
        if os.path.exists("vcurl_agent_tools.py"):
            os.remove("vcurl_agent_tools.py")

    def test_setup_cursor(self):
        msg = setup_cursor()
        self.assertIn("Cursor", msg)


if __name__ == "__main__":
    unittest.main()
