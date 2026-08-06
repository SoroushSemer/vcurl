"""
vcurl AI Tool Setup Wizard
Interactive menu allowing users to automatically enable vcurl for Claude Desktop/MCP,
OpenAI Codex, Antigravity (Google DeepMind), LangChain, AutoGen, CrewAI, and Cursor.
"""

import json
import os
import sys
from typing import Dict, List


SUPPORTED_TOOLS = {
    "1": {"id": "claude", "name": "Anthropic Claude Desktop / MCP Server", "desc": "Configures Model Context Protocol (MCP) tool server in Claude Desktop"},
    "2": {"id": "codex", "name": "OpenAI Codex / ChatGPT Assistants", "desc": "Generates OpenAPI schema & function definitions for OpenAI tool calling"},
    "3": {"id": "antigravity", "name": "Antigravity (Google DeepMind Agentic IDE)", "desc": "Creates workspace .agents/skills/vcurl/SKILL.md for Antigravity"},
    "4": {"id": "langchain", "name": "LangChain & LangGraph", "desc": "Generates custom BaseTool python integration for LangChain agents"},
    "5": {"id": "autogen", "name": "AutoGen & CrewAI", "desc": "Generates function calling tool wrappers for AutoGen and CrewAI"},
    "6": {"id": "cursor", "name": "Cursor / Windsurf / VS Code Copilot", "desc": "Creates workspace rules and agent tool prompt guidelines"},
}


def setup_claude_mcp() -> str:
    """Configures vcurl as an MCP server in Claude Desktop."""
    config_dir = os.path.expanduser("~/.claude")
    config_path = os.path.join(config_dir, "claude_desktop_config.json")
    os.makedirs(config_dir, exist_ok=True)

    data = {"mcpServers": {}}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass

    if "mcpServers" not in data:
        data["mcpServers"] = {}

    data["mcpServers"]["vcurl"] = {
        "command": sys.executable,
        "args": ["-m", "vcurl.cli", "--json"],
        "description": "Zero-Knowledge Secure HTTP Fetch Tool for AI Agents"
    }

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return f"Successfully updated Claude Desktop MCP configuration at: {config_path}"


def setup_codex() -> str:
    """Generates OpenAI tool calling spec file."""
    output_path = os.path.abspath("vcurl_openai_tool.json")
    spec = {
        "type": "function",
        "function": {
            "name": "execute_vcurl",
            "description": "Executes HTTP requests securely using credential aliases. Prevents credential exfiltration and SSRF.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target HTTP or HTTPS URL"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                    "credential_alias": {"type": "string", "description": "Vault credential alias (e.g. github_write_token)"},
                    "body": {"type": "object", "description": "JSON body payload"},
                    "headers": {"type": "object", "description": "Optional custom headers"}
                },
                "required": ["url", "method"]
            }
        }
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2)

    return f"Created OpenAI Codex tool specification at: {output_path}"


def setup_antigravity() -> str:
    """Creates Antigravity agent skill definition."""
    skill_dir = os.path.abspath(".agents/skills/vcurl")
    os.makedirs(skill_dir, exist_ok=True)
    skill_file = os.path.join(skill_dir, "SKILL.md")

    content = """---
name: vcurl-fetch
description: Execute zero-knowledge HTTP requests with SSRF protection and credential alias injection.
---

# vcurl Agent Skill

When executing external HTTP requests, use `vcurl` to prevent secret exfiltration:

```python
from vcurl import execute_vcurl

response = execute_vcurl(
    url="https://api.github.com/repos/owner/repo/issues",
    method="POST",
    credential_alias="github_write_token",
    body={"title": "Issue title"}
)
```
"""
    with open(skill_file, "w", encoding="utf-8") as f:
        f.write(content)

    return f"Created Antigravity Skill definition at: {skill_file}"


def setup_langchain() -> str:
    """Generates LangChain tool integration module."""
    output_path = os.path.abspath("vcurl_langchain.py")
    content = """from typing import Any, Dict, Optional
from langchain.tools import tool
from vcurl import execute_vcurl

@tool
def vcurl_fetch(
    url: str,
    method: str = "GET",
    credential_alias: Optional[str] = None,
    body: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    \"\"\"Executes a secure HTTP fetch using vcurl with zero-knowledge secret injection and SSRF protection.\"\"\"
    return execute_vcurl(
        url=url,
        method=method,
        credential_alias=credential_alias,
        body=body
    )
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return f"Created LangChain tool wrapper at: {output_path}"


def setup_autogen() -> str:
    """Generates AutoGen and CrewAI tool wrapper."""
    output_path = os.path.abspath("vcurl_agent_tools.py")
    content = """from typing import Any, Dict, Optional
from vcurl import execute_vcurl

def vcurl_tool(
    url: str,
    method: str = "GET",
    credential_alias: Optional[str] = None,
    body: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    \"\"\"Tool for AutoGen / CrewAI agents to perform secure zero-knowledge HTTP fetches.\"\"\"
    return execute_vcurl(url=url, method=method, credential_alias=credential_alias, body=body)
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return f"Created AutoGen/CrewAI tool wrapper at: {output_path}"


def setup_cursor() -> str:
    """Generates Cursor / Windsurf rules file."""
    rules_dir = os.path.abspath(".cursor/rules")
    os.makedirs(rules_dir, exist_ok=True)
    rules_file = os.path.join(rules_dir, "vcurl-security.mdc")

    content = """---
description: vcurl Zero-Knowledge Fetch Guidelines
globs: *
---

# Security Rule: Use vcurl for HTTP Requests

Always use `vcurl.execute_vcurl` for network HTTP requests to prevent API key exfiltration:

- Never pass raw secrets in `Authorization` headers.
- Pass credential aliases (e.g. `credential_alias="github_write_token"`).
"""
    with open(rules_file, "w", encoding="utf-8") as f:
        f.write(content)

    return f"Created Cursor security rules at: {rules_file}"


def run_interactive_wizard() -> None:
    """Runs the terminal interactive AI tool selection menu."""
    print("\n=======================================================")
    print("      vcurl (Vault Curl) - AI Tool Setup Wizard       ")
    print("=======================================================\n")
    print("Select which AI tools you would like to enable vcurl for:\n")

    for key, tool in SUPPORTED_TOOLS.items():
        print(f"  [{key}] {tool['name']}")
        print(f"      {tool['desc']}\n")
    print("  [A] Enable for ALL supported AI tools")
    print("  [Q] Quit wizard\n")

    try:
        choice = input("Enter choice (e.g. 1, 3, A): ").strip().upper()
    except (KeyboardInterrupt, EOFError):
        print("\nWizard cancelled.")
        return

    if choice == "Q" or not choice:
        print("Setup cancelled.")
        return

    selected_ids = []
    if choice == "A":
        selected_ids = [t["id"] for t in SUPPORTED_TOOLS.values()]
    else:
        # Support comma separated choices like "1, 3"
        parts = [p.strip() for p in choice.split(",")]
        for p in parts:
            if p in SUPPORTED_TOOLS:
                selected_ids.append(SUPPORTED_TOOLS[p]["id"])

    if not selected_ids:
        print("Invalid selection.")
        return

    print("\nEnabling vcurl for selected AI tools...")
    results = []
    if "claude" in selected_ids:
        results.append(setup_claude_mcp())
    if "codex" in selected_ids:
        results.append(setup_codex())
    if "antigravity" in selected_ids:
        results.append(setup_antigravity())
    if "langchain" in selected_ids:
        results.append(setup_langchain())
    if "autogen" in selected_ids:
        results.append(setup_autogen())
    if "cursor" in selected_ids:
        results.append(setup_cursor())

    print("\n-------------------------------------------------------")
    for res in results:
        print(f"✓ {res}")
    print("-------------------------------------------------------")
    print("\nSetup complete! You can now use vcurl with your AI tools.\n")
