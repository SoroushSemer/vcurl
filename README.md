# vcurl (Vault Curl)

**The Zero-Knowledge Fetch for AI Agents.**

`vcurl` is an agent-agnostic, ultra-lightweight, high-performance HTTP execution engine designed to protect AI Agents against credential exfiltration and Server-Side Request Forgery (SSRF) caused by prompt injection attacks.

---

## Quick Start (One Command Installation & Setup)

```bash
# 1. Install vcurl
pip install vcurl

# 2. Run Interactive AI Tool Selection Wizard
vcurl setup

# 3. Launch Management Web UI Dashboard
vcurl ui
```

---

## Features Implemented

1. **Interactive AI Tool Setup Wizard (`vcurl setup`)**:
   - Single-command interactive selection menu enabling `vcurl` for popular AI tools:
     - **Anthropic Claude Desktop / MCP Server**
     - **OpenAI Codex / ChatGPT Assistants**
     - **Antigravity (Google DeepMind Agentic IDE)**
     - **LangChain & LangGraph**
     - **AutoGen & CrewAI**
     - **Cursor / Windsurf / VS Code Copilot**
2. **Pluggable Secret Provider Engine (`vcurl/providers/`)**:
   - Chain multiple credential sources dynamically:
     - **Environment Variables** (Default)
     - **AWS Secrets Manager** (`AWSSecretProvider`)
     - **HashiCorp Vault** (`HashiCorpVaultProvider`)
     - **Google Cloud Secret Manager** (`GCPSecretProvider`)
     - **Azure Key Vault** (`AzureKeyVaultProvider`)
     - **1Password CLI / Doppler / Local Encrypted Store**
3. **Modern Local Web UI Dashboard (`vcurl ui`)**:
   - **Outgoing Request Audit Tracker**: Live stream of all HTTP requests initiated by AI tools, showing target domain, method, credential alias used (secrets redacted), SSRF protection status (ALLOWED / BLOCKED), latency (ms), and response status code.
   - **Credential & Vault Manager**: Add, edit, or remove credential aliases and header mapping via web UI.
   - **Provider Linker**: Connect AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager, Azure Key Vault, or Local Encrypted Store.
   - **1-Click AI Integrations**: Enable tool integration files for Claude, Codex, Antigravity, LangChain, AutoGen, and Cursor with a single click.
4. **SSRF Protection & Anti-DNS Rebinding**:
   - Blocks private/loopback/link-local/cloud metadata IPs (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`, `::1`).
   - **DNS Socket Pinning**: Connects directly to verified IP addresses, neutralizing TOCTOU DNS Rebinding attacks.
   - **Redirect Re-Validation**: Validates redirect targets on HTTP 301/302/303/307/308 redirects.
5. **Response Sanitization**:
   - Strips sensitive response headers (`Set-Cookie`, `Authorization`, `X-API-Key`) and automatically parses JSON response payloads.

---

## Python API Usage

```python
from vcurl import execute_vcurl, VaultConfig, AWSSecretProvider, HashiCorpVaultProvider

# 1. Standard usage with environment variables
response = execute_vcurl(
    url="https://api.github.com/repos/example/repo/issues",
    method="POST",
    credential_alias="github_write_token",
    body={"title": "Bug report from agent"}
)

print(response["status_code"])   # 201
print(response["response_body"]) # Parsed JSON response dict
print(response["safe_headers"])  # Sanitized header dict (Set-Cookie stripped!)

# 2. Attach AWS Secrets Manager or HashiCorp Vault to custom VaultConfig
custom_vault = VaultConfig()
custom_vault.add_provider(AWSSecretProvider(region_name="us-west-2"))
custom_vault.add_provider(HashiCorpVaultProvider(vault_addr="http://127.0.0.1:8200", token="s.token"))

response = execute_vcurl(
    url="https://api.example.com/data",
    method="GET",
    credential_alias="custom_service_key",
    vault=custom_vault
)
```

---

## Running Unit Tests

```bash
python -m unittest discover -s tests
```

---

## License

MIT License. See [`LICENSE`](file:///c:/Users/Soroush/Documents/vcurl/LICENSE) for details.
