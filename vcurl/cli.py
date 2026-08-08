"""
vcurl Command Line Interface (CLI)
Provides single-command setup (`vcurl setup`), Web Dashboard (`vcurl ui`),
encrypted vault management (`vcurl vault set <alias> <secret>`),
and direct request execution for AI Agents.
"""

import argparse
import json
import sys
from typing import Any, Dict

from .core import execute_vcurl
from .integrations.wizard import run_interactive_wizard
from .ui.server import start_ui_server
from .vault import DEFAULT_ENCRYPTED_VAULT, DEFAULT_VAULT


def main() -> None:
    # Check for direct subcommands (setup, ui, vault)
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd in ("setup", "init"):
            run_interactive_wizard()
            return
        elif cmd in ("ui", "dashboard"):
            port = 8888
            if "--port" in sys.argv:
                try:
                    idx = sys.argv.index("--port")
                    port = int(sys.argv[idx + 1])
                except (ValueError, IndexError):
                    pass
            start_ui_server(port=port)
            return
        elif cmd == "vault":
            if len(sys.argv) > 2:
                subcmd = sys.argv[2].lower()
                if subcmd == "set" and len(sys.argv) >= 5:
                    alias = sys.argv[3]
                    secret = sys.argv[4]
                    DEFAULT_VAULT.set_secret(alias, secret)
                    print(f"✓ Secret for alias '{alias}' successfully saved to encrypted vault (~/.vcurl/vault.enc).")
                    print("  (Isolated out-of-process: Not stored in environment variables where LLMs could read it!)")
                    return
                elif subcmd in ("list", "ls"):
                    aliases = DEFAULT_ENCRYPTED_VAULT.list_aliases()
                    print("\nRegistered Encrypted Vault Aliases:")
                    if not aliases:
                        print("  (No secrets stored in encrypted vault yet. Use 'vcurl vault set <alias> <secret>')")
                    else:
                        for k, v in aliases.items():
                            print(f"  - {k}: {v}")
                    print()
                    return

    parser = argparse.ArgumentParser(
        description="vcurl: Zero-Knowledge Secure HTTP Fetch for AI Agents"
    )
    parser.add_argument("--url", help="Target HTTP/HTTPS URL")
    parser.add_argument("--method", default="GET", help="HTTP Method (default: GET)")
    parser.add_argument("--alias", help="Credential alias to resolve from vault")
    parser.add_argument("--body", help="JSON string body or plain text body")
    parser.add_argument("--headers", help="JSON dictionary string of headers")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds (default: 10.0)")
    parser.add_argument("--json", action="store_true", help="Read request JSON payload from stdin")

    args = parser.parse_args()

    if args.json or not args.url:
        try:
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                payload: Dict[str, Any] = json.loads(stdin_data)
                url = payload.get("url") or args.url
                method = payload.get("method") or args.method
                alias = payload.get("credential_alias") or payload.get("alias") or args.alias
                body = payload.get("body") if "body" in payload else args.body
                headers = payload.get("headers") if "headers" in payload else args.headers
                timeout = payload.get("timeout", args.timeout)
            else:
                if not args.url:
                    parser.error("url argument is required when no stdin JSON is provided.")
                url, method, alias, body, headers, timeout = args.url, args.method, args.alias, args.body, args.headers, args.timeout
        except Exception as e:
            sys.stderr.write(f"Error parsing stdin input: {e}\n")
            sys.exit(1)
    else:
        url, method, alias, body, headers, timeout = args.url, args.method, args.alias, args.body, args.headers, args.timeout

    parsed_headers = None
    if isinstance(headers, str):
        try:
            parsed_headers = json.loads(headers)
        except Exception:
            pass
    elif isinstance(headers, dict):
        parsed_headers = headers

    parsed_body = body
    if isinstance(body, str):
        try:
            parsed_body = json.loads(body)
        except Exception:
            parsed_body = body

    try:
        result = execute_vcurl(
            url=url,
            method=method,
            credential_alias=alias,
            body=parsed_body,
            headers=parsed_headers,
            timeout=timeout,
        )
        print(json.dumps(result, indent=2))
    except Exception as e:
        sys.stderr.write(f"vcurl Security/Execution Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
