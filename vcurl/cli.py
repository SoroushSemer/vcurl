"""
vcurl Command Line Interface (CLI)
Enables command-line execution or stdin JSON invocation of vcurl by AI Agents.
"""

import argparse
import json
import sys
from typing import Any, Dict

from .core import execute_vcurl


def main() -> None:
    parser = argparse.ArgumentParser(
        description="vcurl: Secure Zero-Knowledge HTTP Fetch for AI Agents"
    )
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--method", default="GET", help="HTTP Method (default: GET)")
    parser.add_argument("--alias", help="Credential alias to resolve from vault")
    parser.add_argument("--body", help="JSON string body or plain text body")
    parser.add_argument("--headers", help="JSON dictionary string of headers")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds (default: 10.0)")
    parser.add_argument("--json", action="store_true", help="Read request JSON payload from stdin")

    args = parser.parse_args()

    if args.json or not args.url:
        # Read from stdin if stdin is piped or --json flag used
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

    # Parse headers if passed as JSON string
    parsed_headers = None
    if isinstance(headers, str):
        try:
            parsed_headers = json.loads(headers)
        except Exception:
            sys.stderr.write("Warning: Headers parameter could not be parsed as JSON string.\n")
    elif isinstance(headers, dict):
        parsed_headers = headers

    # Parse body if passed as JSON string
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
