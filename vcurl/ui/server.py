"""
vcurl Web UI Management Server
Lightweight HTTP server serving the Web Dashboard SPA and REST API for Credential Management,
Secret Provider Linker, and Outgoing Request Audit Log Stream.
"""

import json
import os
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

from ..audit import AUDIT_TRACKER
from ..integrations.wizard import (
    setup_antigravity,
    setup_autogen,
    setup_claude_mcp,
    setup_codex,
    setup_cursor,
    setup_langchain,
)
from ..vault import DEFAULT_VAULT


class UIRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for vcurl Web Dashboard and REST API."""

    def log_message(self, format, *args):
        # Silence default HTTP server logging in stdout
        pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_content: str, status: int = 200) -> None:
        body = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/", "/index.html"):
            # Serve index.html static SPA
            html_file = os.path.join(os.path.dirname(__file__), "static", "index.html")
            if os.path.exists(html_file):
                with open(html_file, "r", encoding="utf-8") as f:
                    self._send_html(f.read())
            else:
                self.send_error(404, "Dashboard HTML file not found.")
            return

        if path == "/api/audit":
            records = AUDIT_TRACKER.get_records(limit=100)
            self._send_json(records)
            return

        if path == "/api/vault":
            mappings = DEFAULT_VAULT._mapping
            self._send_json(mappings)
            return

        if path == "/api/status":
            self._send_json({
                "status": "healthy",
                "audited_requests": len(AUDIT_TRACKER.records),
                "vault_aliases": len(DEFAULT_VAULT._mapping),
            })
            return

        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload: Dict[str, Any] = json.loads(post_data)
        except Exception:
            payload = {}

        if path == "/api/vault":
            alias = payload.get("alias")
            env = payload.get("env")
            header = payload.get("header", "Authorization")
            prefix = payload.get("prefix", "Bearer ")
            if not alias or not env:
                self._send_json({"error": "Missing alias or env parameter."}, status=400)
                return

            DEFAULT_VAULT.register_alias(alias=alias, env_var=env, header_name=header, header_prefix=prefix)
            self._send_json({"message": f"Successfully registered alias '{alias}'."})
            return

        if path == "/api/enable-tool":
            tool_id = payload.get("tool_id")
            msg = "Tool enabled successfully."
            if tool_id == "claude":
                msg = setup_claude_mcp()
            elif tool_id == "codex":
                msg = setup_codex()
            elif tool_id == "antigravity":
                msg = setup_antigravity()
            elif tool_id == "langchain":
                msg = setup_langchain()
            elif tool_id == "autogen":
                msg = setup_autogen()
            elif tool_id == "cursor":
                msg = setup_cursor()

            self._send_json({"message": msg})
            return

        self.send_error(404, "Not Found")


def start_ui_server(port: int = 8888, open_browser: bool = True) -> None:
    """Launches the vcurl Web UI server and opens the dashboard in browser."""
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, UIRequestHandler)
    url = f"http://127.0.0.1:{port}"

    print(f"\n=======================================================")
    print(f"      vcurl Web UI Security Dashboard Running          ")
    print(f"=======================================================")
    print(f"  Dashboard URL: {url}")
    print(f"  Audit Tracker: {url}/api/audit")
    print(f"  Press Ctrl+C to stop server.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb UI server stopped.")
        httpd.server_close()
