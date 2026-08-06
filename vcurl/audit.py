"""
vcurl Audit Log & Request Tracker Module
Records real-time outgoing HTTP requests initiated by AI agents for security auditing.
"""

import datetime
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List, Optional


class AuditRecord:
    """Represents a single audited outgoing HTTP request."""
    def __init__(
        self,
        url: str,
        method: str,
        credential_alias: Optional[str] = None,
        ssrf_status: str = "ALLOWED",
        resolved_ip: str = "",
        status_code: Optional[int] = None,
        latency_ms: float = 0.0,
        error: Optional[str] = None,
        safe_headers: Optional[Dict[str, str]] = None,
        response_preview: Optional[str] = None,
        agent_tool: str = "vcurl",
    ):
        self.id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.url = url
        self.method = method.upper()
        self.credential_alias = credential_alias or "None"
        self.ssrf_status = ssrf_status
        self.resolved_ip = resolved_ip
        self.status_code = status_code
        self.latency_ms = round(latency_ms, 2)
        self.error = error
        self.safe_headers = safe_headers or {}
        self.response_preview = response_preview or ""
        self.agent_tool = agent_tool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "url": self.url,
            "method": self.method,
            "credential_alias": self.credential_alias,
            "ssrf_status": self.ssrf_status,
            "resolved_ip": self.resolved_ip,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "safe_headers": self.safe_headers,
            "response_preview": self.response_preview,
            "agent_tool": self.agent_tool,
        }


class AuditTracker:
    """Thread-safe request audit logger and tracker."""
    def __init__(self, max_records: int = 500, log_file: Optional[str] = None):
        self.max_records = max_records
        self._lock = threading.Lock()
        self.records: List[AuditRecord] = []

        if not log_file:
            home = os.path.expanduser("~")
            log_file = os.path.join(home, ".vcurl", "audit_log.json")
        self.log_file = log_file
        self.load_from_disk()

    def record(self, record: AuditRecord) -> None:
        """Appends a new audit record thread-safely."""
        with self._lock:
            self.records.insert(0, record)
            if len(self.records) > self.max_records:
                self.records = self.records[:self.max_records]
            self.save_to_disk()

    def get_records(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Returns recent audit records as dictionary list."""
        with self._lock:
            return [r.to_dict() for r in self.records[:limit]]

    def clear(self) -> None:
        """Clears all audit records."""
        with self._lock:
            self.records.clear()
            self.save_to_disk()

    def save_to_disk(self) -> None:
        """Persists audit log to local JSON file."""
        try:
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            data = [r.to_dict() for r in self.records[:100]]
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def load_from_disk(self) -> None:
        """Loads audit log from local JSON file if present."""
        if not os.path.exists(self.log_file):
            return
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                with self._lock:
                    self.records = []
                    for item in data:
                        rec = AuditRecord(
                            url=item.get("url", ""),
                            method=item.get("method", "GET"),
                            credential_alias=item.get("credential_alias"),
                            ssrf_status=item.get("ssrf_status", "ALLOWED"),
                            resolved_ip=item.get("resolved_ip", ""),
                            status_code=item.get("status_code"),
                            latency_ms=item.get("latency_ms", 0.0),
                            error=item.get("error"),
                            safe_headers=item.get("safe_headers"),
                            response_preview=item.get("response_preview"),
                            agent_tool=item.get("agent_tool", "vcurl"),
                        )
                        rec.id = item.get("id", rec.id)
                        rec.timestamp = item.get("timestamp", rec.timestamp)
                        self.records.append(rec)
        except Exception:
            pass


# Global singleton instance
AUDIT_TRACKER = AuditTracker()
