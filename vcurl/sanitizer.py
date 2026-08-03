"""
vcurl Response Sanitizer Module
Strips sensitive HTTP headers and parses response bodies into safe formats.
"""

import json
from typing import Any, Dict, List, Tuple, Union

# Set of sensitive HTTP headers (in lowercase) that must NEVER be returned to LLM
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "set-cookie2",
    "www-authenticate",
    "proxy-authorization",
    "proxy-authenticate",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-secret-key",
    "x-amz-security-token",
    "x-amz-session-token",
    "session-token",
}


def sanitize_headers(headers: Union[List[Tuple[str, str]], Dict[str, str]]) -> Dict[str, str]:
    """
    Strips sensitive headers from HTTP response headers.
    Returns a dictionary of safe headers with lowercased key normalization.
    """
    safe: Dict[str, str] = {}
    
    items = headers.items() if isinstance(headers, dict) else headers
    for key, value in items:
        clean_key = str(key).strip().lower()
        if clean_key not in SENSITIVE_HEADERS:
            safe[clean_key] = str(value)

    return safe


def parse_response_body(body_bytes: bytes, content_type: str = "") -> Union[Dict[str, Any], List[Any], str]:
    """
    Parses response body bytes into JSON object/list if valid, otherwise returns string.
    """
    if not body_bytes:
        return ""

    # Decode raw bytes using UTF-8 with fallback
    text_content = body_bytes.decode("utf-8", errors="replace").strip()
    if not text_content:
        return ""

    # Attempt JSON parsing if content-type indicates JSON or body starts with JSON characters
    is_json_header = "json" in content_type.lower()
    looks_like_json = text_content.startswith(("{", "["))

    if is_json_header or looks_like_json:
        try:
            return json.loads(text_content)
        except (json.JSONDecodeError, ValueError):
            pass

    return text_content


def sanitize_response(
    status_code: int,
    headers: Union[List[Tuple[str, str]], Dict[str, str]],
    body_bytes: bytes
) -> Dict[str, Any]:
    """
    Constructs a safe response dictionary ready for consumption by LLM agents.
    
    Returns:
        Dict containing:
            - status_code: int
            - response_body: Union[dict, list, str]
            - safe_headers: Dict[str, str]
    """
    safe_hdrs = sanitize_headers(headers)
    content_type = safe_hdrs.get("content-type", "")
    parsed_body = parse_response_body(body_bytes, content_type=content_type)

    return {
        "status_code": status_code,
        "response_body": parsed_body,
        "safe_headers": safe_hdrs,
    }
