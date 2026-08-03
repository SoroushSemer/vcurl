"""
vcurl Core Execution Layer
Main entry point and request execution engine for Zero-Knowledge Fetch in AI Agents.
"""

import json
import urllib.parse
from typing import Any, Dict, Optional, Union

from .sanitizer import sanitize_response
from .ssrf import PinnedHTTPConnection, PinnedHTTPSConnection, validate_url
from .vault import DEFAULT_VAULT, VaultConfig


def execute_vcurl(
    url: str,
    method: str,
    credential_alias: Optional[str] = None,
    body: Optional[Union[Dict[str, Any], list, str, bytes]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    vault: Optional[VaultConfig] = None,
    max_redirects: int = 5,
) -> Dict[str, Any]:
    """
    Executes an HTTP request securely on behalf of an AI Agent.
    
    Prevents credential exfiltration and SSRF attacks by:
    1. Resolving safe `credential_alias` to actual secrets at the network layer.
    2. Validating DNS and blocking access to private/local IP subnets (SSRF protection).
    3. Pinning socket connections directly to pre-validated IPs (preventing DNS Rebinding).
    4. Re-validating redirect targets to block SSRF redirect loops.
    5. Sanitizing response headers to strip any sensitive cookies or credentials.

    Args:
        url (str): Target HTTP or HTTPS URL.
        method (str): HTTP Method (GET, POST, PUT, DELETE, PATCH, etc.).
        credential_alias (Optional[str]): Safe alias for credential lookup in vault.
        body (Optional[Union[Dict, list, str, bytes]]): Request payload.
        headers (Optional[Dict[str, str]]): Additional HTTP headers provided by caller.
        timeout (float): Connection and read timeout in seconds (default 10.0s).
        vault (Optional[VaultConfig]): Custom VaultConfig instance. Uses DEFAULT_VAULT if None.
        max_redirects (int): Maximum HTTP redirects to follow safely (default 5).

    Returns:
        Dict[str, Any]: Clean response object containing:
            - "status_code" (int): HTTP status code.
            - "response_body" (Union[dict, list, str]): Parsed response body.
            - "safe_headers" (Dict[str, str]): Sanitized HTTP response headers.

    Raises:
        SSRFError: If destination URL or redirect resolves to private/restricted network.
        VaultError: If credential_alias is invalid or environment secret is missing.
        ValueError: If HTTP method or input parameters are malformed.
        RuntimeError: If request execution times out or encounters network failures.
    """
    # 1. Normalize Method
    method_upper = str(method).strip().upper()
    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    if method_upper not in valid_methods:
        raise ValueError(f"Invalid HTTP method '{method}'. Supported methods: {', '.join(sorted(valid_methods))}")

    # 2. Prepare Headers dictionary (copy to avoid mutating input dict)
    req_headers: Dict[str, str] = {}
    if headers:
        for k, v in headers.items():
            req_headers[str(k).strip()] = str(v)

    # 3. Secret Resolution & Secure Injection
    # Prevent caller/agent from attempting raw header injection directly
    sensitive_keys_to_strip = {"authorization", "x-api-key", "api-key", "cookie"}
    for k in list(req_headers.keys()):
        if k.lower() in sensitive_keys_to_strip:
            del req_headers[k]

    active_vault = vault if vault is not None else DEFAULT_VAULT
    if credential_alias:
        sec_header_name, sec_header_val = active_vault.resolve(credential_alias)
        req_headers[sec_header_name] = sec_header_val

    # 4. Serialize Request Body
    encoded_body: Optional[bytes] = None
    if body is not None:
        if isinstance(body, (dict, list)):
            encoded_body = json.dumps(body).encode("utf-8")
            # Set Content-Type if not explicitly supplied
            if not any(k.lower() == "content-type" for k in req_headers):
                req_headers["Content-Type"] = "application/json"
        elif isinstance(body, str):
            encoded_body = body.encode("utf-8")
        elif isinstance(body, bytes):
            encoded_body = body
        else:
            raise ValueError(f"Unsupported body type '{type(body).__name__}'. Must be dict, list, str, or bytes.")

    current_url = url
    redirect_count = 0

    while True:
        # 5. SSRF Validation & DNS Resolution
        scheme, hostname, port, resolved_ips = validate_url(current_url)
        # Select primary validated IP address
        target_ip = resolved_ips[0]

        parsed = urllib.parse.urlparse(current_url)
        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path += f"?{parsed.query}"

        # 6. Execute Request via DNS-Pinned Connection (Prevents DNS Rebinding)
        # Ensure Host header matches original domain
        request_headers = dict(req_headers)
        if not any(k.lower() == "host" for k in request_headers):
            request_headers["Host"] = parsed.netloc

        conn = None
        try:
            if scheme == "https":
                conn = PinnedHTTPSConnection(
                    host=hostname,
                    port=port,
                    pinned_ip=target_ip,
                    timeout=timeout,
                )
            else:
                conn = PinnedHTTPConnection(
                    host=hostname,
                    port=port,
                    pinned_ip=target_ip,
                    timeout=timeout,
                )

            conn.request(
                method=method_upper,
                url=path,
                body=encoded_body,
                headers=request_headers,
            )

            res = conn.getresponse()
            status_code = res.status
            res_headers = res.getheaders()
            body_bytes = res.read()

            # 7. Check for Redirects (301, 302, 303, 307, 308)
            if status_code in (301, 302, 303, 307, 308):
                location_header = None
                for hk, hv in res_headers:
                    if hk.lower() == "location":
                        location_header = hv
                        break

                if location_header:
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        raise RuntimeError(f"Exceeded maximum allowed HTTP redirects ({max_redirects}).")

                    # Compute new target URL
                    current_url = urllib.parse.urljoin(current_url, location_header)
                    
                    # For 303 See Other, change method to GET and drop body
                    if status_code == 303:
                        method_upper = "GET"
                        encoded_body = None

                    continue  # Loop to re-validate new target URL against SSRF policy!

            # 8. Sanitize & Return Response
            return sanitize_response(
                status_code=status_code,
                headers=res_headers,
                body_bytes=body_bytes,
            )

        except (TimeoutError, socket.timeout) as e:
            raise RuntimeError(f"Request execution timed out after {timeout} seconds.") from e
        except Exception as e:
            if isinstance(e, (SSRFError, ValueError, RuntimeError)):
                raise
            raise RuntimeError(f"HTTP request execution failed: {e}") from e
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
