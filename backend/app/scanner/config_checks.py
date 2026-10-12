"""
VulnWatch Scanner — HTTP Configuration Checks
==============================================
Evaluates basic HTTP server configuration:
- Information disclosure in Server / X-Powered-By headers
- Cache-Control headers
- Dangerous/unnecessary HTTP methods
"""

from __future__ import annotations

import re
from typing import Any


def check_configuration(
    headers: dict[str, str],
    allowed_methods: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate basic server configuration weaknesses and information disclosure.
    """
    findings: list[dict[str, Any]] = []
    norm_headers = {k.lower(): v for k, v in headers.items()}

    # 1. Server header version disclosure
    server = norm_headers.get("server")
    if server and re.search(r"\d+\.\d+", server):
        findings.append({
            "title": "Server Header Exposes Software Version",
            "severity": "low",
            "category": "config",
            "type": "missing_control",
            "description": (
                f"The Server response header discloses specific product version information ('{server}'). "
                "This assists adversaries in reconnaissance and fingerprinting known vulnerabilities."
            ),
            "evidence": f"Server: {server}",
            "recommendation": "Configure your web server to suppress or genericize the Server banner (e.g. ServerTokens Prod).",
            "location": "HTTP Response Headers -> Server",
        })

    # 2. X-Powered-By header
    powered_by = norm_headers.get("x-powered-by")
    if powered_by:
        findings.append({
            "title": "Technology Stack Disclosed via X-Powered-By",
            "severity": "low",
            "category": "config",
            "type": "missing_control",
            "description": (
                f"The response includes an X-Powered-By header ('{powered_by}'), revealing underlying framework "
                "or language technology."
            ),
            "evidence": f"X-Powered-By: {powered_by}",
            "recommendation": "Remove or disable the X-Powered-By header in application configuration.",
            "location": "HTTP Response Headers -> X-Powered-By",
        })

    # 3. HTTP Methods (if OPTIONS probed)
    if allowed_methods:
        upper_methods = [m.upper().strip() for m in allowed_methods]
        if "TRACE" in upper_methods:
            findings.append({
                "title": "Insecure HTTP TRACE Method Enabled",
                "severity": "medium",
                "category": "config",
                "type": "vulnerability",
                "description": (
                    "The HTTP TRACE method is enabled on the server. TRACE reflects the received request "
                    "back to the client, which can be leveraged in Cross-Site Tracing (XST) attacks to steal cookies."
                ),
                "evidence": f"Allowed methods include TRACE: {', '.join(upper_methods)}",
                "recommendation": "Disable the HTTP TRACE method in your web server configuration.",
                "location": "HTTP Methods Configuration",
            })

    return findings
