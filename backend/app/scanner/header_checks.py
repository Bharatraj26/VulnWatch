"""
VulnWatch Scanner — HTTP Security Header Checks
================================================
Passively inspects HTTP response headers for recommended defensive controls:
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Frame-Options (XFO)
- X-Content-Type-Options (XCTO)
- Referrer-Policy
- Permissions-Policy
"""

from __future__ import annotations

from typing import Any


def check_security_headers(
    headers: dict[str, str],
    is_https: bool = False,
) -> list[dict[str, Any]]:
    """
    Evaluate security headers in the HTTP response.
    Returns structured list of findings.
    """
    findings: list[dict[str, Any]] = []

    # Normalize headers to lowercase keys
    norm_headers = {k.lower(): v for k, v in headers.items()}

    # 1. Content-Security-Policy
    csp = norm_headers.get("content-security-policy")
    if not csp:
        findings.append({
            "title": "Missing Content-Security-Policy Header",
            "severity": "high",
            "category": "headers",
            "type": "missing_control",
            "description": (
                "The Content-Security-Policy (CSP) response header is absent. CSP restricts "
                "the sources from which scripts, styles, and other resources can be loaded, "
                "mitigating Cross-Site Scripting (XSS) and data injection attacks."
            ),
            "evidence": "Header 'Content-Security-Policy' was not present in the HTTP response.",
            "recommendation": "Define and deploy a strict CSP header (e.g. Content-Security-Policy: default-src 'self').",
            "location": "HTTP Response Headers",
        })
    else:
        if "'unsafe-inline'" in csp and "nonce-" not in csp:
            findings.append({
                "title": "Content-Security-Policy Allows 'unsafe-inline'",
                "severity": "medium",
                "category": "headers",
                "type": "missing_control",
                "description": (
                    "The CSP policy includes 'unsafe-inline' without cryptographic nonces or hashes. "
                    "This weakens protection against inline script injection."
                ),
                "evidence": f"Content-Security-Policy: {csp}",
                "recommendation": "Remove 'unsafe-inline' or introduce CSP nonces/hashes for necessary inline scripts.",
                "location": "HTTP Response Headers -> Content-Security-Policy",
            })

    # 2. Strict-Transport-Security (relevant for HTTPS targets)
    hsts = norm_headers.get("strict-transport-security")
    if is_https:
        if not hsts:
            findings.append({
                "title": "Missing Strict-Transport-Security Header",
                "severity": "high",
                "category": "headers",
                "type": "missing_control",
                "description": (
                    "HTTP Strict Transport Security (HSTS) is not configured on this HTTPS endpoint. "
                    "HSTS instructs browsers to always connect via HTTPS, preventing SSL-stripping attacks."
                ),
                "evidence": "Header 'Strict-Transport-Security' was not returned.",
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
                "location": "HTTP Response Headers",
            })
        elif "max-age" in hsts:
            try:
                # Check max-age value
                parts = [p.strip() for p in hsts.split(";")]
                for p in parts:
                    if p.lower().startswith("max-age="):
                        seconds = int(p.split("=")[1])
                        if seconds < 10368000:  # < 120 days
                            findings.append({
                                "title": "Short HSTS max-age Duration",
                                "severity": "low",
                                "category": "headers",
                                "type": "missing_control",
                                "description": f"HSTS max-age is set to {seconds} seconds, which is less than the recommended 1 year (31536000 seconds).",
                                "evidence": f"Strict-Transport-Security: {hsts}",
                                "recommendation": "Increase HSTS max-age to at least 31536000 (1 year).",
                                "location": "HTTP Response Headers -> Strict-Transport-Security",
                            })
            except (ValueError, IndexError):
                pass

    # 3. X-Frame-Options
    xfo = norm_headers.get("x-frame-options")
    if not xfo:
        findings.append({
            "title": "Missing X-Frame-Options Header",
            "severity": "medium",
            "category": "headers",
            "type": "missing_control",
            "description": (
                "The X-Frame-Options header is missing. Without this or a CSP 'frame-ancestors' directive, "
                "the application may be embedded in an external iframe, exposing users to clickjacking attacks."
            ),
            "evidence": "Header 'X-Frame-Options' was not present in the HTTP response.",
            "recommendation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
            "location": "HTTP Response Headers",
        })
    elif xfo.upper() not in ("DENY", "SAMEORIGIN"):
        findings.append({
            "title": "Non-Standard X-Frame-Options Value",
            "severity": "low",
            "category": "headers",
            "type": "missing_control",
            "description": f"X-Frame-Options has unexpected value '{xfo}'. Recommended values are DENY or SAMEORIGIN.",
            "evidence": f"X-Frame-Options: {xfo}",
            "recommendation": "Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options.",
            "location": "HTTP Response Headers -> X-Frame-Options",
        })

    # 4. X-Content-Type-Options
    xcto = norm_headers.get("x-content-type-options")
    if not xcto:
        findings.append({
            "title": "Missing X-Content-Type-Options Header",
            "severity": "low",
            "category": "headers",
            "type": "missing_control",
            "description": (
                "The 'X-Content-Type-Options: nosniff' header is not set. This allows older or non-standard "
                "browsers to MIME-sniff the response away from the declared Content-Type."
            ),
            "evidence": "Header 'X-Content-Type-Options' was not present in the HTTP response.",
            "recommendation": "Configure your server to send 'X-Content-Type-Options: nosniff'.",
            "location": "HTTP Response Headers",
        })
    elif xcto.lower() != "nosniff":
        findings.append({
            "title": "Invalid X-Content-Type-Options Directive",
            "severity": "low",
            "category": "headers",
            "type": "missing_control",
            "description": f"Expected 'nosniff', got '{xcto}'.",
            "evidence": f"X-Content-Type-Options: {xcto}",
            "recommendation": "Set 'X-Content-Type-Options: nosniff'.",
            "location": "HTTP Response Headers -> X-Content-Type-Options",
        })

    # 5. Referrer-Policy
    referrer = norm_headers.get("referrer-policy")
    if not referrer:
        findings.append({
            "title": "Missing Referrer-Policy Header",
            "severity": "low",
            "category": "headers",
            "type": "missing_control",
            "description": (
                "No Referrer-Policy header was detected. Without an explicit policy, browsers may include "
                "full path and query strings in the Referer header to external destinations."
            ),
            "evidence": "Header 'Referrer-Policy' was not present in the HTTP response.",
            "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            "location": "HTTP Response Headers",
        })

    # 6. Permissions-Policy
    permissions = norm_headers.get("permissions-policy")
    if not permissions:
        findings.append({
            "title": "Missing Permissions-Policy Header",
            "severity": "low",
            "category": "headers",
            "type": "missing_control",
            "description": (
                "The Permissions-Policy header is absent. It provides fine-grained control over browser "
                "features such as camera, microphone, geolocation, and payment APIs."
            ),
            "evidence": "Header 'Permissions-Policy' was not present in the HTTP response.",
            "recommendation": "Add a Permissions-Policy header restricting unused browser capabilities (e.g. geolocation=(), camera=(), microphone=()).",
            "location": "HTTP Response Headers",
        })

    return findings
