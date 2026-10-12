"""
VulnWatch Scanner — Cookie Security Attribute Checks
=====================================================
Analyzes Set-Cookie headers returned by the target application.
Only evaluates cookies when they are actually returned.
Inspects Secure, HttpOnly, and SameSite attributes.
"""

from __future__ import annotations

import http.cookies
from typing import Any


def check_cookies(raw_set_cookie_headers: list[str], is_https: bool = False) -> list[dict[str, Any]]:
    """
    Inspect cookie attributes from raw Set-Cookie response header strings.
    If no cookies are set, returns empty list (no invented findings).
    """
    findings: list[dict[str, Any]] = []

    if not raw_set_cookie_headers:
        return findings

    for header_str in raw_set_cookie_headers:
        cookie_parser = http.cookies.SimpleCookie()
        try:
            cookie_parser.load(header_str)
        except http.cookies.CookieError:
            continue

        for cookie_name, morsel in cookie_parser.items():
            # Check Secure attribute
            has_secure = bool(morsel.get("secure"))
            if not has_secure:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'Secure' Attribute",
                    "severity": "high" if is_https else "medium",
                    "category": "cookies",
                    "type": "missing_control",
                    "description": (
                        f"The cookie '{cookie_name}' does not specify the 'Secure' attribute. "
                        "Browsers will transmit this cookie over unencrypted HTTP connections if accessed, "
                        "exposing session identifiers to interception."
                    ),
                    "evidence": f"Set-Cookie: {header_str}",
                    "recommendation": f"Add the 'Secure' directive to cookie '{cookie_name}'.",
                    "location": f"Set-Cookie: {cookie_name}",
                })

            # Check HttpOnly attribute
            has_httponly = bool(morsel.get("httponly"))
            if not has_httponly:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'HttpOnly' Attribute",
                    "severity": "high",
                    "category": "cookies",
                    "type": "missing_control",
                    "description": (
                        f"The cookie '{cookie_name}' is set without the 'HttpOnly' flag. "
                        "This allows client-side JavaScript (e.g. document.cookie) to read or modify "
                        "the cookie, significantly increasing the impact of Cross-Site Scripting (XSS)."
                    ),
                    "evidence": f"Set-Cookie: {header_str}",
                    "recommendation": f"Add 'HttpOnly' flag to cookie '{cookie_name}' if it contains sensitive or session data.",
                    "location": f"Set-Cookie: {cookie_name}",
                })

            # Check SameSite attribute
            samesite = morsel.get("samesite")
            if not samesite:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                    "severity": "medium",
                    "category": "cookies",
                    "type": "missing_control",
                    "description": (
                        f"The cookie '{cookie_name}' does not specify a 'SameSite' attribute. "
                        "Without SameSite (Strict or Lax), browsers may send this cookie in cross-site requests, "
                        "increasing vulnerability to Cross-Site Request Forgery (CSRF)."
                    ),
                    "evidence": f"Set-Cookie: {header_str}",
                    "recommendation": f"Set 'SameSite=Lax' or 'SameSite=Strict' on cookie '{cookie_name}'.",
                    "location": f"Set-Cookie: {cookie_name}",
                })
            elif samesite.lower() == "none" and not has_secure:
                findings.append({
                    "title": f"Cookie '{cookie_name}' Specifies SameSite=None Without Secure",
                    "severity": "high",
                    "category": "cookies",
                    "type": "missing_control",
                    "description": (
                        f"Cookie '{cookie_name}' specifies SameSite=None but lacks the Secure attribute. "
                        "Modern browsers will reject cookies configured with SameSite=None without Secure."
                    ),
                    "evidence": f"Set-Cookie: {header_str}",
                    "recommendation": f"Ensure cookie '{cookie_name}' includes 'Secure' when SameSite=None is required.",
                    "location": f"Set-Cookie: {cookie_name}",
                })

    return findings
