"""
VulnWatch Scanner — Transport & TLS Checks
===========================================
Inspects protocol security (HTTPS vs cleartext HTTP) and evaluates TLS/SSL
certificate validation status when HTTPS is used.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import urllib.parse
from typing import Any


def check_transport(target_url: str, port: int) -> list[dict[str, Any]]:
    """
    Perform transport and TLS configuration checks.
    Returns list of findings.
    """
    findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlsplit(target_url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or "localhost"

    if scheme == "http":
        findings.append({
            "title": "Cleartext HTTP Transport in Use",
            "severity": "medium",
            "category": "transport",
            "type": "missing_control",
            "description": (
                "The application is accessible over unencrypted HTTP. Data transmitted "
                "in cleartext is vulnerable to passive eavesdropping and man-in-the-middle tampering."
            ),
            "evidence": f"Target scheme is '{scheme}://' on port {port}",
            "recommendation": "Configure TLS/HTTPS and enforce automatic redirection from HTTP to HTTPS.",
            "location": "Protocol / Transport Layer",
        })
        return findings

    # HTTPS target — inspect TLS certificate
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((hostname, port), timeout=5) as sock,
            context.wrap_socket(sock, server_hostname=hostname) as ssock,
        ):
            cert = ssock.getpeercert()
            if cert:
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    not_after = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.UTC)
                    now = datetime.datetime.now(datetime.UTC)
                    if now > not_after:
                        findings.append({
                            "title": "Expired TLS Certificate",
                            "severity": "high",
                            "category": "transport",
                            "type": "vulnerability",
                            "description": f"The TLS certificate expired on {not_after_str}.",
                            "evidence": f"Certificate expiry date: {not_after_str}",
                            "recommendation": "Renew and install a currently valid TLS certificate.",
                            "location": "TLS / Certificate",
                        })
    except ssl.SSLCertVerificationError as exc:
        findings.append({
            "title": "TLS Certificate Verification Failure",
            "severity": "high",
            "category": "transport",
            "type": "vulnerability",
            "description": f"The TLS certificate could not be verified by the system trust store: {exc.verify_message}.",
            "evidence": str(exc),
            "recommendation": "Install a valid TLS certificate issued by a trusted Certificate Authority.",
            "location": "TLS / Certificate",
        })
    except (ssl.SSLError, OSError) as exc:
        findings.append({
            "title": "TLS Handshake Incomplete",
            "severity": "low",
            "category": "transport",
            "type": "missing_control",
            "description": f"Could not complete full TLS inspection: {exc}",
            "evidence": str(exc),
            "recommendation": "Verify TLS service configuration and supported cipher suites.",
            "location": "TLS / Certificate",
        })

    return findings
