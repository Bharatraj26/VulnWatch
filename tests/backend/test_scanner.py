"""
VulnWatch Tests — Scanner Engine & Checks
==========================================
Unit tests for target validation, SSRF defense, security header evaluation,
cookie attribute analysis, server configuration checks, and scoring formula.
"""

from __future__ import annotations

import urllib.request
from unittest.mock import MagicMock, patch

import pytest
from app.scanner.config_checks import check_configuration
from app.scanner.cookie_checks import check_cookies
from app.scanner.header_checks import check_security_headers
from app.scanner.scoring import calculate_security_score, generate_report_summary
from app.scanner.target_validator import (
    SafeRedirectHandler,
    TargetValidationError,
    is_authorized_ip,
    validate_target_url,
)
from app.scanner.transport_checks import check_transport

# ─── 1. Target Validation & SSRF Prevention ───────────────────────────────────


def test_target_validator_allows_loopback():
    """Validates that loopback URLs are accepted."""
    url, ip, port = validate_target_url("http://localhost:5000")
    assert "localhost" in url or "127.0.0.1" in url
    assert port == 5000
    assert ip in ("127.0.0.1", "::1")

    _url2, ip2, port2 = validate_target_url("http://127.0.0.1:8000")
    assert ip2 == "127.0.0.1"
    assert port2 == 8000


def test_target_validator_rejects_empty_or_non_string():
    """Rejects empty or non-string inputs."""
    with pytest.raises(TargetValidationError, match="non-empty string"):
        validate_target_url("")


def test_target_validator_rejects_unsupported_schemes():
    """Rejects non-HTTP schemes (e.g. ftp, file, gopher)."""
    with pytest.raises(TargetValidationError, match="Unsupported protocol"):
        validate_target_url("ftp://localhost:21")

    with pytest.raises(TargetValidationError, match="Unsupported protocol"):
        validate_target_url("file:///etc/passwd")


def test_target_validator_rejects_embedded_credentials():
    """Rejects URLs containing usernames/passwords."""
    with pytest.raises(TargetValidationError, match="embedded user credentials"):
        validate_target_url("http://admin:secret@localhost:5000")


def test_target_validator_rejects_cloud_metadata():
    """Rejects cloud metadata endpoints (169.254.169.254)."""
    with pytest.raises(TargetValidationError, match="unauthorized destination"):
        validate_target_url("http://169.254.169.254/latest/meta-data/")


def test_target_validator_rejects_public_addresses():
    """Rejects arbitrary third-party public addresses."""
    # 8.8.8.8 is a public DNS server
    with pytest.raises(TargetValidationError, match="unauthorized destination"):
        validate_target_url("http://8.8.8.8")


def test_is_authorized_ip_rules():
    """Unit tests for IP authorization logic."""
    assert is_authorized_ip("127.0.0.1") is True
    assert is_authorized_ip("127.0.0.5") is True
    assert is_authorized_ip("::1") is True
    assert is_authorized_ip("169.254.169.254") is False
    assert is_authorized_ip("0.0.0.0") is False
    assert is_authorized_ip("255.255.255.255") is False
    assert is_authorized_ip("10.0.0.1") is False  # Non-loopback private disallowed by default
    assert is_authorized_ip("8.8.8.8") is False  # Public IP


# ─── 2. Security Header Checks ────────────────────────────────────────────────


def test_header_checks_missing_all():
    """Identifies missing security headers on an empty response."""
    findings = check_security_headers({}, is_https=False)
    titles = [f["title"] for f in findings]
    assert "Missing Content-Security-Policy Header" in titles
    assert "Missing X-Frame-Options Header" in titles
    assert "Missing X-Content-Type-Options Header" in titles
    assert "Missing Referrer-Policy Header" in titles
    assert "Missing Permissions-Policy Header" in titles

    # All missing headers are classified as missing_control
    for f in findings:
        assert f["type"] == "missing_control"


def test_header_checks_hsts_on_https():
    """Verifies that missing HSTS is flagged on HTTPS endpoints."""
    findings = check_security_headers({}, is_https=True)
    titles = [f["title"] for f in findings]
    assert "Missing Strict-Transport-Security Header" in titles


def test_header_checks_good_headers():
    """Verifies that a fully hardened response produces zero header findings."""
    good_headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=(), camera=()",
    }
    findings = check_security_headers(good_headers, is_https=True)
    assert len(findings) == 0


def test_header_checks_csp_unsafe_inline():
    """Flags CSP policies permitting 'unsafe-inline' without nonce."""
    headers = {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
    findings = check_security_headers(headers, is_https=False)
    titles = [f["title"] for f in findings]
    assert "Content-Security-Policy Allows 'unsafe-inline'" in titles


# ─── 3. Cookie Checks ─────────────────────────────────────────────────────────


def test_cookie_checks_empty():
    """Does not invent findings when no cookies are returned."""
    findings = check_cookies([], is_https=False)
    assert len(findings) == 0


def test_cookie_checks_insecure_cookie():
    """Flags missing Secure, HttpOnly, and SameSite attributes on cookies."""
    raw_cookies = ["sessionid=abc123xyz; Path=/"]
    findings = check_cookies(raw_cookies, is_https=True)
    titles = [f["title"] for f in findings]
    assert "Cookie 'sessionid' Missing 'Secure' Attribute" in titles
    assert "Cookie 'sessionid' Missing 'HttpOnly' Attribute" in titles
    assert "Cookie 'sessionid' Missing 'SameSite' Attribute" in titles


def test_cookie_checks_hardened_cookie():
    """Accepts properly hardened cookies without raising findings."""
    raw_cookies = ["sessionid=abc123xyz; Path=/; Secure; HttpOnly; SameSite=Strict"]
    findings = check_cookies(raw_cookies, is_https=True)
    assert len(findings) == 0


# ─── 4. Configuration & Transport Checks ──────────────────────────────────────


def test_config_checks_server_version_disclosure():
    """Detects version information exposed in Server header."""
    headers = {"server": "Apache/2.4.52 (Ubuntu)"}
    findings = check_configuration(headers)
    assert len(findings) == 1
    assert "Server Header Exposes Software Version" in findings[0]["title"]


def test_config_checks_trace_method():
    """Flags HTTP TRACE method when enabled."""
    findings = check_configuration({}, allowed_methods=["GET", "POST", "TRACE"])
    assert len(findings) == 1
    assert "Insecure HTTP TRACE Method Enabled" in findings[0]["title"]
    assert findings[0]["type"] == "vulnerability"


def test_transport_checks_http_scheme():
    """Flags cleartext HTTP transport usage."""
    findings = check_transport("http://localhost:5000", 5000)
    assert len(findings) == 1
    assert "Cleartext HTTP Transport in Use" in findings[0]["title"]


# ─── 5. Scoring Formula ───────────────────────────────────────────────────────


def test_scoring_formula_clean():
    """Clean assessment gives score 100 and Grade A."""
    score, grade, breakdown = calculate_security_score([])
    assert score == 100
    assert grade == "A"
    assert breakdown["critical"] == 0
    assert breakdown["high"] == 0


def test_scoring_formula_deductions():
    """Applies documented deductions based on severity weights."""
    findings = [
        {"severity": "critical", "type": "vulnerability"},  # -25
        {"severity": "high", "type": "missing_control"},     # -15
        {"severity": "medium", "type": "missing_control"},   # -8
        {"severity": "low", "type": "missing_control"},      # -3
    ]
    # 100 - (25 + 15 + 8 + 3) = 49
    score, grade, breakdown = calculate_security_score(findings)
    assert score == 49
    assert grade == "D"
    assert breakdown["critical"] == 1
    assert breakdown["high"] == 1
    assert breakdown["medium"] == 1
    assert breakdown["low"] == 1


def test_scoring_formula_bounded():
    """Score never drops below 0 even with excessive findings."""
    findings = [{"severity": "critical"} for _ in range(10)]
    score, grade, _ = calculate_security_score(findings)
    assert score == 0
    assert grade == "F"


def test_report_summary_narrative():
    """Generates informative report narrative."""
    findings = [{"severity": "high", "type": "missing_control"}]
    score, grade, breakdown = calculate_security_score(findings)
    summary = generate_report_summary("http://localhost:5000", score, grade, findings, breakdown)
    assert "85/100" in summary
    assert "Grade A" in summary
    assert "1 missing defensive control(s)" in summary


# ─── 6. Phase 3.1 Security Hardening & Edge Cases ────────────────────────────


def test_target_validator_rejects_obfuscated_ips():
    """Detects and rejects alternative and obfuscated IP representations."""
    # Hex notation
    with pytest.raises(TargetValidationError, match="Prohibited IP format"):
        validate_target_url("http://0x7f000001:8000")

    # Pure DWORD / integer notation
    with pytest.raises(TargetValidationError, match="Prohibited IP format"):
        validate_target_url("http://2130706433:8000")

    # Dotted octal notation
    with pytest.raises(TargetValidationError, match="Prohibited IP format"):
        validate_target_url("http://0177.0.0.1:8000")

    # Leading zero in octet
    with pytest.raises(TargetValidationError, match="Prohibited IP format"):
        validate_target_url("http://127.00.0.1:8000")

    # Shortened / non-canonical notation (e.g. 127.1)
    with pytest.raises(TargetValidationError, match="Prohibited IP format"):
        validate_target_url("http://127.1:8000")

    # Octet value out of range (256)
    with pytest.raises(TargetValidationError, match="Prohibited IP format"):
        validate_target_url("http://127.0.0.256:8000")


def test_target_validator_ipv6_brackets_and_mapping():
    """Ensures IPv6 loopback and mapped addresses are safely formatted and authorized."""
    # IPv6 loopback [::1]
    url, ip, port = validate_target_url("http://[::1]:8080/api")
    assert url == "http://[::1]:8080/api"
    assert ip == "::1"
    assert port == 8080

    # IPv4-mapped IPv6 loopback [::ffff:127.0.0.1]
    url2, ip2, port2 = validate_target_url("http://[::ffff:127.0.0.1]:5000")
    assert "127.0.0.1" in url2
    assert ip2 == "::ffff:127.0.0.1"
    assert port2 == 5000

    # IPv4-mapped metadata [::ffff:169.254.169.254] must be rejected
    with pytest.raises(TargetValidationError, match="Scanning prohibited"):
        validate_target_url("http://[::ffff:169.254.169.254]:80")

    # IPv6 link-local [fe80::1] must be rejected
    with pytest.raises(TargetValidationError, match="Scanning prohibited"):
        validate_target_url("http://[fe80::1]:80")


def test_target_validator_port_restrictions():
    """Blocks restricted system service ports and out-of-range ports."""
    # SSH port 22
    with pytest.raises(TargetValidationError, match="restricted system service port"):
        validate_target_url("http://localhost:22")

    # SMB port 445
    with pytest.raises(TargetValidationError, match="restricted system service port"):
        validate_target_url("http://localhost:445")

    # Telnet port 23
    with pytest.raises(TargetValidationError, match="restricted system service port"):
        validate_target_url("http://localhost:23")

    # Out-of-bounds port 0
    with pytest.raises(TargetValidationError, match="Invalid port number"):
        validate_target_url("http://localhost:0")

    # Out-of-bounds port 70000
    with pytest.raises(TargetValidationError, match="Invalid port number"):
        validate_target_url("http://localhost:70000")


def test_target_validator_multi_ip_resolution_check():
    """Rejects hostnames resolving to multiple IPs if ANY IP is unauthorized."""
    mock_addrinfo = [
        (2, 1, 6, "", ("127.0.0.1", 80)),
        (2, 1, 6, "", ("169.254.169.254", 80)),
    ]
    with (
        patch("socket.getaddrinfo", return_value=mock_addrinfo),
        pytest.raises(TargetValidationError, match="unauthorized destination"),
    ):
        validate_target_url("http://rebind-test.local:80")

    mock_private_split = [
        (2, 1, 6, "", ("127.0.0.1", 80)),
        (2, 1, 6, "", ("192.168.1.100", 80)),
    ]
    with (
        patch("socket.getaddrinfo", return_value=mock_private_split),
        pytest.raises(TargetValidationError, match="unauthorized destination"),
    ):
        validate_target_url("http://split-test.local:80")


def test_target_validator_length_limits():
    """Enforces maximum URL and hostname lengths."""
    # Excessive URL length (>2048 chars)
    long_url = "http://localhost:8000/" + ("a" * 2050)
    with pytest.raises(TargetValidationError, match="maximum allowed length"):
        validate_target_url(long_url)

    # Excessive hostname length (>253 chars)
    long_host = ("a" * 255) + ".local"
    with pytest.raises(TargetValidationError, match="maximum RFC 1035 length"):
        validate_target_url(f"http://{long_host}:8000")


def test_safe_redirect_handler_blocks_downgrade():
    """Blocks insecure redirects from HTTPS down to cleartext HTTP."""
    handler = SafeRedirectHandler()
    req = MagicMock()
    req.full_url = "https://localhost:8443/login"
    with pytest.raises(TargetValidationError, match="protocol downgrade"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://localhost:8000/insecure")


def test_safe_redirect_handler_blocks_prohibited_redirect():
    """Blocks redirects targeting cloud metadata or prohibited IPs."""
    handler = SafeRedirectHandler()
    req = MagicMock()
    req.full_url = "http://localhost:5000/redirect"
    with pytest.raises(TargetValidationError, match="Scanning prohibited"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://169.254.169.254/latest/")


def test_safe_redirect_handler_max_redirects_exceeded():
    """Enforces maximum redirect hop limit."""
    handler = SafeRedirectHandler(max_redirects=2)
    req = urllib.request.Request("http://localhost:5000/step1", method="GET")
    # Hop 1
    handler.redirect_request(req, None, 302, "Found", {}, "http://localhost:5000/step2")
    # Hop 2
    handler.redirect_request(req, None, 302, "Found", {}, "http://localhost:5000/step3")
    # Hop 3 -> exceeds limit 2
    with pytest.raises(TargetValidationError, match="Exceeded maximum allowed redirects"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://localhost:5000/step4")


def test_safe_redirect_handler_relative_redirect():
    """Properly joins and validates relative redirect paths."""
    handler = SafeRedirectHandler()
    req = urllib.request.Request("http://localhost:5000/login", method="GET")
    # Should resolve /dashboard against http://localhost:5000/login -> http://localhost:5000/dashboard
    new_req = handler.redirect_request(req, None, 302, "Found", {}, "/dashboard")
    assert new_req is not None
    assert new_req.full_url == "http://localhost:5000/dashboard"


def test_pinned_http_connection_uses_verified_ip():
    """Verifies that PinnedHTTPConnection connects to the pre-verified IP to prevent rebinding."""
    from app.scanner.target_validator import PinnedHTTPConnection

    conn_cls = type(
        "TestPinnedConn",
        (PinnedHTTPConnection,),
        {"verified_hosts": {"rebinding-target.local": "127.0.0.1"}},
    )
    conn = conn_cls("rebinding-target.local", port=8080)
    with patch("socket.create_connection") as mock_create_conn:
        conn.connect()
        mock_create_conn.assert_called_once()
        args, _kwargs = mock_create_conn.call_args
        # Confirms the raw socket was connected to the pinned IP '127.0.0.1', NOT the hostname
        assert args[0] == ("127.0.0.1", 8080)


def test_build_safe_opener_structure():
    """Verifies build_safe_opener configures SafeRedirectHandler and Pinned handlers."""
    from app.scanner.target_validator import (
        PinnedHTTPHandler,
        PinnedHTTPSHandler,
        SafeRedirectHandler,
        build_safe_opener,
    )

    opener = build_safe_opener(target_ip="127.0.0.1", hostname="localhost")
    handler_classes = [type(h) for h in opener.handlers]
    assert SafeRedirectHandler in handler_classes
    assert PinnedHTTPHandler in handler_classes
    assert PinnedHTTPSHandler in handler_classes


def test_pdf_generator_creates_valid_pdf():
    """Generates a binary PDF report and verifies PDF signature and minimum payload size."""
    from app.scanner.pdf_generator import generate_report_pdf

    sample_report = {
        "id": "RPT-UNIT01",
        "scanId": "SCN-UNIT01",
        "target": "http://localhost:5000/",
        "scannedAt": "2026-10-12T16:00:00Z",
        "securityScore": 82,
        "status": "ready",
        "summary": "Sample report executive summary narrative.",
        "severityBreakdown": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
        "findings_list": [
            {
                "id": "F-01",
                "title": "Missing Content-Security-Policy Header",
                "severity": "high",
                "category": "headers",
                "type": "missing_control",
                "description": "CSP header absent.",
                "evidence": "Header Content-Security-Policy not detected.",
                "recommendation": "Configure a strict Content-Security-Policy.",
                "location": "HTTP Headers",
            }
        ],
    }

    pdf_bytes = generate_report_pdf(sample_report)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000


def test_pdf_generator_handles_empty_findings():
    """Generates a clean PDF report when no findings were observed."""
    from app.scanner.pdf_generator import generate_report_pdf

    clean_report = {
        "id": "RPT-CLEAN01",
        "scanId": "SCN-CLEAN01",
        "target": "http://localhost:8000/",
        "scannedAt": "2026-10-12T16:00:00Z",
        "securityScore": 100,
        "status": "ready",
        "summary": "All controls active.",
        "severityBreakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "findings_list": [],
    }

    pdf_bytes = generate_report_pdf(clean_report)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1500


