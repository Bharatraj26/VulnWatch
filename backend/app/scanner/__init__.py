"""
VulnWatch Scanner Engine
========================
Coordinates target validation, HTTP fetching via safe redirect handling,
security evaluation modules, and score calculation.
"""

from __future__ import annotations

import datetime
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from app.scanner.config_checks import check_configuration
from app.scanner.cookie_checks import check_cookies
from app.scanner.dependency_checker import check_project_dependencies
from app.scanner.header_checks import check_security_headers
from app.scanner.scoring import (
    calculate_security_score,
    generate_report_summary,
    get_highest_severity,
)
from app.scanner.target_validator import (
    SafeRedirectHandler,
    TargetValidationError,
    build_safe_opener,
    validate_target_url,
)

__all__ = [
    "SafeRedirectHandler",
    "ScanExecutionResult",
    "TargetValidationError",
    "execute_scan",
]

MAX_RESPONSE_BYTES = 1_048_576  # 1 MB maximum response body read
MAX_HEADERS_COUNT = 100         # Maximum number of response headers processed


class ScanExecutionResult:
    """Encapsulates the complete result of a scan execution."""

    def __init__(
        self,
        target_url: str,
        scan_type: str,
        status: str,
        started_at: str,
        completed_at: str,
        duration: float,
        http_status: int | None,
        target_ip: str | None,
        findings: list[dict[str, Any]],
        score: int,
        grade: str,
        breakdown: dict[str, int],
        summary: str,
        error_message: str | None = None,
    ):
        self.target_url = target_url
        self.scan_type = scan_type
        self.status = status
        self.started_at = started_at
        self.completed_at = completed_at
        self.duration = duration
        self.http_status = http_status
        self.target_ip = target_ip
        self.findings = findings
        self.score = score
        self.grade = grade
        self.breakdown = breakdown
        self.summary = summary
        self.error_message = error_message
        self.severity = get_highest_severity(findings)


def execute_scan(
    target_url: str,
    scan_type: str = "basic",
    allowed_targets: list[str] | None = None,
    timeout: float = 6.0,
) -> ScanExecutionResult:
    """
    Safely execute passive security checks against an authorized local target.
    """
    start_time = time.time()
    started_at = datetime.datetime.now(datetime.UTC).isoformat()

    # Step 1: Target validation & SSRF prevention
    normalized_url, target_ip, port = validate_target_url(target_url, allowed_targets)
    parsed = urllib.parse.urlsplit(normalized_url)
    is_https = parsed.scheme.lower() == "https"

    findings: list[dict[str, Any]] = []
    http_status: int | None = None
    headers_dict: dict[str, str] = {}
    raw_cookies: list[str] = []
    allowed_methods: list[str] = []
    error_message: str | None = None
    status = "completed"

    # Step 2: Fetch target using secure, pinned opener (DNS rebinding & open redirect immune)
    target_host = parsed.hostname or "localhost"
    opener = build_safe_opener(
        target_ip=target_ip,
        hostname=target_host,
        allowed_targets=allowed_targets,
    )
    req = urllib.request.Request(
        normalized_url,
        headers={"User-Agent": "VulnWatch-Scanner/0.1 (Passive Security Audit; Educational)"},
    )

    try:
        with opener.open(req, timeout=timeout) as response:
            http_status = response.status
            for idx, (key, val) in enumerate(response.headers.items()):
                if idx >= MAX_HEADERS_COUNT:
                    break
                headers_dict[key] = val
            raw_cookies = response.headers.get_all("Set-Cookie") or []
            # Bounded response read to prevent streaming resource exhaustion
            _ = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        http_status = exc.code
        for idx, (key, val) in enumerate(exc.headers.items()):
            if idx >= MAX_HEADERS_COUNT:
                break
            headers_dict[key] = val
        raw_cookies = exc.headers.get_all("Set-Cookie") or []
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        status = "failed"
        error_message = f"Connection failed: {exc}"
        findings.append({
            "title": "Target Connection Failure",
            "severity": "medium",
            "category": "transport",
            "type": "missing_control",
            "description": f"Could not establish a connection to target '{normalized_url}': {exc}.",
            "evidence": str(exc),
            "recommendation": "Ensure the target application is running and accessible on the specified host and port.",
            "location": "Network / Target Endpoint",
        })

    # Step 3: Run specific check modules if connection was made
    if status == "completed":
        from app.scanner.transport_checks import check_transport
        findings.extend(check_transport(normalized_url, port))

        if scan_type in ("basic", "headers", "full"):
            findings.extend(check_security_headers(headers_dict, is_https=is_https))

        if scan_type in ("cookies", "full"):
            findings.extend(check_cookies(raw_cookies, is_https=is_https))

        if scan_type in ("headers", "full"):
            if scan_type == "full":
                try:
                    options_req = urllib.request.Request(
                        normalized_url,
                        method="OPTIONS",
                        headers={"User-Agent": "VulnWatch-Scanner/0.1"},
                    )
                    with opener.open(options_req, timeout=timeout) as opt_resp:
                        allow_hdr = opt_resp.headers.get("Allow") or opt_resp.headers.get("Public")
                        if allow_hdr:
                            allowed_methods = [m.strip() for m in allow_hdr.split(",")]
                        _ = opt_resp.read(MAX_RESPONSE_BYTES)
                except (urllib.error.URLError, TimeoutError, OSError):
                    pass
            findings.extend(check_configuration(headers_dict, allowed_methods))

        if scan_type == "full":
            findings.extend(check_project_dependencies())

    # Calculate score & summary
    score, grade, breakdown = calculate_security_score(findings)
    summary = generate_report_summary(normalized_url, score, grade, findings, breakdown)

    end_time = time.time()
    completed_at = datetime.datetime.now(datetime.UTC).isoformat()
    duration = round(end_time - start_time, 2)

    return ScanExecutionResult(
        target_url=normalized_url,
        scan_type=scan_type,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration=duration,
        http_status=http_status,
        target_ip=target_ip,
        findings=findings,
        score=score,
        grade=grade,
        breakdown=breakdown,
        summary=summary,
        error_message=error_message,
    )
