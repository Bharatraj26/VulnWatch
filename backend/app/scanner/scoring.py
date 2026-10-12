"""
VulnWatch Scanner — Security Scoring & Evaluation
==================================================
Transparent, deterministic scoring methodology based on defensive gaps
and detected weaknesses.

Scoring Formula:
- Base Score: 100 points
- Deductions:
    - Critical severity: -25 points
    - High severity:     -15 points
    - Medium severity:   -8 points
    - Low severity:      -3 points
    - Info severity:      0 points
- Final Score: max(0, min(100, 100 - sum(deductions)))

Grade Scale:
- 85 – 100: Grade A (Strong posture; basic defensive controls active)
- 70 – 84:  Grade B (Satisfactory; minor header or cookie attributes missing)
- 50 – 69:  Grade C (Moderate risk; multiple defensive controls absent)
- 30 – 49:  Grade D (Elevated risk; critical headers or transport missing)
- 0 – 29:   Grade F (High risk; widespread absence of transport and injection protections)
"""

from __future__ import annotations

from typing import Any

DEDUCTION_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def calculate_security_score(findings: list[dict[str, Any]]) -> tuple[int, str, dict[str, int]]:
    """
    Calculate the 0–100 security score and severity breakdown.
    Returns (score, grade, breakdown_dict).
    """
    breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    deductions = 0
    for finding in findings:
        sev = finding.get("severity", "info").lower()
        if sev not in breakdown:
            sev = "info"
        breakdown[sev] += 1
        deductions += DEDUCTION_WEIGHTS.get(sev, 0)

    score = max(0, min(100, 100 - deductions))

    if score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return score, grade, breakdown


def get_highest_severity(findings: list[dict[str, Any]]) -> str:
    """Determine the highest severity level among the findings."""
    if not findings:
        return "info"

    for sev in SEVERITY_ORDER:
        if any(f.get("severity", "").lower() == sev for f in findings):
            return sev
    return "info"


def generate_report_summary(
    target_url: str,
    score: int,
    grade: str,
    findings: list[dict[str, Any]],
    breakdown: dict[str, int],
) -> str:
    """Generate a clear, human-readable summary for the scan report."""
    total = len(findings)
    missing_controls = sum(1 for f in findings if f.get("type") == "missing_control")
    vulnerabilities = sum(1 for f in findings if f.get("type") == "vulnerability")

    if total == 0:
        return (
            f"Passive security inspection of '{target_url}' completed with an excellent score of {score}/100 (Grade {grade}). "
            "All expected HTTP security headers and defensive controls were observed in place."
        )

    parts = [
        f"Passive security assessment of '{target_url}' resulted in a security score of {score}/100 (Grade {grade}).",
        f"A total of {total} observation(s) were identified: {missing_controls} missing defensive control(s) and {vulnerabilities} confirmed weakness(es).",
    ]

    breakdown_text = []
    if breakdown["critical"] > 0:
        breakdown_text.append(f"{breakdown['critical']} critical")
    if breakdown["high"] > 0:
        breakdown_text.append(f"{breakdown['high']} high")
    if breakdown["medium"] > 0:
        breakdown_text.append(f"{breakdown['medium']} medium")
    if breakdown["low"] > 0:
        breakdown_text.append(f"{breakdown['low']} low")

    if breakdown_text:
        parts.append(f"Severity breakdown: {', '.join(breakdown_text)}.")

    if breakdown["critical"] > 0 or breakdown["high"] > 0:
        parts.append("Immediate remediation is recommended for high and critical priority items.")
    else:
        parts.append("Review recommendations below to harden the application against common web attacks.")

    return " ".join(parts)
