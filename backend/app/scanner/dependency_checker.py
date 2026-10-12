"""
VulnWatch Scanner — Local Project Dependency Audit
===================================================
Audits local project dependencies against a documented offline sample advisory
baseline for educational demonstration.

Note: This is an offline baseline check for key framework components and does NOT
replace a live, comprehensive CVE vulnerability feed (such as pip-audit or OSV).
"""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path
from typing import Any


def check_project_dependencies(requirements_file: Path | None = None) -> list[dict[str, Any]]:
    """
    Audit local dependencies listed in requirements.txt against a sample offline advisory baseline.
    Returns findings if vulnerable versions are detected.
    """
    findings: list[dict[str, Any]] = []

    if requirements_file is None:
        requirements_file = Path(__file__).resolve().parent.parent.parent / "requirements.txt"

    if not requirements_file.exists():
        return findings

    try:
        content = requirements_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return findings

    known_vulnerabilities = {
        "flask": {
            "min_version": "2.2.5",
            "cve": "CVE-2023-30861",
            "description": "Versions prior to 2.2.5 had a cookie session disclosure vulnerability.",
        },
        "werkzeug": {
            "min_version": "3.0.3",
            "cve": "CVE-2024-34069",
            "description": "Versions prior to 3.0.3 are vulnerable to IP spoofing via Client-IP headers.",
        },
        "jinja2": {
            "min_version": "3.1.4",
            "cve": "CVE-2024-34064",
            "description": "Versions prior to 3.1.4 contain an HTML attribute injection vulnerability.",
        },
        "urllib3": {
            "min_version": "2.2.2",
            "cve": "CVE-2024-37891",
            "description": "Versions prior to 2.2.2 incorrectly handled Proxy-Authorization headers on redirect.",
        },
    }

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match = re.match(r"^([a-zA-Z0-9_\-]+)", line)
        if not match:
            continue

        pkg_name = match.group(1).lower()
        if pkg_name in known_vulnerabilities:
            rule = known_vulnerabilities[pkg_name]
            try:
                installed_ver = importlib.metadata.version(pkg_name)
                installed_parts = [int(p) for p in re.findall(r"\d+", installed_ver)[:3]]
                min_parts = [int(p) for p in re.findall(r"\d+", rule["min_version"])[:3]]

                if installed_parts < min_parts:
                    findings.append({
                        "title": f"Vulnerable Dependency Version: {pkg_name} ({installed_ver})",
                        "severity": "high",
                        "category": "dependencies",
                        "type": "vulnerability",
                        "description": (
                            f"{rule['description']} ({rule['cve']}). "
                            "Identified via offline sample advisory baseline check."
                        ),
                        "evidence": f"Installed: {pkg_name}=={installed_ver}; required minimum: >={rule['min_version']}",
                        "recommendation": f"Upgrade '{pkg_name}' to version {rule['min_version']} or later in requirements.txt.",
                        "location": f"requirements.txt -> {pkg_name}",
                    })
            except importlib.metadata.PackageNotFoundError:
                continue

    return findings
