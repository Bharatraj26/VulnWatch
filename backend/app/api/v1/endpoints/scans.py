"""
VulnWatch — Scans Endpoints (Phase 3 Scanner Integration)
==========================================================
Handles scan execution, database persistence, and scan retrieval.
"""

from __future__ import annotations

import sqlite3
import urllib.error
import uuid

from flask import Blueprint, current_app, jsonify, request

from app.core.database import get_db
from app.scanner import execute_scan
from app.scanner.target_validator import TargetValidationError

scans_bp = Blueprint("scans", __name__)


@scans_bp.route("/stats", methods=["GET"])
def get_stats():
    """
    Returns calculated summary statistics for the dashboard directly from SQLite.
    """
    db = get_db()
    total_scans = db.execute("SELECT COUNT(*) as count FROM scans;").fetchone()["count"]
    total_findings = db.execute("SELECT COUNT(*) as count FROM findings;").fetchone()["count"]
    critical_issues = db.execute(
        "SELECT COUNT(*) as count FROM findings WHERE severity = 'critical';"
    ).fetchone()["count"]
    last_scan_row = db.execute(
        "SELECT started_at, target_url FROM scans ORDER BY started_at DESC LIMIT 1;"
    ).fetchone()

    sev_cursor = db.execute("SELECT severity, COUNT(*) as count FROM findings GROUP BY severity;")
    sev_map = {row["severity"]: row["count"] for row in sev_cursor.fetchall()}

    return jsonify({
        "totalScans": total_scans,
        "vulnerabilitiesFound": total_findings,
        "criticalIssues": critical_issues,
        "lastScan": last_scan_row["started_at"] if last_scan_row else None,
        "lastScanTarget": last_scan_row["target_url"] if last_scan_row else None,
        "severityTotals": {
            "critical": sev_map.get("critical", 0),
            "high": sev_map.get("high", 0),
            "medium": sev_map.get("medium", 0),
            "low": sev_map.get("low", 0),
            "info": sev_map.get("info", 0),
        },
    }), 200


@scans_bp.route("", methods=["GET"])
def list_scans():
    """
    Returns list of all scans stored in the SQLite database.
    """
    db = get_db()
    cursor = db.execute(
        """
        SELECT id, target_url, scan_type, status, started_at, completed_at,
               duration, findings_count, severity
        FROM scans
        ORDER BY started_at DESC;
        """
    )
    rows = cursor.fetchall()

    scans = [
        {
            "id": row["id"],
            "target": row["target_url"],
            "scanType": row["scan_type"],
            "status": row["status"],
            "startedAt": row["started_at"],
            "completedAt": row["completed_at"],
            "duration": row["duration"],
            "findings": row["findings_count"],
            "severity": row["severity"],
        }
        for row in rows
    ]

    return jsonify(scans), 200


@scans_bp.route("/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """
    Returns detailed scan record with all associated findings.
    """
    db = get_db()
    scan_row = db.execute(
        "SELECT * FROM scans WHERE id = ?;", (scan_id,)
    ).fetchone()

    if not scan_row:
        return jsonify({
            "detail": f"Scan '{scan_id}' not found."
        }), 404

    findings_rows = db.execute(
        """
        SELECT id, title, severity, category, type, description, evidence, recommendation, location
        FROM findings
        WHERE scan_id = ?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END;
        """,
        (scan_id,),
    ).fetchall()

    findings = [
        {
            "id": f["id"],
            "title": f["title"],
            "severity": f["severity"],
            "category": f["category"],
            "type": f["type"],
            "description": f["description"],
            "evidence": f["evidence"],
            "recommendation": f["recommendation"],
            "location": f["location"],
        }
        for f in findings_rows
    ]

    return jsonify({
        "id": scan_row["id"],
        "target": scan_row["target_url"],
        "scanType": scan_row["scan_type"],
        "status": scan_row["status"],
        "startedAt": scan_row["started_at"],
        "completedAt": scan_row["completed_at"],
        "duration": scan_row["duration"],
        "findings": scan_row["findings_count"],
        "severity": scan_row["severity"],
        "httpStatus": scan_row["http_status"],
        "targetIp": scan_row["target_ip"],
        "errorMessage": scan_row["error_message"],
        "findingsList": findings,
    }), 200


@scans_bp.route("", methods=["POST"])
def create_scan():
    """
    Executes a security scan against an authorized target and saves results to SQLite.
    Restricted to localhost/loopback addresses.
    """
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url")
    scan_type = (data.get("scan_type") or "basic").lower()

    if not target_url:
        return jsonify({"detail": "target_url is required."}), 400

    if scan_type not in ("basic", "headers", "cookies", "full"):
        return jsonify({
            "detail": f"Invalid scan_type '{scan_type}'. Allowed: basic, headers, cookies, full."
        }), 400

    allowed_targets = current_app.config.get("ALLOWED_TARGETS", ["localhost", "127.0.0.1", "::1"])

    # Execute scanner
    try:
        result = execute_scan(
            target_url=target_url,
            scan_type=scan_type,
            allowed_targets=allowed_targets,
        )
    except TargetValidationError as exc:
        return jsonify({
            "detail": f"Target authorization error: {exc}"
        }), 400
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # Sanitize error detail to prevent system path or internals exposure
        clean_msg = str(exc).splitlines()[0] if str(exc) else "Unable to establish connection to target."
        return jsonify({
            "detail": f"Scanner connection error: {clean_msg}"
        }), 502

    # Store in SQLite database
    db = get_db()
    scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"
    report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"

    try:
        db.execute(
            """
            INSERT INTO scans (
                id, target_url, scan_type, status, started_at, completed_at,
                duration, findings_count, severity, target_ip, http_status, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                scan_id,
                result.target_url,
                result.scan_type,
                result.status,
                result.started_at,
                result.completed_at,
                result.duration,
                len(result.findings),
                result.severity,
                result.target_ip,
                result.http_status,
                result.error_message,
            ),
        )

        # Insert findings
        for finding in result.findings:
            finding_id = f"F-{uuid.uuid4().hex[:8].upper()}"
            db.execute(
                """
                INSERT INTO findings (
                    id, scan_id, title, severity, category, type, description, evidence, recommendation, location
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    finding_id,
                    scan_id,
                    finding.get("title", "Untitled finding"),
                    finding.get("severity", "info"),
                    finding.get("category", "general"),
                    finding.get("type", "missing_control"),
                    finding.get("description", ""),
                    finding.get("evidence", ""),
                    finding.get("recommendation", ""),
                    finding.get("location", ""),
                ),
            )

        # Insert report
        db.execute(
            """
            INSERT INTO reports (
                id, scan_id, target, scanned_at, security_score, finding_count,
                critical_count, high_count, medium_count, low_count, info_count, summary, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                report_id,
                scan_id,
                result.target_url,
                result.completed_at,
                result.score,
                len(result.findings),
                result.breakdown["critical"],
                result.breakdown["high"],
                result.breakdown["medium"],
                result.breakdown["low"],
                result.breakdown["info"],
                result.summary,
                "ready",
            ),
        )
        db.commit()
    except (sqlite3.Error, OSError):
        db.rollback()
        return jsonify({
            "detail": "Failed to persist scan record to database."
        }), 500

    return jsonify({
        "id": scan_id,
        "reportId": report_id,
        "target": result.target_url,
        "scanType": result.scan_type,
        "status": result.status,
        "startedAt": result.started_at,
        "completedAt": result.completed_at,
        "duration": result.duration,
        "findings": len(result.findings),
        "severity": result.severity,
        "score": result.score,
        "grade": result.grade,
        "message": f"Scan completed with security score {result.score}/100.",
    }), 201
