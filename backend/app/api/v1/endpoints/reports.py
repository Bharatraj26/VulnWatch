"""
VulnWatch — Reports Endpoints (Phase 3 Integration)
====================================================
Retrieves generated security audit reports from SQLite.
Supports JSON inspection and binary PDF report generation.
"""

from __future__ import annotations

import io
import json
import logging
from typing import Any

from flask import Blueprint, jsonify, request, send_file

from app.core.database import get_db
from app.scanner.pdf_generator import generate_report_pdf

logger = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__)


def clean_identifier(raw_id: str) -> str:
    """Strip whitespace and common file extensions from report/scan identifier."""
    cleaned = raw_id.strip()
    if cleaned.lower().endswith(".pdf"):
        cleaned = cleaned[:-4]
    elif cleaned.lower().endswith(".json"):
        cleaned = cleaned[:-5]
    return cleaned.strip()


def fetch_report_data(report_or_scan_id: str) -> dict[str, Any] | None:
    """Helper to query report and related findings from SQLite."""
    clean_id = clean_identifier(report_or_scan_id)
    db = get_db()
    row = db.execute(
        """
        SELECT * FROM reports
        WHERE id = ? OR scan_id = ?;
        """,
        (clean_id, clean_id),
    ).fetchone()

    if not row:
        return None

    scan_id = row["scan_id"]
    findings_cursor = db.execute(
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
    )
    finding_rows = findings_cursor.fetchall()

    findings_list = [
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
        for f in finding_rows
    ]

    return {
        "id": row["id"],
        "scanId": row["scan_id"],
        "target": row["target"],
        "scannedAt": row["scanned_at"],
        "securityScore": row["security_score"],
        "findings": row["finding_count"],
        "status": row["status"],
        "severityBreakdown": {
            "critical": row["critical_count"],
            "high": row["high_count"],
            "medium": row["medium_count"],
            "low": row["low_count"],
            "info": row["info_count"],
        },
        "summary": row["summary"],
        "findings_list": findings_list,
    }


@reports_bp.route("", methods=["GET"], strict_slashes=False)
def list_reports():
    """
    Returns list of all generated reports from SQLite.
    """
    db = get_db()
    cursor = db.execute(
        """
        SELECT id, scan_id, target, scanned_at, security_score, finding_count,
               critical_count, high_count, medium_count, low_count, info_count, status
        FROM reports
        ORDER BY scanned_at DESC;
        """
    )
    rows = cursor.fetchall()

    reports = [
        {
            "id": row["id"],
            "scanId": row["scan_id"],
            "target": row["target"],
            "scannedAt": row["scanned_at"],
            "securityScore": row["security_score"],
            "findings": row["finding_count"],
            "status": row["status"],
            "severityBreakdown": {
                "critical": row["critical_count"],
                "high": row["high_count"],
                "medium": row["medium_count"],
                "low": row["low_count"],
                "info": row["info_count"],
            },
        }
        for row in rows
    ]

    return jsonify(reports), 200


@reports_bp.route("/<report_or_scan_id>", methods=["GET"], strict_slashes=False)
def get_report(report_or_scan_id: str):
    """
    Returns detailed security report matching ReportDetail interface.
    Searches by either report ID (RPT-*) or scan ID (SCN-*).
    """
    report = fetch_report_data(report_or_scan_id)
    if not report:
        return jsonify({
            "detail": f"Report for '{report_or_scan_id}' not found."
        }), 404

    return jsonify(report), 200


@reports_bp.route("/<report_or_scan_id>/pdf", methods=["GET"], strict_slashes=False)
@reports_bp.route("/<report_or_scan_id>.pdf", methods=["GET"], strict_slashes=False)
def download_report_pdf(report_or_scan_id: str):
    """
    Generates and downloads a complete PDF security assessment report.
    """
    clean_id = clean_identifier(report_or_scan_id)
    report = fetch_report_data(clean_id)
    if not report:
        return jsonify({
            "detail": f"Report for '{report_or_scan_id}' not found."
        }), 404

    try:
        pdf_bytes = generate_report_pdf(report)
    except Exception as exc:
        logger.exception("Failed to generate report PDF for %s", report_or_scan_id)
        return jsonify({
            "detail": f"Failed to generate report PDF: {exc}"
        }), 500

    safe_id = "".join(c for c in report["id"] if c.isalnum() or c in ("-", "_"))
    filename = f"vulnwatch-report-{safe_id}.pdf"

    response = send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@reports_bp.route("/<report_or_scan_id>/download", methods=["GET"], strict_slashes=False)
def download_report(report_or_scan_id: str):
    """
    Unified report download endpoint supporting ?format=pdf (default) and ?format=json.
    """
    fmt = request.args.get("format", "pdf").lower()
    clean_id = clean_identifier(report_or_scan_id)
    report = fetch_report_data(clean_id)
    if not report:
        return jsonify({
            "detail": f"Report for '{report_or_scan_id}' not found."
        }), 404

    safe_id = "".join(c for c in report["id"] if c.isalnum() or c in ("-", "_"))

    if fmt == "json":
        filename = f"vulnwatch-report-{safe_id}.json"
        json_bytes = json.dumps(report, indent=2).encode("utf-8")
        response = send_file(
            io.BytesIO(json_bytes),
            mimetype="application/json",
            as_attachment=True,
            download_name=filename,
        )
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    # Default: PDF
    try:
        pdf_bytes = generate_report_pdf(report)
    except Exception as exc:
        logger.exception("Failed to generate report PDF for %s", report_or_scan_id)
        return jsonify({
            "detail": f"Failed to generate report PDF: {exc}"
        }), 500

    filename = f"vulnwatch-report-{safe_id}.pdf"
    response = send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response
