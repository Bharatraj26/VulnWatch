"""
VulnWatch — Health Endpoint (Flask)
=====================================
GET /api/health

Returns JSON confirming API is operational:
{
  "status": "ok",
  "service": "VulnWatch API"
}
"""

from __future__ import annotations

from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Returns application health status."""
    return jsonify({
        "status": "ok",
        "service": "VulnWatch API"
    }), 200
