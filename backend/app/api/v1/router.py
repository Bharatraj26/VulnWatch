"""
VulnWatch — API v1 Router Blueprint
====================================
Aggregates all API endpoints into a cohesive Flask Blueprint.
"""

from __future__ import annotations

from flask import Blueprint

from app.api.v1.endpoints.health import health_bp
from app.api.v1.endpoints.reports import reports_bp
from app.api.v1.endpoints.scans import scans_bp

api_router = Blueprint("api_v1", __name__)

api_router.register_blueprint(health_bp)
api_router.register_blueprint(scans_bp, prefix="/scans")
api_router.register_blueprint(reports_bp, prefix="/reports")
