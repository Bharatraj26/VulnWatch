"""
VulnWatch — Flask Application Factory
=======================================
Creates and configures the Flask application.
Supports API endpoints, SQLite persistence, CORS, and optional static UI serving.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

from app.api.v1.endpoints.health import health_bp
from app.api.v1.endpoints.reports import reports_bp
from app.api.v1.endpoints.scans import scans_bp
from app.core.config import Config
from app.core.database import close_db, init_db


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create and configure an instance of the Flask application."""
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

    app = Flask(
        __name__,
        static_folder=str(frontend_dist / "assets") if (frontend_dist / "assets").exists() else None,
        static_url_path="/assets",
    )

    if test_config is None:
        app.config.from_object(Config)
    else:
        app.config.from_mapping(test_config)

    # CORS configuration with exposed headers for file downloads
    cors_origins = app.config.get("CORS_ORIGINS", ["*"])
    CORS(
        app,
        resources={r"/api/*": {"origins": cors_origins}},
        expose_headers=["Content-Disposition", "Content-Type", "Content-Length"],
    )

    # Teardown database connection after request
    app.teardown_appcontext(close_db)

    # Initialize SQLite database tables
    init_db(app)

    # Register API blueprints
    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")

    # Frontend serving (HTML, CSS, JS) if built
    if frontend_dist.exists() and (frontend_dist / "index.html").exists():
        @app.route("/", defaults={"path": ""})
        @app.route("/<path:path>")
        def serve_ui(path: str):
            # Do NOT serve index.html for API requests that were not matched
            if path.startswith("api/") or path == "api":
                return jsonify({"detail": f"API endpoint '/{path}' not found."}), 404

            target_path = frontend_dist / path
            if path and target_path.exists() and not target_path.is_dir():
                return send_from_directory(str(frontend_dist), path)
            return send_from_directory(str(frontend_dist), "index.html")
    else:
        @app.route("/")
        def index():
            return jsonify({
                "service": "VulnWatch — Automated Web Security Testing Platform",
                "version": "1.2.0",
                "api_health": "/api/health",
                "docs": "Educational security testing platform. Passive scanning only.",
            })

    return app
