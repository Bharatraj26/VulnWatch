"""
VulnWatch Backend — Application Entry Point
============================================
Creates the Flask application instance using the application factory.
"""

from __future__ import annotations

from app import create_app

app = create_app()

if __name__ == "__main__":
    from app.core.config import Config

    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
    )
