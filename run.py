"""
VulnWatch Application Runner (Root Entry Point)
===============================================
Convenience runner to start the VulnWatch Flask application from the project root.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from app.core.config import Config

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", Config.PORT))
    host = os.environ.get("HOST", Config.HOST)
    debug = os.environ.get("FLASK_DEBUG", str(Config.DEBUG)).lower() in ("true", "1")
    print(f"[*] VulnWatch application starting at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
