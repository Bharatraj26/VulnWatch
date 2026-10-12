"""
VulnWatch Backend Server Runner
================================
Runs the Flask application on the configured host and port.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.core.config import Config

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", Config.PORT))
    host = os.environ.get("HOST", Config.HOST)
    debug = os.environ.get("FLASK_DEBUG", str(Config.DEBUG)).lower() in ("true", "1")
    print(f"[*] VulnWatch Flask server running on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
