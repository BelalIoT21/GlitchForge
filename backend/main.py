"""
GlitchForge Backend - Entry Point

Run with: python main.py
"""

import sys
from pathlib import Path

# Ensure the backend directory is on the path so 'app' is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import create_app
from app.config import FLASK_PORT
from app.services.engine import init_engine

app = create_app()


if __name__ == '__main__':
    print("=" * 70)
    print(" " * 20 + "GLITCHFORGE BACKEND")
    print(" " * 15 + "AI-Enhanced Vulnerability Scanner")
    print("=" * 70)

    print("\nInitializing GlitchForge Engine...")
    init_engine()
    print("Engine ready!")

    print(f"\nStarting server on http://0.0.0.0:{FLASK_PORT}")
    print("\nAvailable Endpoints:")
    print("   GET  /health           - Health check")
    print("   GET  /api/status       - Engine status")
    print("   POST /api/scan         - Complete scan & analysis")
    print("   POST /api/quick-scan   - Quick vulnerability scan")
    print("\n" + "=" * 70)
    print("Press CTRL+C to stop\n")

    app.run(
        host='0.0.0.0',
        port=FLASK_PORT,
        debug=True,
        threaded=True
    )
