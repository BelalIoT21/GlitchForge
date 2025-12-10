"""
GlitchForge Production Server - Waitress WSGI

Production-ready server using Waitress (works on Windows, Linux, and macOS).
Handles multiple concurrent requests efficiently.

Usage:
    python main.py

Configuration:
    - Threads: 8 concurrent requests
    - Timeout: 300s (5 minutes for full scans)
    - Host: 0.0.0.0 (accessible from network)
    - Port: 5000

For development/testing with Flask dev server:
    Set FLASK_ENV=development and uncomment Flask dev server code
"""

import sys
import logging
from pathlib import Path
import multiprocessing

# Ensure backend directory is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Configure root logging to show all scanner output
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    stream=sys.stdout
)
# Force immediate output
for handler in logging.root.handlers:
    handler.flush()

from waitress import serve
from app import create_app
from app.services.engine import init_engine

# Number of threads to handle concurrent requests
# Increase this for more concurrency (recommended: 4-16)
THREADS = 8

# Host and port
HOST = '0.0.0.0'
PORT = 5000

# Channel timeout (for long-running scans)
# Full scans can take 2-5 minutes depending on target complexity and payload count
CHANNEL_TIMEOUT = 300  # 5 minutes

def main():
    """Start the production server"""
    print("=" * 70)
    print(" " * 20 + "GLITCHFORGE PRODUCTION")
    print(" " * 15 + "AI-Enhanced Vulnerability Scanner")
    print(" " * 22 + "(Windows/Waitress)")
    print("=" * 70)

    print("\nInitializing GlitchForge Engine...")
    init_engine()
    print("Engine ready! Models loaded in memory.\n")

    print(f"Configuration:")
    print(f"  Server: Waitress WSGI Server")
    print(f"  Host: {HOST}:{PORT}")
    print(f"  Threads: {THREADS} (concurrent request capacity)")
    print(f"  Timeout: {CHANNEL_TIMEOUT}s")
    print(f"  CPU Cores: {multiprocessing.cpu_count()}")

    print(f"\nStarting server on http://{HOST}:{PORT}")
    print("\nAvailable Endpoints:")
    print("   GET  /health           - Health check")
    print("   GET  /api/status       - Engine status")
    print("   POST /api/scan         - Complete scan & analysis")
    print("   POST /api/quick-scan   - Quick vulnerability scan")
    print("\n" + "=" * 70)
    print("Server is ready! Press CTRL+C to stop\n")

    # Create Flask app
    app = create_app()

    # Serve with Waitress
    try:
        serve(
            app,
            host=HOST,
            port=PORT,
            threads=THREADS,
            channel_timeout=CHANNEL_TIMEOUT,
            url_scheme='http',
            # Connection settings
            connection_limit=1000,
            cleanup_interval=30,
            # Suppress Waitress "Serving on" message (we print our own)
            _quiet=True
        )
    except KeyboardInterrupt:
        print("\n\nShutting down GlitchForge...")
        print("Server stopped.\n")
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
