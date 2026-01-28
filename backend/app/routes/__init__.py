"""
Route blueprint registration
"""

from app.routes.health import health_bp
from app.routes.scan import scan_bp


def register_blueprints(app):
    """Register all route blueprints with the app."""
    app.register_blueprint(health_bp)
    app.register_blueprint(scan_bp)
