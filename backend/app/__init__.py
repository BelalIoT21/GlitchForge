"""
GlitchForge Application Factory

Creates and configures the Flask application with security features:
- CORS configuration
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Rate limiting middleware
- Authentication support
"""

import os
from flask import Flask
from flask_cors import CORS

from app.config import CORS_ORIGINS, SECRET_KEY


def create_app(config_override: dict = None):
    """
    Create and configure the Flask application.

    Args:
        config_override: Optional dict to override default configuration

    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)

    # Load configuration
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['JSON_SORT_KEYS'] = False  # Preserve key order in JSON responses

    # Apply any configuration overrides
    if config_override:
        app.config.update(config_override)

    # Configure CORS with security considerations
    # Allow Authorization header for JWT tokens
    CORS(app, resources={
        r"/api/*": {
            "origins": CORS_ORIGINS,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "expose_headers": [
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
                "Retry-After"
            ],
            "supports_credentials": True
        }
    })

    # Initialize security headers
    # Only enforce HTTPS in production
    env = os.getenv('FLASK_ENV', 'development')
    enforce_https = env == 'production'

    from app.security.headers import SecurityHeaders
    security_headers = SecurityHeaders(
        enforce_https=enforce_https,
        # Relaxed CSP for development (allows connections to localhost)
        csp_policy=(
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' http://localhost:* https://localhost:*; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'"
        )
    )
    security_headers.init_app(app)

    # Register route blueprints
    from app.routes import register_blueprints
    register_blueprints(app)

    # Log security status on startup
    @app.before_request
    def log_request_info():
        # This runs once on first request - useful for debugging
        pass

    return app
