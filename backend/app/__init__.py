"""
GlitchForge Application Factory
"""

from flask import Flask
from flask_cors import CORS

from app.config import CORS_ORIGINS


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    CORS(app, resources={
        r"/api/*": {
            "origins": CORS_ORIGINS,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type"]
        }
    })

    # Register route blueprints
    from app.routes import register_blueprints
    register_blueprints(app)

    return app
