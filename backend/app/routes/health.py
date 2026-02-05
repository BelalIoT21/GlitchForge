"""
Health and status endpoints

Security features:
- Rate limiting to prevent abuse
"""

from flask import Blueprint, jsonify

from app.services.engine import get_engine
from app.security.rate_limiter import rate_limit

health_bp = Blueprint('health', __name__)


@health_bp.route('/health', methods=['GET'])
@rate_limit(limit_type='ip')  # 60 requests per minute
def health():
    """
    Health check endpoint

    GET /health

    Returns basic health status of the API

    Rate limit: 60 requests per minute per IP
    """
    engine = get_engine()
    return jsonify({
        'status': 'healthy',
        'message': 'GlitchForge API is running',
        'models_loaded': engine.rf_model is not None and engine.nn_model is not None
    }), 200


@health_bp.route('/api/status', methods=['GET'])
@rate_limit(limit_type='ip')  # 60 requests per minute
def status():
    """
    Get engine status

    GET /api/status

    Returns detailed status of the scanning engine

    Rate limit: 60 requests per minute per IP
    """
    engine = get_engine()
    return jsonify({
        'success': True,
        'engine': 'ready',
        'models_loaded': {
            'random_forest': engine.rf_model is not None,
            'neural_network': engine.nn_model is not None
        },
        'available_scans': ['sql', 'xss', 'csrf'],
        'security': {
            'rate_limiting': 'enabled',
            'input_validation': 'enabled',
            'authentication': 'optional'
        }
    }), 200
