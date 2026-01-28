"""
Health and status endpoints
"""

from flask import Blueprint, jsonify

from app.services.engine import get_engine

health_bp = Blueprint('health', __name__)


@health_bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    engine = get_engine()
    return jsonify({
        'status': 'healthy',
        'message': 'GlitchForge API is running',
        'models_loaded': engine.rf_model is not None and engine.nn_model is not None
    }), 200


@health_bp.route('/api/status', methods=['GET'])
def status():
    """Get engine status"""
    engine = get_engine()
    return jsonify({
        'success': True,
        'engine': 'ready',
        'models_loaded': {
            'random_forest': engine.rf_model is not None,
            'neural_network': engine.nn_model is not None
        },
        'available_scans': ['sql', 'xss', 'csrf']
    }), 200
