"""
GlitchForge Flask Backend Server
Simple wrapper around your existing code

Just run: python app_server.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
from pathlib import Path

# Add current directory to path so we can import from src/
sys.path.insert(0, str(Path(__file__).parent))

# Import your existing engine
from glitchforge_engine import GlitchForgeEngine

app = Flask(__name__)

# Enable CORS for React frontend
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000", "http://localhost:3001"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Initialize engine once at startup
print("Initializing GlitchForge Engine...")
engine = GlitchForgeEngine()
print("✓ Engine ready!")


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'GlitchForge API is running',
        'models_loaded': engine.rf_model is not None and engine.nn_model is not None
    }), 200


@app.route('/api/scan', methods=['POST'])
def scan():
    """
    Main scanning endpoint
    
    POST /api/scan
    Body: {
        "url": "http://example.com",
        "scan_types": ["sql", "xss", "csrf"]
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        url = data['url']
        scan_types = data.get('scan_types', ['sql', 'xss', 'csrf'])
        
        print(f"Scanning {url}...")
        
        # Use your existing engine
        results = engine.scan_and_analyze(url, scan_types)
        
        return jsonify(results), 200
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/quick-scan', methods=['POST'])
def quick_scan():
    """Quick scan without ML analysis"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        url = data['url']
        scan_types = data.get('scan_types', ['sql', 'xss', 'csrf'])
        
        vulnerabilities = engine.quick_scan(url, scan_types)
        
        return jsonify({
            'success': True,
            'url': url,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': [
                {
                    'type': v.vuln_type.value,
                    'severity': v.severity.value,
                    'url': v.url,
                    'parameter': v.parameter,
                    'payload': v.payload,
                    'confidence': v.confidence
                }
                for v in vulnerabilities
            ]
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/status', methods=['GET'])
def status():
    """Get engine status"""
    return jsonify({
        'success': True,
        'engine': 'ready',
        'models_loaded': {
            'random_forest': engine.rf_model is not None,
            'neural_network': engine.nn_model is not None
        },
        'available_scans': ['sql', 'xss', 'csrf']
    }), 200


if __name__ == '__main__':
    print("=" * 70)
    print(" " * 20 + "GLITCHFORGE BACKEND")
    print(" " * 15 + "AI-Enhanced Vulnerability Scanner")
    print("=" * 70)
    print(f"\n🚀 Starting server on http://0.0.0.0:5000")
    print("\n📡 Available Endpoints:")
    print("   GET  /health           - Health check")
    print("   GET  /api/status       - Engine status")
    print("   POST /api/scan         - Complete scan & analysis")
    print("   POST /api/quick-scan   - Quick vulnerability scan")
    print("\n" + "=" * 70)
    print("Press CTRL+C to stop\n")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )