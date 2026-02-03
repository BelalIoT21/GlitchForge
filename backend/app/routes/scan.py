"""
Scan endpoints
"""

from flask import Blueprint, request, jsonify

from app.services.engine import get_engine, _get_vuln_metadata
from app.core.scanner.base_scanner import VulnerabilityType

scan_bp = Blueprint('scan', __name__, url_prefix='/api')


@scan_bp.route('/scan', methods=['POST'])
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

        engine = get_engine()
        results = engine.scan_and_analyze(url, scan_types)

        return jsonify(results), 200

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scan_bp.route('/quick-scan', methods=['POST'])
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

        engine = get_engine()
        vulnerabilities = engine.quick_scan(url, scan_types)

        # Format vulnerabilities with metadata
        formatted_vulns = []
        for v in vulnerabilities:
            metadata = _get_vuln_metadata(v.vuln_type, v)
            formatted_vulns.append({
                'where': {
                    'url': v.url,
                    'parameter': v.parameter
                },
                'what': {
                    'vulnerability_type': v.vuln_type.value,
                    'severity': v.severity.value,
                    'payload_used': v.payload,
                    'description': metadata['description'],
                    'evidence': v.evidence,
                    'cwe_id': metadata['cwe_id'],
                    'confidence': v.confidence
                },
                'how_to_fix': {
                    'remediation': metadata['remediation']
                }
            })

        return jsonify({
            'success': True,
            'url': url,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': formatted_vulns
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
