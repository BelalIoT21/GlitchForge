"""
Scan endpoints
"""

from flask import Blueprint, request, jsonify

from app.services.engine import get_engine
from app.core.scanner.base_scanner import VulnerabilityType

scan_bp = Blueprint('scan', __name__, url_prefix='/api')


def _get_vuln_metadata(vuln_type: VulnerabilityType):
    """Get description, CWE ID, and remediation for vulnerability type"""
    metadata = {
        VulnerabilityType.SQL_INJECTION: {
            'description': "Application is vulnerable to SQL Injection attacks. Attackers can manipulate database queries to access or modify data.",
            'cwe_id': "CWE-89",
            'remediation': "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Implement input validation and sanitization."
        },
        VulnerabilityType.XSS: {
            'description': "Application is vulnerable to Cross-Site Scripting (XSS). Attackers can inject malicious scripts into web pages viewed by users.",
            'cwe_id': "CWE-79",
            'remediation': "Encode all user input before displaying it. Use Content Security Policy (CSP) headers. Implement proper input validation and output encoding."
        },
        VulnerabilityType.CSRF: {
            'description': "Application lacks CSRF protection. Attackers can trick users into performing unwanted actions.",
            'cwe_id': "CWE-352",
            'remediation': "Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute. Verify Origin and Referer headers."
        }
    }
    return metadata.get(vuln_type, {
        'description': "Security vulnerability detected",
        'cwe_id': "CWE-000",
        'remediation': "Follow security best practices"
    })


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
            metadata = _get_vuln_metadata(v.vuln_type)
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
