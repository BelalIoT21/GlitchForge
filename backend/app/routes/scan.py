"""
Scan endpoints with real-time progress streaming
"""

import uuid
import queue
import threading
from flask import Blueprint, request, jsonify, Response

from app.services.engine import get_engine, _get_vuln_metadata
from app.services.progress import get_progress_manager, ScanPhase
from app.core.scanner.base_scanner import VulnerabilityType

scan_bp = Blueprint('scan', __name__, url_prefix='/api')


@scan_bp.route('/scan', methods=['POST'])
def scan():
    """
    Main scanning endpoint

    POST /api/scan
    Body: {
        "url": "http://example.com",
        "scan_types": ["sql", "xss", "csrf"],
        "cookies": {"PHPSESSID": "abc123", "security": "low"},  // Optional for authenticated scanning
        "crawl": true,  // Optional: crawl site to discover and scan all URLs
        "max_urls": 20  // Optional: max URLs to scan when crawling
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
        cookies = data.get('cookies', None)  # Optional session cookies for DVWA etc.
        crawl = data.get('crawl', False)  # Enable site crawling
        max_urls = data.get('max_urls', 20)  # Max URLs to scan when crawling

        engine = get_engine()

        if crawl:
            print(f"Site scan (crawl): {url} (max {max_urls} URLs)")
            if cookies:
                print(f"Using authenticated session with {len(cookies)} cookies")
            results = engine.scan_site_and_analyze(url, scan_types, cookies, max_urls)
        else:
            print(f"Scanning {url}...")
            if cookies:
                print(f"Using authenticated session with {len(cookies)} cookies")
            results = engine.scan_and_analyze(url, scan_types, cookies)

        return jsonify(results), 200

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@scan_bp.route('/scan-stream', methods=['POST'])
def scan_stream():
    """
    Streaming scan endpoint with real-time progress via SSE

    POST /api/scan-stream
    Body: same as /api/scan

    Returns: Server-Sent Events stream with progress updates
    """
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({
            'success': False,
            'error': 'URL is required'
        }), 400

    url = data['url']
    scan_types = data.get('scan_types', ['sql', 'xss', 'csrf'])
    cookies = data.get('cookies', None)
    crawl = data.get('crawl', False)
    max_urls = data.get('max_urls', 20)

    # Create unique scan ID
    scan_id = str(uuid.uuid4())[:8]

    # Create progress tracker
    progress_manager = get_progress_manager()
    progress = progress_manager.create_scan(scan_id, url)

    # Queue for SSE events
    event_queue = queue.Queue()

    def progress_callback(prog):
        """Add progress update to queue"""
        event_queue.put(('progress', prog.to_dict()))

    progress_manager.add_callback(scan_id, progress_callback)

    def run_scan():
        """Run scan in background thread"""
        try:
            engine = get_engine()

            if crawl:
                results = engine.scan_site_and_analyze_with_progress(
                    url, scan_types, cookies, max_urls, scan_id
                )
            else:
                results = engine.scan_and_analyze_with_progress(
                    url, scan_types, cookies, scan_id
                )

            event_queue.put(('result', results))
        except Exception as e:
            import traceback
            traceback.print_exc()
            progress_manager.set_phase(scan_id, ScanPhase.ERROR, error_message=str(e))
            event_queue.put(('error', {'success': False, 'error': str(e)}))
        finally:
            progress_manager.remove_callback(scan_id, progress_callback)

    # Start scan in background
    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

    def generate():
        """Generate SSE events"""
        import json

        # Send initial progress
        yield f"data: {json.dumps({'type': 'progress', 'data': progress.to_dict()})}\n\n"

        while True:
            try:
                event_type, event_data = event_queue.get(timeout=60)

                if event_type == 'progress':
                    yield f"data: {json.dumps({'type': 'progress', 'data': event_data})}\n\n"
                elif event_type == 'result':
                    yield f"data: {json.dumps({'type': 'result', 'data': event_data})}\n\n"
                    break
                elif event_type == 'error':
                    yield f"data: {json.dumps({'type': 'error', 'data': event_data})}\n\n"
                    break
            except queue.Empty:
                # Send keepalive
                yield f": keepalive\n\n"

        # Cleanup
        progress_manager.cleanup(scan_id)

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'  # Disable nginx buffering
        }
    )


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
        cookies = data.get('cookies', None)  # Optional session cookies

        engine = get_engine()
        vulnerabilities = engine.quick_scan(url, scan_types, cookies)

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
