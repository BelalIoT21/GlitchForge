"""
GlitchForge Web Dashboard - Final Version
Flask application with ML-enhanced vulnerability scanning
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import sys
from pathlib import Path
import json
import pandas as pd
import numpy as np
import requests
import pickle
from datetime import datetime
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners import VulnerabilityScanner
from config import DVWA_CONFIG, MODELS_DIR, PROCESSED_DATA_DIR

app = Flask(__name__)
CORS(app)

# Global variables
scanner = None
model = None
model_features = None

def load_model():
    """Load trained ML model"""
    global model, model_features
    
    model_path = MODELS_DIR / 'xgboost_vulnerability_model.pkl'
    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)
        model = model_data['model']
        model_features = model_data['feature_names']
    
    print(f"✓ Model loaded: {len(model_features)} features")

# Load model on startup
load_model()

# ============================================================================
# PAGE ROUTES
# ============================================================================

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/scan')
def scan_page():
    """Scanning interface page"""
    return render_template('scan.html')

@app.route('/results')
def results_page():
    """Scan results page"""
    return render_template('results.html')

# ============================================================================
# ML HELPER FUNCTIONS
# ============================================================================

def create_feature_dict_from_vulnerability(vulnerability):
    """Convert vulnerability to feature dictionary for ML model"""
    
    features = {}
    
    # Initialize all features to 0
    for feature_name in model_features:
        features[feature_name] = 0.0
    
    # Map vulnerability type to features
    if 'SQL' in vulnerability['type']:
        features['cvss_base_score'] = 9.0
        features['attack_vector_NETWORK'] = 1
        features['privileges_required_NONE'] = 1
        features['user_interaction_NONE'] = 1
        features['confidentiality_impact_HIGH'] = 1
        features['integrity_impact_HIGH'] = 1
        features['exploit_available'] = 1
        features['days_since_disclosure'] = 1  # Newly discovered
        
    elif 'XSS' in vulnerability['type']:
        features['cvss_base_score'] = 7.5
        features['attack_vector_NETWORK'] = 1
        features['privileges_required_NONE'] = 1
        features['confidentiality_impact_HIGH'] = 1
        features['exploit_available'] = 1
        features['days_since_disclosure'] = 1
        
    elif 'HTTPS' in vulnerability['type'] or 'SSL' in vulnerability['type']:
        features['cvss_base_score'] = 7.5
        features['attack_vector_NETWORK'] = 1
        features['confidentiality_impact_HIGH'] = 1
        features['integrity_impact_HIGH'] = 1
        
    elif 'Header' in vulnerability['type']:
        if vulnerability['severity'] == 'critical':
            features['cvss_base_score'] = 7.0
        elif vulnerability['severity'] == 'high':
            features['cvss_base_score'] = 6.0
        else:
            features['cvss_base_score'] = 4.0
        features['attack_vector_NETWORK'] = 1
    
    return features


def calculate_ml_risk_score(vulnerability):
    """
    Use ML model to calculate risk score
    Returns risk score and plain English explanation
    """
    
    # Get features
    features = create_feature_dict_from_vulnerability(vulnerability)
    
    # Convert to numpy array matching model's feature order
    feature_vector = []
    for feature_name in model_features:
        feature_vector.append(features.get(feature_name, 0.0))
    
    X = np.array(feature_vector).reshape(1, -1).astype('float64')
    
    # Predict risk score
    risk_score = float(model.predict(X)[0])
    
    # Get base risk (average)
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        base_value = float(explainer.expected_value)
        shap_values = explainer.shap_values(X)[0]
        
        # Get top contributing factors
        reasons = []
        feature_impacts = []
        
        for i, (feat_name, shap_val) in enumerate(zip(model_features, shap_values)):
            if abs(shap_val) > 0.1:
                feature_impacts.append({
                    'feature': feat_name,
                    'impact': float(shap_val),
                    'value': features.get(feat_name, 0.0)
                })
        
        feature_impacts.sort(key=lambda x: abs(x['impact']), reverse=True)
        
        # Convert to plain English (top 3 only)
        for factor in feature_impacts[:3]:
            if 'cvss' in factor['feature']:
                reasons.append(f"High severity score ({factor['value']:.1f}/10)")
            elif 'exploit' in factor['feature'] and factor['value'] > 0:
                reasons.append("Public exploits available")
            elif 'network' in factor['feature'].lower() and factor['value'] > 0:
                reasons.append("Can be exploited remotely")
            elif 'privileges_required_NONE' in factor['feature'] and factor['value'] > 0:
                reasons.append("No login required")
            elif 'confidentiality' in factor['feature'].lower() and factor['value'] > 0:
                reasons.append("Can steal sensitive data")
            elif 'integrity' in factor['feature'].lower() and factor['value'] > 0:
                reasons.append("Can modify data")
        
        explanation = {
            'risk_score': risk_score,
            'base_risk': base_value,
            'deviation': risk_score - base_value,
            'why_this_score': reasons if reasons else ['Based on vulnerability characteristics'],
            'method': 'SHAP (AI Explanation)'
        }
        
    except Exception as e:
        # Fallback if SHAP fails
        explanation = {
            'risk_score': risk_score,
            'base_risk': 5.0,
            'deviation': risk_score - 5.0,
            'why_this_score': ['Based on vulnerability type and severity'],
            'method': 'ML Model'
        }
    
    return explanation

# ============================================================================
# SCANNING API
# ============================================================================

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start vulnerability scan with ML risk scoring"""
    global scanner
    
    data = request.json
    target_url = data.get('target_url', DVWA_CONFIG['base_url'])
    scan_types = data.get('scan_types', ['sql', 'xss', 'csrf'])
    
    try:
        is_dvwa = 'dvwa' in target_url.lower()
        
        if is_dvwa:
            # DVWA-specific scanning
            scanner = VulnerabilityScanner(target_url)
            
            if not scanner.login_dvwa():
                return jsonify({
                    'success': False,
                    'error': 'Failed to connect to DVWA. Make sure DVWA is running.'
                }), 400
            
            scanner.set_security_level('low')
            
            results = []
            
            if 'sql' in scan_types:
                sql_result = scanner.scan_sql_injection('vulnerabilities/sqli/', 'id')
                results.append(sql_result)
            
            if 'xss' in scan_types:
                xss_result = scanner.scan_xss('vulnerabilities/xss_r/', 'name')
                results.append(xss_result)
            
            if 'csrf' in scan_types:
                csrf_result = scanner.scan_csrf('vulnerabilities/csrf/')
                results.append(csrf_result)
            
            summary = scanner.get_summary()
            
            return jsonify({
                'success': True,
                'results': results,
                'summary': summary,
                'scan_type': 'dvwa'
            })
        
        else:
            # Generic website scanning with ML enhancement
            print(f"[*] Performing ML-enhanced scan on {target_url}...")
            
            findings = []
            
            # Run security checks
            headers_result = check_security_headers(target_url)
            if headers_result:
                findings.append(headers_result)
            
            sql_result = quick_sql_test(target_url)
            if sql_result:
                findings.append(sql_result)
            
            xss_result = quick_xss_test(target_url)
            if xss_result:
                findings.append(xss_result)
            
            ssl_result = check_ssl(target_url)
            if ssl_result:
                findings.append(ssl_result)
            
            # ✨ Add ML risk scoring to each finding
            for finding in findings:
                try:
                    ml_explanation = calculate_ml_risk_score(finding)
                    finding['ml_risk_score'] = ml_explanation['risk_score']
                    finding['ml_explanation'] = ml_explanation
                except Exception as e:
                    print(f"[!] ML scoring failed for {finding['type']}: {e}")
                    finding['ml_risk_score'] = 5.0
                    finding['ml_explanation'] = {
                        'risk_score': 5.0,
                        'why_this_score': ['Based on vulnerability severity'],
                        'method': 'Fallback'
                    }
            
            # Sort by ML risk score (highest first)
            findings.sort(key=lambda x: x.get('ml_risk_score', 0), reverse=True)
            
            # Create summary
            summary = {
                'total_scans': len(findings),
                'vulnerabilities_found': sum(1 for f in findings if f['severity'] in ['high', 'critical']),
                'high_confidence': sum(1 for f in findings if f['severity'] == 'critical'),
                'medium_confidence': sum(1 for f in findings if f['severity'] == 'high'),
                'low_confidence': sum(1 for f in findings if f['severity'] == 'medium'),
                'by_type': {
                    'security_headers': sum(1 for f in findings if 'Header' in f['type']),
                    'sql_injection': sum(1 for f in findings if 'SQL' in f['type']),
                    'xss': sum(1 for f in findings if 'XSS' in f['type']),
                    'ssl': sum(1 for f in findings if 'HTTPS' in f['type'] or 'SSL' in f['type'])
                }
            }
            
            return jsonify({
                'success': True,
                'results': findings,
                'summary': summary,
                'scan_type': 'generic',
                'ml_powered': True
            })
        
    except requests.exceptions.Timeout:
        return jsonify({
            'success': False,
            'error': 'Connection timeout. Please check the URL.'
        }), 500
    
    except requests.exceptions.ConnectionError:
        return jsonify({
            'success': False,
            'error': 'Cannot connect to the target URL. Please verify the URL is correct.'
        }), 500
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': f'Scan error: {str(e)}'
        }), 500

# ============================================================================
# VULNERABILITY DETECTION FUNCTIONS
# ============================================================================

def check_security_headers(url):
    """Check for missing CRITICAL security headers"""
    try:
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        headers = response.headers
        
        missing_critical = []
        missing_important = []
        
        # CRITICAL headers
        if 'Strict-Transport-Security' not in headers and url.startswith('https://'):
            missing_critical.append('Strict-Transport-Security (HSTS)')
        
        # IMPORTANT headers
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            missing_important.append('X-Frame-Options (Clickjacking protection)')
        
        if 'X-Content-Type-Options' not in headers:
            missing_important.append('X-Content-Type-Options (MIME sniffing)')
        
        # Only report if critical OR multiple important missing
        if missing_critical:
            return {
                'type': 'Missing Critical Security Headers',
                'severity': 'high',
                'details': f"Missing: {', '.join(missing_critical)}. This leaves your site vulnerable to downgrade attacks.",
                'recommendation': 'Add Strict-Transport-Security header to enforce HTTPS',
                'impact': 'Users can be redirected to insecure HTTP versions, allowing man-in-the-middle attacks'
            }
        elif len(missing_important) >= 3:
            return {
                'type': 'Missing Security Headers',
                'severity': 'medium',
                'details': f"Missing {len(missing_important)} security headers: {', '.join(missing_important)}",
                'recommendation': 'Add these headers to improve security',
                'impact': 'More vulnerable to clickjacking and MIME-type attacks'
            }
        
        return None
        
    except requests.exceptions.Timeout:
        return {
            'type': 'Connection Timeout',
            'severity': 'high',
            'details': 'Server did not respond within 10 seconds',
            'recommendation': 'Check if server is online'
        }
    
    except requests.exceptions.ConnectionError:
        return {
            'type': 'Connection Failed',
            'severity': 'critical',
            'details': 'Cannot connect to server',
            'recommendation': 'Verify URL is correct'
        }
    
    except Exception as e:
        return None


def quick_sql_test(url):
    """Quick SQL injection test"""
    try:
        test_payload = "'"
        
        test_urls = [
            f"{url}?id={test_payload}",
            f"{url}?page={test_payload}",
            f"{url}?search={test_payload}"
        ]
        
        for test_url in test_urls:
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                sql_errors = [
                    'sql syntax',
                    'mysql',
                    'sqlite',
                    'postgresql',
                    'ora-',
                    'syntax error',
                    'unclosed quotation'
                ]
                
                for error in sql_errors:
                    if error in response.text.lower():
                        return {
                            'type': 'Possible SQL Injection',
                            'severity': 'critical',
                            'details': 'SQL error message detected - database queries may be vulnerable to injection attacks',
                            'recommendation': 'URGENT: Use parameterized queries (prepared statements) immediately',
                            'impact': 'Attackers can steal ALL database data, delete records, or take complete control',
                            'tested_parameter': test_url.split('?')[1].split('=')[0] if '?' in test_url else 'unknown'
                        }
            except:
                continue
        
        return None
        
    except Exception as e:
        return None


def quick_xss_test(url):
    """Quick XSS test"""
    try:
        test_payload = "<script>alert('XSS')</script>"
        
        test_urls = [
            f"{url}?search={test_payload}",
            f"{url}?q={test_payload}",
            f"{url}?name={test_payload}"
        ]
        
        for test_url in test_urls:
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                if test_payload in response.text or '<script>' in response.text:
                    return {
                        'type': 'Possible XSS Vulnerability',
                        'severity': 'high',
                        'details': 'Unescaped user input detected - malicious JavaScript could be injected',
                        'recommendation': 'Implement output encoding (HTML entity encoding) and Content Security Policy',
                        'impact': 'Attackers can steal user sessions, redirect to phishing sites, or steal sensitive data',
                        'tested_parameter': test_url.split('?')[1].split('=')[0] if '?' in test_url else 'unknown'
                    }
            except:
                continue
        
        return None
        
    except Exception as e:
        return None


def check_ssl(url):
    """Check SSL/TLS configuration"""
    try:
        if not url.startswith('https://'):
            return {
                'type': 'No HTTPS Encryption',
                'severity': 'critical',
                'details': 'Website not using HTTPS - ALL data transmitted in plain text',
                'recommendation': 'Install SSL/TLS certificate immediately and redirect HTTP to HTTPS',
                'impact': 'Passwords, credit cards, and all sensitive data can be intercepted by anyone on the network'
            }
        
        try:
            response = requests.get(url, timeout=10, verify=True)
            return None
        except requests.exceptions.SSLError:
            return {
                'type': 'Invalid SSL Certificate',
                'severity': 'high',
                'details': 'SSL certificate is invalid, expired, or self-signed',
                'recommendation': 'Install valid SSL certificate from trusted Certificate Authority',
                'impact': 'Users see security warnings and may not trust your site'
            }
        
    except Exception as e:
        return None


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🔥 GlitchForge Web Dashboard Starting...")
    print("="*60)
    print("\n  Access at: http://localhost:5000")
    print("\n  Pages:")
    print("    - / (Home)")
    print("    - /scan (Vulnerability Scanner)")
    print("    - /results (Scan Results with AI Explanations)")
    print("\n  ✨ ML-Enhanced Security Scanning")
    print("  ✨ SHAP Explainability Built-In")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)