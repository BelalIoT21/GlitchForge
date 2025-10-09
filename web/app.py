"""
GlitchForge Web Dashboard
Flask application for interactive vulnerability scanning and ML predictions
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import sys
from pathlib import Path
import json
import pandas as pd
import requests
import pickle
import base64
from io import BytesIO
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap
from lime.lime_tabular import LimeTabularExplainer

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners import VulnerabilityScanner
from ml.explainer import VulnerabilityExplainer
from config import DVWA_CONFIG, MODELS_DIR, PROCESSED_DATA_DIR

app = Flask(__name__)
CORS(app)

# Global variables
scanner = None
explainer = None
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

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/scan')
def scan_page():
    """Scanning interface page"""
    return render_template('scan.html')

@app.route('/explain')
def explain_page():
    """Explanation page"""
    return render_template('explain.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start vulnerability scan"""
    global scanner
    
    data = request.json
    target_url = data.get('target_url', DVWA_CONFIG['base_url'])
    scan_types = data.get('scan_types', ['sql', 'xss', 'csrf'])
    
    try:
        # Initialize scanner
        scanner = VulnerabilityScanner(target_url)
        
        # Login
        if not scanner.login_dvwa():
            return jsonify({
                'success': False,
                'error': 'Failed to authenticate with target'
            }), 400
        
        scanner.set_security_level('low')
        
        # Run scans
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
        
        # Get summary
        summary = scanner.get_summary()
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': summary
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/vulnerabilities/list', methods=['GET'])
def list_vulnerabilities():
    """List vulnerabilities from dataset"""
    
    try:
        df = pd.read_csv(PROCESSED_DATA_DIR / 'processed_nvd_data.csv')
        
        # Get sample
        sample_size = int(request.args.get('limit', 20))
        sample = df.sample(n=min(sample_size, len(df)))
        
        vulns = []
        for _, row in sample.iterrows():
            vulns.append({
                'cve_id': row.get('cve_id', 'Unknown'),
                'cvss_score': float(row.get('cvss_base_score', 0)),
                'risk_score': float(row.get('risk_score', 0)),
                'days_old': int(row.get('days_since_disclosure', 0)),
                'exploit_available': bool(row.get('exploit_available', 0))
            })
        
        return jsonify({
            'success': True,
            'total': len(df),
            'vulnerabilities': vulns
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/predict', methods=['POST'])
def predict_risk():
    """Predict risk score for vulnerability"""
    
    data = request.json
    cve_id = data.get('cve_id')
    
    try:
        df = pd.read_csv(PROCESSED_DATA_DIR / 'processed_nvd_data.csv')
        
        # Find vulnerability
        vuln = df[df['cve_id'] == cve_id].iloc[0]
        
        # Get features
        exclude_cols = ['cve_id', 'risk_score', 'cwe_ids', 'description', 
                       'published_date', 'modified_date']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        X = vuln[feature_cols].values.reshape(1, -1)
        
        # Predict
        prediction = float(model.predict(X)[0])
        
        return jsonify({
            'success': True,
            'cve_id': cve_id,
            'cvss_score': float(vuln['cvss_base_score']),
            'predicted_risk': prediction,
            'risk_level': 'CRITICAL' if prediction >= 9 else 'HIGH' if prediction >= 7 else 'MEDIUM'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/explain', methods=['POST'])
def explain_prediction():
    """Generate SHAP explanation for ANY vulnerability on-demand"""
    
    data = request.json
    cve_id = data.get('cve_id')
    
    try:
        # Load the full dataset
        df = pd.read_csv(PROCESSED_DATA_DIR / 'processed_nvd_data.csv')
        
        if cve_id not in df['cve_id'].values:
            return jsonify({
                'success': False,
                'error': 'CVE not found in database'
            }), 404
        
        # Get the specific vulnerability
        vuln_row = df[df['cve_id'] == cve_id].iloc[0]
        
        # Extract features
        exclude_cols = ['cve_id', 'risk_score', 'cwe_ids', 'description', 
                       'published_date', 'modified_date']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        # Get feature values for this vulnerability
        X_vuln = vuln_row[feature_cols].values.reshape(1, -1)
        
        # Convert to float64 for SHAP
        X_vuln = X_vuln.astype('float64')
        
        # Make prediction
        prediction = float(model.predict(X_vuln)[0])
        
        # Create SHAP explainer on-the-fly with small background sample
        print(f"[*] Creating SHAP explainer for {cve_id}...")
        background = shap.sample(df[feature_cols].astype('float64'), 50)
        explainer = shap.TreeExplainer(model)
        
        # Calculate SHAP values for this specific vulnerability
        shap_values = explainer.shap_values(X_vuln)
        base_value = float(explainer.expected_value)
        
        # Get feature contributions
        feature_contributions = []
        for feat, val, shap_val in zip(feature_cols, X_vuln[0], shap_values[0]):
            feature_contributions.append({
                'feature': feat,
                'value': float(val),
                'shap_value': float(shap_val),
                'impact': 'positive' if shap_val > 0 else 'negative'
            })
        
        # Sort by absolute SHAP value
        feature_contributions.sort(key=lambda x: abs(x['shap_value']), reverse=True)
        
        # Generate human-readable explanation
        explanation = generate_human_explanation(
            cve_id=cve_id,
            vuln_row=vuln_row,
            prediction=prediction,
            base_value=base_value,
            top_features=feature_contributions[:10]
        )
        
        return jsonify({
            'success': True,
            'cve_id': cve_id,
            'prediction': prediction,
            'base_value': base_value,
            'cvss_score': float(vuln_row['cvss_base_score']),
            'top_features': feature_contributions[:15],
            'explanation': explanation  # NEW: Human-readable explanation
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/api/explain/lime', methods=['POST'])
def explain_with_lime():
    """Generate LIME explanation for comparison with SHAP"""
    
    data = request.json
    cve_id = data.get('cve_id')
    
    try:
        # Load dataset
        df = pd.read_csv(PROCESSED_DATA_DIR / 'processed_nvd_data.csv')
        
        if cve_id not in df['cve_id'].values:
            return jsonify({
                'success': False,
                'error': 'CVE not found'
            }), 404
        
        # Get vulnerability
        vuln_row = df[df['cve_id'] == cve_id].iloc[0]
        
        # Extract features
        exclude_cols = ['cve_id', 'risk_score', 'cwe_ids', 'description', 
                       'published_date', 'modified_date']
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        X_train = df[feature_cols].astype('float64').values
        X_vuln = vuln_row[feature_cols].values.reshape(1, -1).astype('float64')
        
        # Make prediction
        prediction = float(model.predict(X_vuln)[0])
        
        # Create LIME explainer
        print(f"[*] Creating LIME explainer for {cve_id}...")
        lime_explainer = LimeTabularExplainer(
            X_train,
            feature_names=feature_cols,
            mode='regression',
            random_state=42
        )
        
        # Generate explanation
        lime_exp = lime_explainer.explain_instance(
            X_vuln[0],
            model.predict,
            num_features=15
        )
        
        # Extract feature contributions
        lime_features = []
        for feat, weight in lime_exp.as_list():
            # Parse feature name and value from LIME format
            feat_name = feat.split('<=')[0].split('>')[0].strip()
            
            lime_features.append({
                'feature': feat_name,
                'weight': float(weight),
                'impact': 'positive' if weight > 0 else 'negative'
            })
        
        # Sort by absolute weight
        lime_features.sort(key=lambda x: abs(x['weight']), reverse=True)
        
        # Get R² score (fidelity)
        fidelity = float(lime_exp.score)
        
        return jsonify({
            'success': True,
            'cve_id': cve_id,
            'prediction': prediction,
            'lime_features': lime_features,
            'fidelity': fidelity,
            'method': 'LIME (Local Interpretable Model-agnostic Explanations)'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/explain/compare', methods=['POST'])
def compare_explanations():
    """Compare SHAP and LIME explanations side-by-side"""
    
    data = request.json
    cve_id = data.get('cve_id')
    
    try:
        # Get both SHAP and LIME explanations
        shap_result = explain_prediction()
        lime_result = explain_with_lime()
        
        return jsonify({
            'success': True,
            'cve_id': cve_id,
            'shap': json.loads(shap_result.get_data()),
            'lime': json.loads(lime_result.get_data())
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/shap/summary')
def get_shap_summary():
    """Get SHAP summary image"""
    try:
        return send_file('../shap_summary.png', mimetype='image/png')
    except:
        return jsonify({'error': 'Image not found'}), 404

@app.route('/api/shap/bar')
def get_shap_bar():
    """Get SHAP bar chart image"""
    try:
        return send_file('../shap_bar.png', mimetype='image/png')
    except:
        return jsonify({'error': 'Image not found'}), 404

@app.route('/api/stats')
def get_stats():
    """Get system statistics"""
    
    try:
        df = pd.read_csv(PROCESSED_DATA_DIR / 'processed_nvd_data.csv')
        
        stats = {
            'total_vulnerabilities': len(df),
            'high_risk': int((df['risk_score'] >= 7.0).sum()),
            'medium_risk': int(((df['risk_score'] >= 4.0) & (df['risk_score'] < 7.0)).sum()),
            'low_risk': int((df['risk_score'] < 4.0).sum()),
            'with_exploits': int(df['exploit_available'].sum()),
            'avg_risk_score': float(df['risk_score'].mean()),
            'model_features': len(model_features)
        }
        
        return jsonify({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/visualizations/risk-distribution')
def risk_distribution():
    """Get risk score distribution data"""
    
    try:
        df = pd.read_csv(PROCESSED_DATA_DIR / 'processed_nvd_data.csv')
        
        # Calculate distribution
        risk_bins = [0, 4, 7, 9, 10]
        risk_labels = ['Low', 'Medium', 'High', 'Critical']
        df['risk_category'] = pd.cut(df['risk_score'], bins=risk_bins, labels=risk_labels)
        
        distribution = df['risk_category'].value_counts().to_dict()
        
        # CVSS vs Risk Score correlation
        correlation_data = df[['cvss_base_score', 'risk_score']].to_dict('records')
        
        # Exploit availability impact
        with_exploits = df[df['exploit_available'] == 1]['risk_score'].mean()
        without_exploits = df[df['exploit_available'] == 0]['risk_score'].mean()
        
        return jsonify({
            'success': True,
            'distribution': distribution,
            'correlation': correlation_data[:100],  # Sample for performance
            'exploit_impact': {
                'with_exploits': float(with_exploits),
                'without_exploits': float(without_exploits),
                'difference': float(with_exploits - without_exploits)
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/api/export/report', methods=['POST'])
def export_report():
    """Export vulnerability report in various formats"""
    
    data = request.json
    cve_ids = data.get('cve_ids', [])
    format_type = data.get('format', 'json')  # json, csv, or html
    
    try:
        df = pd.read_csv(PROCESSED_DATA_DIR / 'processed_nvd_data.csv')
        
        if cve_ids:
            report_df = df[df['cve_id'].isin(cve_ids)]
        else:
            # Export all high-risk vulnerabilities
            report_df = df[df['risk_score'] >= 7.0].head(50)
        
        # Select relevant columns
        export_cols = ['cve_id', 'cvss_base_score', 'risk_score', 
                      'exploit_available', 'days_since_disclosure']
        report_data = report_df[export_cols]
        
        if format_type == 'json':
            return jsonify({
                'success': True,
                'data': report_data.to_dict('records'),
                'count': len(report_data)
            })
        
        elif format_type == 'csv':
            csv_data = report_data.to_csv(index=False)
            return jsonify({
                'success': True,
                'csv': csv_data,
                'filename': f'glitchforge_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            })
        
        elif format_type == 'html':
            html_report = generate_html_report(report_data)
            return jsonify({
                'success': True,
                'html': html_report
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def generate_html_report(df):
    """Generate HTML report"""
    
    html = f"""
    <html>
    <head>
        <title>GlitchForge Vulnerability Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #ff6b35; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th {{ background: #004e89; color: white; padding: 12px; text-align: left; }}
            td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
            .critical {{ background: #ef476f; color: white; }}
            .high {{ background: #ffd166; }}
            .medium {{ background: #06d6a0; color: white; }}
        </style>
    </head>
    <body>
        <h1>🔥 GlitchForge Vulnerability Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p>Total Vulnerabilities: {len(df)}</p>
        
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>CVSS Score</th>
                    <th>Risk Score</th>
                    <th>Exploit Available</th>
                    <th>Age (Days)</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for _, row in df.iterrows():
        risk_class = 'critical' if row['risk_score'] >= 9 else 'high' if row['risk_score'] >= 7 else 'medium'
        html += f"""
                <tr class="{risk_class}">
                    <td>{row['cve_id']}</td>
                    <td>{row['cvss_base_score']:.1f}</td>
                    <td>{row['risk_score']:.2f}</td>
                    <td>{'Yes' if row['exploit_available'] else 'No'}</td>
                    <td>{row['days_since_disclosure']}</td>
                </tr>
        """
    
    html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    
    return html

@app.route('/api/scan/generic', methods=['POST'])
def scan_generic_website():
    """Scan any website for common vulnerabilities"""
    
    data = request.json
    target_url = data.get('url')
    scan_depth = data.get('depth', 'quick')  # quick, standard, deep
    
    if not target_url:
        return jsonify({
            'success': False,
            'error': 'URL is required'
        }), 400
    
    try:
        print(f"[*] Scanning {target_url}...")
        
        results = {
            'url': target_url,
            'scan_time': datetime.now().isoformat(),
            'findings': []
        }
        
        # Basic security headers check
        headers_result = check_security_headers(target_url)
        if headers_result:
            results['findings'].append(headers_result)
        
        # SQL injection quick test
        sql_result = quick_sql_test(target_url)
        if sql_result:
            results['findings'].append(sql_result)
        
        # XSS quick test
        xss_result = quick_xss_test(target_url)
        if xss_result:
            results['findings'].append(xss_result)
        
        # SSL/TLS check
        ssl_result = check_ssl(target_url)
        if ssl_result:
            results['findings'].append(ssl_result)
        
        return jsonify({
            'success': True,
            'results': results,
            'total_findings': len(results['findings'])
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def check_security_headers(url):
    """Check for missing security headers"""
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        
        missing_headers = []
        
        if 'X-Frame-Options' not in headers:
            missing_headers.append('X-Frame-Options')
        if 'X-Content-Type-Options' not in headers:
            missing_headers.append('X-Content-Type-Options')
        if 'Strict-Transport-Security' not in headers:
            missing_headers.append('Strict-Transport-Security')
        if 'Content-Security-Policy' not in headers:
            missing_headers.append('Content-Security-Policy')
        
        if missing_headers:
            return {
                'type': 'Missing Security Headers',
                'severity': 'medium',
                'details': f"Missing headers: {', '.join(missing_headers)}",
                'recommendation': 'Implement security headers to prevent common attacks'
            }
        
        return None
        
    except:
        return None

def quick_sql_test(url):
    """Quick SQL injection test"""
    
    try:
        # Test with simple SQL payload
        test_payload = "'"
        test_url = f"{url}?test={test_payload}"
        
        response = requests.get(test_url, timeout=10)
        
        # Check for SQL error messages
        sql_errors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error']
        
        for error in sql_errors:
            if error in response.text.lower():
                return {
                    'type': 'Possible SQL Injection',
                    'severity': 'high',
                    'details': 'SQL error message detected in response',
                    'recommendation': 'Use parameterized queries and input validation'
                }
        
        return None
        
    except:
        return None

def quick_xss_test(url):
    """Quick XSS test"""
    
    try:
        test_payload = "<script>alert(1)</script>"
        test_url = f"{url}?test={test_payload}"
        
        response = requests.get(test_url, timeout=10)
        
        if test_payload in response.text:
            return {
                'type': 'Possible XSS Vulnerability',
                'severity': 'high',
                'details': 'Unescaped user input detected in response',
                'recommendation': 'Implement output encoding and Content Security Policy'
            }
        
        return None
        
    except:
        return None

def check_ssl(url):
    """Check SSL/TLS configuration"""
    
    try:
        if not url.startswith('https://'):
            return {
                'type': 'No HTTPS',
                'severity': 'high',
                'details': 'Website is not using HTTPS encryption',
                'recommendation': 'Implement SSL/TLS certificate and redirect HTTP to HTTPS'
            }
        
        # Could add more detailed SSL checks here
        return None
        
    except:
        return None
    
def generate_human_explanation(cve_id, vuln_row, prediction, base_value, top_features):
    """
    Generate plain English explanation of vulnerability risk
    """
    
    cvss = float(vuln_row['cvss_base_score'])
    exploit_available = bool(vuln_row.get('exploit_available', 0))
    days_old = int(vuln_row.get('days_since_disclosure', 0))
    public_facing = bool(vuln_row.get('public_facing', 0))
    
    # Determine risk level
    if prediction >= 9.0:
        risk_level = "CRITICAL"
        risk_emoji = "🔴"
    elif prediction >= 7.0:
        risk_level = "HIGH"
        risk_emoji = "🟠"
    elif prediction >= 4.0:
        risk_level = "MEDIUM"
        risk_emoji = "🟡"
    else:
        risk_level = "LOW"
        risk_emoji = "🟢"
    
    explanation = {
        'summary': f"{risk_emoji} This vulnerability has a **{risk_level}** risk score of **{prediction:.1f}/10**",
        'why_this_score': [],
        'vulnerability_type': '',
        'attack_scenario': '',
        'how_to_fix': []
    }
    
    # Analyze top features to understand WHY
    reasons = []
    
    for feature in top_features[:5]:  # Top 5 contributors
        feat_name = feature['feature']
        shap_val = feature['shap_value']
        value = feature['value']
        
        if abs(shap_val) < 0.1:  # Skip minor contributors
            continue
        
        # CVSS Score
        if 'cvss_base_score' in feat_name and shap_val > 0:
            reasons.append(f"✓ The CVSS base score is **{cvss:.1f}**, indicating {'severe' if cvss >= 7 else 'moderate'} technical severity (+{shap_val:.2f} risk)")
        
        # Exploit availability
        if 'exploit_available' in feat_name:
            if value > 0 and shap_val > 0:
                reasons.append(f"⚠️ **Public exploits are available** - attackers can easily exploit this vulnerability (+{shap_val:.2f} risk)")
            elif value == 0 and shap_val < 0:
                reasons.append(f"✓ No public exploits available yet, reducing immediate risk ({shap_val:.2f} risk)")
        
        # Days since disclosure
        if 'days_since_disclosure' in feat_name:
            if days_old < 30 and shap_val > 0:
                reasons.append(f"⚠️ Recently disclosed (**{days_old} days ago**) - patches may not be widely deployed (+{shap_val:.2f} risk)")
            elif days_old > 180 and shap_val < 0:
                reasons.append(f"✓ Disclosed **{days_old} days ago** - most systems likely patched ({shap_val:.2f} risk)")
        
        # Public facing
        if 'public_facing' in feat_name:
            if value > 0 and shap_val > 0:
                reasons.append(f"⚠️ **Affects public-facing systems** accessible from the internet (+{shap_val:.2f} risk)")
            elif value == 0 and shap_val < 0:
                reasons.append(f"✓ Only affects internal systems, limiting attacker access ({shap_val:.2f} risk)")
        
        # Attack vector
        if 'attack_vector_NETWORK' in feat_name and value > 0:
            reasons.append(f"⚠️ **Exploitable remotely** over the network (+{shap_val:.2f} risk)")
        
        # Privileges required
        if 'privileges_required_NONE' in feat_name and value > 0:
            reasons.append(f"⚠️ **No authentication required** - anyone can attempt exploitation (+{shap_val:.2f} risk)")
        
        # Impact scores
        if 'confidentiality_impact_HIGH' in feat_name and value > 0:
            reasons.append(f"⚠️ **High confidentiality impact** - sensitive data could be exposed (+{shap_val:.2f} risk)")
        
        if 'integrity_impact_HIGH' in feat_name and value > 0:
            reasons.append(f"⚠️ **High integrity impact** - attackers could modify data (+{shap_val:.2f} risk)")
        
        if 'availability_impact_HIGH' in feat_name and value > 0:
            reasons.append(f"⚠️ **High availability impact** - system could be taken offline (+{shap_val:.2f} risk)")
    
    explanation['why_this_score'] = reasons if reasons else ["Analysis based on multiple technical factors"]
    
    # Determine vulnerability type from CWE
    cwe_ids = str(vuln_row.get('cwe_ids', '')).upper()
    
    if 'CWE-89' in cwe_ids or 'SQL' in vuln_row.get('description', '').upper():
        explanation['vulnerability_type'] = "SQL Injection"
        explanation['attack_scenario'] = "An attacker could inject malicious SQL commands into database queries, potentially accessing, modifying, or deleting sensitive data. This could lead to complete database compromise."
        explanation['how_to_fix'] = [
            "Use parameterized queries (prepared statements) instead of string concatenation",
            "Implement input validation and sanitization",
            "Apply principle of least privilege to database accounts",
            "Use ORM frameworks that handle SQL safely",
            "Enable SQL injection detection in WAF (Web Application Firewall)"
        ]
    
    elif 'CWE-79' in cwe_ids or 'XSS' in vuln_row.get('description', '').upper():
        explanation['vulnerability_type'] = "Cross-Site Scripting (XSS)"
        explanation['attack_scenario'] = "An attacker could inject malicious JavaScript into web pages, potentially stealing user sessions, credentials, or performing actions on behalf of victims."
        explanation['how_to_fix'] = [
            "Encode all user input before displaying it (HTML entity encoding)",
            "Implement Content Security Policy (CSP) headers",
            "Use modern frameworks with automatic XSS protection (React, Vue, Angular)",
            "Validate and sanitize input on both client and server side",
            "Use HTTPOnly and Secure flags on cookies"
        ]
    
    elif 'CWE-352' in cwe_ids or 'CSRF' in vuln_row.get('description', '').upper():
        explanation['vulnerability_type'] = "Cross-Site Request Forgery (CSRF)"
        explanation['attack_scenario'] = "An attacker could trick authenticated users into performing unintended actions (like changing passwords or transferring funds) without their knowledge."
        explanation['how_to_fix'] = [
            "Implement anti-CSRF tokens in all state-changing forms",
            "Use SameSite cookie attribute",
            "Require re-authentication for sensitive operations",
            "Validate Origin and Referer headers",
            "Implement proper session management"
        ]
    
    else:
        explanation['vulnerability_type'] = "Security Vulnerability"
        explanation['attack_scenario'] = "This vulnerability could allow attackers to compromise system security through various attack vectors."
        explanation['how_to_fix'] = [
            "Apply the latest security patches immediately",
            "Follow vendor security recommendations",
            "Implement defense-in-depth security measures",
            "Monitor systems for signs of exploitation",
            "Review and update security configurations"
        ]
    
    # Comparison to average
    deviation = prediction - base_value
    if abs(deviation) > 1.0:
        if deviation > 0:
            explanation['summary'] += f"\n\nThis is **{abs(deviation):.1f} points higher** than the average vulnerability, making it a priority for immediate action."
        else:
            explanation['summary'] += f"\n\nThis is **{abs(deviation):.1f} points lower** than the average vulnerability."
    
    return explanation

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🔥 GlitchForge Web Dashboard Starting...")
    print("="*60)
    print("\n  Access at: http://localhost:5000")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)