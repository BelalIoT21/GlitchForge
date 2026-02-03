#!/usr/bin/env python3
"""
GlitchForge - AI-Enhanced Vulnerability Scanner Engine
Student: Belal Almshmesh (U2687294)
Supervisor: Dr. Halima Kure
University of East London

Optimized engine for web dashboard with ML-based risk assessment and XAI explanations.
- Models loaded ONCE at startup for fast performance
- Comprehensive vulnerability scanning (SQL, XSS, CSRF)
- ML predictions with Random Forest & Neural Network
- SHAP/LIME explainability for transparent risk assessment
- Intelligent prioritization engine

Usage:
    from app.services.engine import get_engine

    engine = get_engine()  # Singleton - models loaded once
    results = engine.scan_and_analyze(url)  # Fast scan with explanations
"""

import os
import sys
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import json
import pandas as pd
import numpy as np
import joblib
import warnings

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Suppress all warnings for production
warnings.filterwarnings('ignore')

# Ensure backend directory is on path (needed when running engine.py directly)
_backend_dir = str(Path(__file__).resolve().parent.parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# Stage 1: Scanner imports
from app.core.scanner.stage1_scanner import GlitchForgeScanner
from app.core.scanner.base_scanner import VulnerabilityResult, VulnerabilityType

# Stage 2: ML imports
from app.core.ml.feature_engineering import FeatureEngineer

# Stage 4: Prioritization imports
from app.core.prioritization.engine import RiskPrioritizationEngine
from app.core.prioritization.manager import PriorityQueueManager
from app.core.prioritization.data_models import RiskScore

# Stage 3: XAI imports
from app.core.xai.shap_explainer import SHAPExplainer
from app.core.xai.lime_explainer import LIMEExplainer

# Utilities
from app.utils.logger import get_logger

# Config
from app.config import SCANNER_CONFIG, X_TRAIN_PATH, PROCESSED_DATA_DIR


# Human-readable names for ML feature columns
FEATURE_DISPLAY_NAMES = {
    'cvss_base_score': 'CVSS Base Score',
    'cvss_exploitability_score': 'Exploitability Score',
    'cvss_impact_score': 'Impact Score',
    'has_exploit': 'Known Exploit Exists',
    'age_days': 'Vulnerability Age (days)',
    'days_since_modified': 'Days Since Last Update',
    'modification_span_days': 'Modification History Span',
    'affected_products_count': 'Affected Products Count',
    'exploit_cvss_interaction': 'Exploit + CVSS Interaction',
    'total_impact_score': 'Total Impact Score',
    'attack_vector_score': 'Attack Vector Score',
    'attack_complexity_score': 'Attack Complexity Score',
    'privileges_required_score': 'Privileges Required',
    'user_interaction_score': 'User Interaction Required',
    'confidentiality_impact_score': 'Confidentiality Impact',
    'integrity_impact_score': 'Integrity Impact',
    'availability_impact_score': 'Availability Impact',
    'cvss_severity_encoded': 'Severity Level',
    'cvss_scope_encoded': 'Scope (Changed/Unchanged)',
    'is_critical': 'Critical Severity',
    'is_high': 'High Severity',
    'is_medium': 'Medium Severity',
    'high_exploitability': 'Highly Exploitable',
    'high_impact': 'High Impact',
    'single_product': 'Single Product Affected',
    'multiple_products': 'Multiple Products Affected',
    'widespread': 'Widespread Impact',
    'publish_quarter': 'Publication Quarter',
}


def _get_vuln_metadata(vuln_type: VulnerabilityType, vuln: 'VulnerabilityResult' = None):
    """Get description, CWE ID, and specific remediation for a vulnerability"""

    # Build specific remediation based on actual vulnerability details
    if vuln and vuln_type == VulnerabilityType.SQL_INJECTION:
        remediation = (
            f"The parameter '{vuln.parameter}' on this page is vulnerable to SQL Injection.\n"
            f"1. Use parameterized queries (prepared statements) for any database query that includes the '{vuln.parameter}' parameter.\n"
            f"2. Apply server-side input validation on '{vuln.parameter}' — reject unexpected characters like quotes, dashes, and semicolons.\n"
            f"3. Use an ORM (e.g. SQLAlchemy, Django ORM) instead of raw SQL to handle this input.\n"
            f"4. Apply least-privilege database permissions so the web application account cannot DROP or ALTER tables."
        )
    elif vuln and vuln_type == VulnerabilityType.XSS:
        remediation = (
            f"The parameter '{vuln.parameter}' on this page reflects user input without proper encoding.\n"
            f"1. HTML-encode all output of '{vuln.parameter}' before rendering it in the page — use your framework's auto-escaping (e.g. Jinja2, React JSX).\n"
            f"2. Add a Content-Security-Policy header (e.g. script-src 'self') to block inline script execution.\n"
            f"3. Validate and sanitize '{vuln.parameter}' on the server side — strip or reject HTML tags and event handlers.\n"
            f"4. Use HttpOnly and Secure flags on session cookies to limit what stolen scripts can access."
        )
    elif vuln and vuln_type == VulnerabilityType.CSRF:
        remediation = (
            f"This page at '{vuln.url}' lacks CSRF protection on its forms.\n"
            f"1. Add a unique CSRF token to every form on this page and validate it server-side on submission.\n"
            f"2. Set the SameSite attribute on session cookies to 'Strict' or 'Lax' to prevent cross-origin requests.\n"
            f"3. Verify the Origin and Referer headers on state-changing requests to ensure they come from your domain.\n"
            f"4. Use your framework's built-in CSRF middleware (e.g. Django csrf_protect, Express csurf)."
        )
    else:
        # Fallback generic
        metadata_generic = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
            VulnerabilityType.XSS: "Encode all user input before displaying it. Use Content Security Policy (CSP) headers.",
            VulnerabilityType.CSRF: "Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute.",
        }
        remediation = metadata_generic.get(vuln_type, "Follow security best practices.")

    descriptions = {
        VulnerabilityType.SQL_INJECTION: "Application is vulnerable to SQL Injection attacks. Attackers can manipulate database queries to access or modify data.",
        VulnerabilityType.XSS: "Application is vulnerable to Cross-Site Scripting (XSS). Attackers can inject malicious scripts into web pages viewed by users.",
        VulnerabilityType.CSRF: "Application lacks CSRF protection. Attackers can trick users into performing unwanted actions.",
    }
    cwe_ids = {
        VulnerabilityType.SQL_INJECTION: "CWE-89",
        VulnerabilityType.XSS: "CWE-79",
        VulnerabilityType.CSRF: "CWE-352",
    }

    return {
        'description': descriptions.get(vuln_type, "Security vulnerability detected"),
        'cwe_id': cwe_ids.get(vuln_type, "CWE-000"),
        'remediation': remediation
    }


class GlitchForgeEngine:
    """
    GlitchForge AI-Enhanced Vulnerability Scanner Engine

    Combines traditional security scanning with machine learning for intelligent
    vulnerability detection, risk assessment, and prioritization.

    Features:
    - Automated vulnerability scanning (SQL, XSS, CSRF)
    - ML-based risk prediction (Random Forest + Neural Network)
    - Explainable AI with SHAP/LIME
    - Intelligent remediation prioritization
    """

    def __init__(self, models_dir: str = 'models'):
        """
        Initialize GlitchForge Engine and load ML models

        Args:
            models_dir: Directory containing trained models
        """
        # Print banner
        self._print_banner()

        self.logger = get_logger("GlitchForgeEngine")
        self.models_dir = Path(__file__).parent.parent.parent / models_dir

        # Models (loaded once)
        self.rf_model = None
        self.nn_model = None
        self.feature_engineer = None
        self.prioritization_engine = None

        # XAI explainers (loaded once)
        self.shap_explainer = None
        self.lime_explainer = None
        self.feature_names = None

        # Load models at startup
        self._load_models()

        # Initialize XAI explainers
        self._init_xai_explainers()

        # Initialize prioritization engine
        self.prioritization_engine = RiskPrioritizationEngine()

        self.logger.info("GlitchForge Engine initialized and ready")

    def _print_banner(self):
        """Print GlitchForge banner"""
        banner = """
╔══════════════════════════════════════════════════════╗
║                                                      ║
║     ██████╗ ██╗     ██╗████████╗ ██████╗██╗  ██╗     ║
║    ██╔════╝ ██║     ██║╚══██╔══╝██╔════╝██║  ██║     ║
║    ██║  ███╗██║     ██║   ██║   ██║     ███████║     ║
║    ██║   ██║██║     ██║   ██║   ██║     ██╔══██║     ║
║    ╚██████╔╝███████╗██║   ██║   ╚██████╗██║  ██║     ║
║     ╚═════╝ ╚══════╝╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝     ║
║                                                      ║
║    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗        ║
║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝        ║
║    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗          ║
║    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝          ║
║    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗        ║
║    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝        ║
║                                                      ║
║      Explainable AI Vulnerability Management         ║
║            Complete System Demonstration             ║
║                                                      ║
║    Scanning  •  ML Analysis  •  Risk Assessment      ║
╚══════════════════════════════════════════════════════╝

Student: Belal Almshmesh(U2687294)
Supervisor: Dr. Halima Kure
University of East London - BSc Computer Science
"""
        try:
            print(banner)
        except UnicodeEncodeError:
            # Fallback for Windows console
            print("\n" + "="*54)
            print(" " * 15 + "GLITCHFORGE")
            print(" " * 8 + "Explainable AI Vulnerability Management")
            print("="*54 + "\n")

    def _load_models(self):
        """Load ML models once at startup"""
        self.logger.info("Loading ML models...")

        rf_path = self.models_dir / 'random_forest.pkl'
        nn_path = self.models_dir / 'neural_network.h5'

        if rf_path.exists() and nn_path.exists():
            try:
                # Load Random Forest
                self.rf_model = joblib.load(rf_path)
                self.logger.info("Random Forest loaded")

                # Load Neural Network
                from tensorflow import keras
                self.nn_model = keras.models.load_model(nn_path)
                self.logger.info("Neural Network loaded")

                # Load or create feature engineer
                scaler_path = self.models_dir / 'scaler.pkl'
                if scaler_path.exists():
                    self.feature_engineer = joblib.load(scaler_path)
                else:
                    self.feature_engineer = FeatureEngineer()

                self.logger.info("Feature engineer ready")

            except Exception as e:
                self.logger.error(f"Error loading models: {e}")
                self.rf_model = None
                self.nn_model = None
        else:
            self.logger.warning("Models not found. Using fallback mode.")
            self.logger.warning("   Train models with: python -m app.core.ml.stage2_train")

    def _init_xai_explainers(self):
        """Initialize SHAP and LIME explainers once at startup using training data"""
        if not self.rf_model:
            self.logger.warning("RF model not loaded - XAI explainers skipped")
            return

        try:
            # Load feature names
            feature_names_path = PROCESSED_DATA_DIR / 'feature_names.txt'
            if feature_names_path.exists():
                with open(feature_names_path, 'r') as f:
                    self.feature_names = [line.strip() for line in f if line.strip()]
            else:
                # Fallback: use model's feature names
                self.feature_names = list(self.rf_model.feature_names_in_)

            self.logger.info(f"Loaded {len(self.feature_names)} feature names for XAI")

            # Load training data for background samples
            X_train = None
            if X_TRAIN_PATH.exists():
                X_train = pd.read_csv(X_TRAIN_PATH).values
                self.logger.info(f"Loaded X_train ({X_train.shape}) for XAI background")
            else:
                self.logger.warning("X_train.csv not found - XAI explainers will use limited background")

            # Initialize SHAP (TreeExplainer for RF - fast and exact)
            self.shap_explainer = SHAPExplainer(
                model=self.rf_model,
                feature_names=self.feature_names,
                model_type='random_forest',
                background_samples=100
            )
            if X_train is not None:
                self.shap_explainer.create_explainer(X_train)
            self.logger.info("SHAP explainer initialized (TreeExplainer)")

            # Initialize LIME
            self.lime_explainer = LIMEExplainer(
                model=self.rf_model,
                feature_names=self.feature_names,
                class_names=['Low Risk', 'Medium Risk', 'High Risk'],
                mode='classification'
            )
            if X_train is not None:
                self.lime_explainer.create_explainer(X_train)
            self.logger.info("LIME explainer initialized")

        except Exception as e:
            self.logger.error(f"Error initializing XAI explainers: {e}")
            self.shap_explainer = None
            self.lime_explainer = None

    def full_scan(
        self,
        url: str,
        scan_types: List[str] = ['sql', 'xss', 'csrf']
    ) -> List[VulnerabilityResult]:
        """
        Full vulnerability scan using all payloads from config

        Args:
            url: Target URL
            scan_types: Types of scans to run

        Returns:
            List of vulnerabilities found
        """
        scanner = GlitchForgeScanner(SCANNER_CONFIG)

        try:
            scanner.scan_all(
                url=url,
                scan_types=scan_types
            )
            return scanner.all_results
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            return []

    def quick_scan(
        self,
        url: str,
        scan_types: List[str] = ['sql', 'xss', 'csrf']
    ) -> List[VulnerabilityResult]:
        """
        Fast vulnerability scan with reduced payloads

        Args:
            url: Target URL
            scan_types: Types of scans to run

        Returns:
            List of vulnerabilities found
        """
        quick_config = {
            'timeout': 3,
            'max_retries': 1,
            'user_agent': 'GlitchForge/1.0',
            'max_payloads': 5
        }

        scanner = GlitchForgeScanner(quick_config)

        try:
            scanner.scan_all(
                url=url,
                scan_types=scan_types
            )
            return scanner.all_results
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            return []

    def predict_risks(
        self,
        vulnerabilities: List[VulnerabilityResult]
    ) -> List[Dict]:
        """
        Predict risk levels for vulnerabilities using ML models

        Args:
            vulnerabilities: List of vulnerability results

        Returns:
            List of predictions with explanations
        """
        if not vulnerabilities:
            return []

        if not self.rf_model or not self.nn_model:
            self.logger.warning("Models not loaded. Cannot predict risks.")
            return []

        # Convert vulnerabilities to all 29 engineered features the model expects
        df = self._convert_to_features(vulnerabilities)

        feature_cols = list(self.rf_model.feature_names_in_)
        X = df[feature_cols]

        # Predictions
        predictions = []

        for idx, row in df.iterrows():
            X_sample = X.iloc[[idx]]

            # Random Forest prediction
            rf_pred = self.rf_model.predict(X_sample)[0]
            rf_proba = self.rf_model.predict_proba(X_sample)[0]
            rf_confidence = float(max(rf_proba))

            # Neural Network prediction
            nn_pred = int(np.argmax(self.nn_model.predict(X_sample, verbose=0)[0]))
            nn_proba = self.nn_model.predict(X_sample, verbose=0)[0]
            nn_confidence = float(max(nn_proba))

            # Generate real XAI explanations
            feature_importance = {}
            shap_data = None
            lime_data = None

            X_numpy = X_sample.values

            # SHAP explanation (fast - TreeExplainer)
            if self.shap_explainer and self.shap_explainer.explainer:
                try:
                    shap_values_raw = self.shap_explainer.explainer.shap_values(X_numpy)

                    # Extract positive class SHAP values
                    if isinstance(shap_values_raw, list) and len(shap_values_raw) > 1:
                        sv = shap_values_raw[1][0]  # Positive class, first sample
                    elif isinstance(shap_values_raw, np.ndarray) and shap_values_raw.ndim == 3:
                        sv = shap_values_raw[0, :, 1]
                    else:
                        sv = shap_values_raw[0] if shap_values_raw.ndim == 2 else shap_values_raw

                    # Build feature importance from SHAP
                    abs_shap = np.abs(sv)
                    total = abs_shap.sum() if abs_shap.sum() > 0 else 1.0
                    for i, fname in enumerate(self.feature_names):
                        feature_importance[fname] = round(float(abs_shap[i] / total), 4)

                    # Build SHAP data for frontend
                    base_val = self.shap_explainer.explainer.expected_value
                    if isinstance(base_val, (list, np.ndarray)):
                        base_val = base_val[1] if len(base_val) > 1 else base_val[0]

                    # Top contributing features (sorted by |SHAP|)
                    sorted_indices = np.argsort(np.abs(sv))[::-1]
                    top_features = []
                    for i in sorted_indices[:10]:
                        raw_name = self.feature_names[i]
                        display_name = FEATURE_DISPLAY_NAMES.get(raw_name, raw_name.replace('_', ' ').title())
                        pct = round(float(abs_shap[i] / total) * 100, 1)
                        direction = 'increases' if sv[i] > 0 else 'decreases'
                        top_features.append({
                            'feature': display_name,
                            'contribution_pct': pct,
                            'direction': direction,
                            'description': f"{display_name} {direction} risk by {pct}%"
                        })

                    shap_data = {
                        'method': 'Feature contributions to risk prediction',
                        'summary': f"Top risk driver: {top_features[0]['feature']} ({top_features[0]['contribution_pct']}% contribution)" if top_features else '',
                        'features': top_features
                    }
                except Exception as e:
                    self.logger.warning(f"SHAP explanation failed: {e}")

            # LIME explanation
            if self.lime_explainer and self.lime_explainer.explainer:
                try:
                    lime_exp = self.lime_explainer.explain_single(
                        X_numpy[0], num_features=10, num_samples=500
                    )
                    lime_dict = self.lime_explainer.get_explanation_as_dict(lime_exp)

                    lime_features = []
                    abs_total = sum(abs(w) for w in lime_dict['weights']) or 1.0
                    for fname, weight in zip(lime_dict['features'], lime_dict['weights']):
                        display_name = FEATURE_DISPLAY_NAMES.get(fname, fname.replace('_', ' ').title())
                        pct = round(abs(weight) / abs_total * 100, 1)
                        direction = 'increases' if weight > 0 else 'decreases'
                        lime_features.append({
                            'feature': display_name,
                            'contribution_pct': pct,
                            'direction': direction,
                            'description': f"{display_name} {direction} risk by {pct}%"
                        })

                    lime_data = {
                        'method': 'Local interpretable model explanation',
                        'model_fit': round(float(lime_dict['score']), 4),
                        'summary': f"Top risk driver: {lime_features[0]['feature']} ({lime_features[0]['contribution_pct']}% influence)" if lime_features else '',
                        'features': lime_features
                    }

                    # Fill in feature_importance from LIME if SHAP didn't run
                    if not feature_importance:
                        abs_weights = {f: abs(w) for f, w in zip(lime_dict['features'], lime_dict['weights'])}
                        total_w = sum(abs_weights.values()) or 1.0
                        feature_importance = {f: round(w / total_w, 4) for f, w in abs_weights.items()}
                except Exception as e:
                    self.logger.warning(f"LIME explanation failed: {e}")

            # Fallback if both failed
            if not feature_importance:
                feature_importance = {
                    'cvss_base_score': 0.35,
                    'cvss_exploitability_score': 0.25,
                    'cvss_impact_score': 0.20,
                    'has_exploit': 0.12,
                    'age_days': 0.08
                }

            explanation_text = self._generate_prediction_explanation(
                row, feature_importance, rf_pred, rf_confidence
            )

            prediction = {
                'vulnerability_id': row['cve_id'],
                'original_vuln': row['_original_vuln'],
                'rf_prediction': int(rf_pred),
                'rf_confidence': rf_confidence,
                'nn_prediction': nn_pred,
                'nn_confidence': nn_confidence,
                'cvss_base_score': float(row['cvss_base_score']),
                'cvss_exploitability_score': float(row['cvss_exploitability_score']),
                'cvss_impact_score': float(row['cvss_impact_score']),
                'has_exploit': bool(row['has_exploit']),
                'explanation_text': explanation_text,
                'feature_importance': feature_importance,
                'shap_explanation': shap_data,
                'lime_explanation': lime_data
            }

            predictions.append(prediction)

        return predictions

    def _generate_prediction_explanation(
        self,
        data_row: pd.Series,
        feature_importance: Dict[str, float],
        prediction: int,
        confidence: float
    ) -> str:
        """Generate human-readable explanation for prediction"""
        risk_names = ['Low', 'Medium', 'High']
        risk_level = risk_names[prediction]

        explanation = f"Classified as {risk_level} risk with {confidence:.0%} confidence. "

        # Add key factor analysis
        factors = []

        # CVSS Base Score
        cvss_base = data_row.get('cvss_base_score', 0)
        if cvss_base >= 9.0:
            factors.append(f"critical CVSS base score ({cvss_base:.1f})")
        elif cvss_base >= 7.0:
            factors.append(f"high CVSS base score ({cvss_base:.1f})")
        elif cvss_base >= 4.0:
            factors.append(f"moderate CVSS base score ({cvss_base:.1f})")

        # Exploitability
        cvss_exploit = data_row.get('cvss_exploitability_score', 0)
        if cvss_exploit >= 3.5:
            factors.append(f"high exploitability ({cvss_exploit:.1f})")

        # Exploit availability
        if data_row.get('has_exploit', False):
            factors.append("known exploit exists")

        if factors:
            explanation += "Key factors: " + ", ".join(factors) + "."

        return explanation

    def prioritize_vulnerabilities(
        self,
        predictions: List[Dict]
    ) -> List[RiskScore]:
        """
        Prioritize vulnerabilities for remediation

        Args:
            predictions: List of predictions from ML models

        Returns:
            List of risk scores with priorities
        """
        if not predictions:
            return []

        risk_scores = []

        for pred in predictions:
            risk_score = self.prioritization_engine.prioritize_vulnerability(
                vuln_id=pred['vulnerability_id'],
                cvss_base=pred['cvss_base_score'],
                cvss_exploitability=pred['cvss_exploitability_score'],
                cvss_impact=pred['cvss_impact_score'],
                has_exploit=pred['has_exploit'],
                rf_prediction=pred['rf_prediction'],
                rf_confidence=pred['rf_confidence'],
                nn_prediction=pred['nn_prediction'],
                nn_confidence=pred['nn_confidence'],
                age_days=30,
                products_count=1,
                feature_importance=pred['feature_importance']
            )

            risk_scores.append(risk_score)

        return risk_scores

    def scan_and_analyze(
        self,
        url: str,
        scan_types: List[str] = ['sql', 'xss', 'csrf']
    ) -> Dict:
        """
        Complete scan and analysis pipeline

        Args:
            url: Target URL
            scan_types: Types of scans

        Returns:
            Complete results dictionary with explanations
        """
        start_time = time.time()

        # Stage 1: Full Scan (all payloads)
        self.logger.info(f"Scanning {url}...")
        vulnerabilities = self.full_scan(url, scan_types)
        scan_time = time.time() - start_time

        if not vulnerabilities:
            return {
                'success': True,
                'url': url,
                'vulnerabilities_found': 0,
                'scan_time': scan_time,
                'message': 'No vulnerabilities found'
            }

        # Stage 2: Predict
        pred_start = time.time()
        predictions = self.predict_risks(vulnerabilities)
        pred_time = time.time() - pred_start

        # Stage 4: Prioritize
        prior_start = time.time()
        risk_scores = self.prioritize_vulnerabilities(predictions)
        prior_time = time.time() - prior_start

        # Sort by risk
        risk_scores.sort(key=lambda x: x.final_risk_score, reverse=True)

        # Build lookup: vulnerability_id -> {original_vuln, xai data}
        vuln_lookup = {}
        xai_lookup = {}
        for pred in predictions:
            vuln_lookup[pred['vulnerability_id']] = pred['original_vuln']
            xai_lookup[pred['vulnerability_id']] = {
                'shap_explanation': pred.get('shap_explanation'),
                'lime_explanation': pred.get('lime_explanation')
            }

        total_time = time.time() - start_time

        # Format results with full vulnerability details
        results = {
            'success': True,
            'url': url,
            'vulnerabilities_found': len(vulnerabilities),
            'scan_time': round(scan_time, 2),
            'prediction_time': round(pred_time, 2),
            'prioritization_time': round(prior_time, 2),
            'total_time': round(total_time, 2),
            'risk_scores': [
                self._format_risk_score(
                    rs,
                    vuln_lookup.get(rs.vulnerability_id),
                    xai_lookup.get(rs.vulnerability_id)
                )
                for rs in risk_scores
            ],
            'statistics': self._calculate_statistics(risk_scores),
            'timestamp': datetime.now().isoformat()
        }

        return results

    def _convert_to_features(
        self,
        vulnerabilities: List[VulnerabilityResult]
    ) -> pd.DataFrame:
        """Convert vulnerabilities to all 29 engineered ML features the model expects."""
        # Encoding maps matching feature_engineering.py training logic
        attack_vector_scores = {'NETWORK': 0.85, 'ADJACENT': 0.62, 'LOCAL': 0.55, 'PHYSICAL': 0.20}
        attack_complexity_scores = {'LOW': 0.85, 'HIGH': 0.44}
        privileges_required_scores = {'NONE': 0.85, 'LOW': 0.62, 'HIGH': 0.27}
        user_interaction_scores = {'NONE': 0.85, 'REQUIRED': 0.62}
        impact_scores = {'HIGH': 1.0, 'LOW': 0.22, 'NONE': 0.0}
        severity_encoded = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0, 'INFORMATIONAL': 0}

        cvss_map = {
            'Critical': (9.0, 10.0),
            'High': (7.0, 8.9),
            'Medium': (4.0, 6.9),
            'Low': (0.1, 3.9),
            'Informational': (0.0, 0.0)
        }

        exploitability_map = {
            'SQL Injection': 3.9,
            'Cross-Site Scripting (XSS)': 3.5,
            'Cross-Site Request Forgery (CSRF)': 2.8
        }

        data = []

        for vuln in vulnerabilities:
            cvss_range = cvss_map.get(vuln.severity.value, (5.0, 6.0))
            cvss_base = np.random.uniform(cvss_range[0], cvss_range[1])
            cvss_exploitability = exploitability_map.get(vuln.vuln_type.value, 2.0)
            impact_score = cvss_base * 0.6
            has_exploit = vuln.confidence > 0.8

            # Raw CVSS vector values for this vuln type
            user_interaction = 'REQUIRED' if 'XSS' in vuln.vuln_type.value else 'NONE'
            confidentiality = 'HIGH'
            integrity = 'HIGH'
            availability = 'LOW'

            # Derive numeric scores matching feature_engineering.py
            av_score = attack_vector_scores['NETWORK']
            ac_score = attack_complexity_scores['LOW']
            pr_score = privileges_required_scores['NONE']
            ui_score = user_interaction_scores[user_interaction]
            conf_score = impact_scores[confidentiality]
            integ_score = impact_scores[integrity]
            avail_score = impact_scores[availability]
            total_impact = conf_score + integ_score + avail_score

            affected_products_count = 1
            publish_quarter = (datetime.now().month - 1) // 3 + 1

            record = {
                'cve_id': f"SCAN-{hash(vuln.url + vuln.parameter + vuln.vuln_type.value) % 10000:04d}",
                '_original_vuln': vuln,

                # Base CVSS scores
                'cvss_base_score': cvss_base,
                'cvss_exploitability_score': cvss_exploitability,
                'cvss_impact_score': impact_score,

                # Severity bins
                'is_critical': int(vuln.severity.value == 'Critical'),
                'is_high': int(vuln.severity.value == 'High'),
                'is_medium': int(vuln.severity.value == 'Medium'),
                'is_low': int(vuln.severity.value in ('Low', 'Informational')),

                # Threshold flags
                'high_exploitability': int(cvss_exploitability >= 3.5),
                'high_impact': int(impact_score >= 5.9),

                # CVSS vector numeric scores
                'attack_vector_score': av_score,
                'attack_complexity_score': ac_score,
                'privileges_required_score': pr_score,
                'user_interaction_score': ui_score,
                'confidentiality_score': conf_score,
                'integrity_score': integ_score,
                'availability_score': avail_score,
                'total_impact_score': total_impact,

                # Exploit features
                'has_exploit': int(has_exploit),
                'exploit_cvss_interaction': float(has_exploit) * cvss_base,

                # Temporal features (scan-time defaults)
                'age_days': 30,
                'days_since_modified': 0,
                'modification_span_days': 0,
                'publish_quarter': publish_quarter,

                # Product features
                'affected_products_count': affected_products_count,
                'single_product': int(affected_products_count == 1),
                'multiple_products': int(affected_products_count > 1),
                'widespread': int(affected_products_count > 10),

                # Encoded categoricals
                'cvss_severity_encoded': severity_encoded.get(vuln.severity.value.upper(), 0),
                'cvss_scope_encoded': 1,  # CHANGED
            }

            data.append(record)

        return pd.DataFrame(data)

    def _format_risk_score(self, risk_score: RiskScore, original_vuln: Optional[VulnerabilityResult] = None, xai_data: Optional[Dict] = None) -> Dict:
        """Format risk score for JSON response, including original vulnerability details and XAI explanations"""
        result = {
            'vulnerability_id': risk_score.vulnerability_id,
            'risk_score': round(risk_score.final_risk_score, 2),
            'risk_level': risk_score.risk_level.value,
            'remediation_priority': risk_score.remediation_priority.value,
            'cvss_base': round(risk_score.cvss_base_score, 1),
            'cvss_exploitability': round(risk_score.cvss_exploitability_score, 1),
            'cvss_impact': round(risk_score.cvss_impact_score, 1),
            'has_exploit': risk_score.has_exploit,
            'model_agreement': risk_score.model_agreement,
            'confidence': round((risk_score.rf_confidence + risk_score.nn_confidence) / 2, 2),
            'explanation': risk_score.explanation_text,
            'primary_factors': risk_score.primary_factors
        }

        # Add XAI explanations (SHAP + LIME)
        if xai_data:
            if xai_data.get('shap_explanation'):
                result['shap_explanation'] = xai_data['shap_explanation']
            if xai_data.get('lime_explanation'):
                result['lime_explanation'] = xai_data['lime_explanation']

        # Merge in original scanner details (where, what caused it, how to fix)
        if original_vuln:
            # Get metadata for vulnerability type (with specific remediation)
            metadata = _get_vuln_metadata(original_vuln.vuln_type, original_vuln)

            result['where'] = {
                'url': original_vuln.url,
                'parameter': original_vuln.parameter,
                'method': 'GET/POST'
            }
            result['what'] = {
                'vulnerability_type': original_vuln.vuln_type.value,
                'payload_used': original_vuln.payload,
                'description': metadata['description'],
                'evidence': original_vuln.evidence,
                'cwe_id': metadata['cwe_id'],
                'confidence': original_vuln.confidence
            }
            result['how_to_fix'] = {
                'remediation': metadata['remediation'],
                'priority': risk_score.remediation_priority.value
            }

        return result

    def _calculate_statistics(self, risk_scores: List[RiskScore]) -> Dict:
        """Calculate summary statistics"""
        if not risk_scores:
            return {}

        scores = [rs.final_risk_score for rs in risk_scores]

        # Count by risk level
        risk_levels = {}
        for rs in risk_scores:
            level = rs.risk_level.value
            risk_levels[level] = risk_levels.get(level, 0) + 1

        # Count by priority
        priorities = {}
        for rs in risk_scores:
            priority = rs.remediation_priority.value
            priorities[priority] = priorities.get(priority, 0) + 1

        # Model agreement
        agreements = sum(1 for rs in risk_scores if rs.model_agreement)

        return {
            'total_vulnerabilities': len(risk_scores),
            'average_risk_score': round(np.mean(scores), 2),
            'median_risk_score': round(np.median(scores), 2),
            'max_risk_score': round(np.max(scores), 2),
            'min_risk_score': round(np.min(scores), 2),
            'model_agreement_rate': round(agreements / len(risk_scores) * 100, 1),
            'risk_levels': risk_levels,
            'remediation_priorities': priorities
        }


# --- Singleton management ---

_engine_instance = None


def init_engine():
    """Initialize the engine singleton (called at startup)."""
    global _engine_instance
    _engine_instance = GlitchForgeEngine()


def get_engine() -> GlitchForgeEngine:
    """Get the singleton engine instance, creating it if needed."""
    global _engine_instance
    if _engine_instance is None:
        init_engine()
    return _engine_instance


# --- CLI usage (standalone execution) ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='GlitchForge AI-Enhanced Vulnerability Scanner'
    )
    parser.add_argument('--url', required=True, help='URL to scan')
    parser.add_argument('--output', help='Output JSON file')
    parser.add_argument(
        '--scan-types',
        nargs='+',
        default=['sql', 'xss', 'csrf'],
        help='Types of scans to run'
    )

    args = parser.parse_args()

    # Initialize engine
    engine = GlitchForgeEngine()

    # Run scan
    print(f"\nScanning {args.url}...")
    print(f"Scan types: {', '.join(args.scan_types)}\n")

    results = engine.scan_and_analyze(args.url, args.scan_types)

    # Display results
    print("\n" + "="*70)
    print("SCAN RESULTS")
    print("="*70)
    print(f"\nScan complete!")
    print(f"  Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"  Total time: {results.get('total_time', results.get('scan_time', 'N/A'))}s")

    if results['vulnerabilities_found'] > 0:
        stats = results['statistics']
        print(f"  Average risk score: {stats.get('average_risk_score', 0)}/100")
        print(f"  Model agreement: {stats.get('model_agreement_rate', 0)}%")

    # Save to file
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")

    # Show top vulnerabilities
    if results['vulnerabilities_found'] > 0:
        print("\n" + "="*70)
        print("TOP CRITICAL VULNERABILITIES")
        print("="*70)

        for i, vuln in enumerate(results['risk_scores'][:5], 1):
            print(f"\n  [{i}] {vuln['vulnerability_id']}  |  {vuln['risk_level']} Risk  |  Score: {vuln['risk_score']}/100")
            print(f"      Priority: {vuln['remediation_priority']}")
            print(f"      CVSS: {vuln['cvss_base']}  Exploitability: {vuln['cvss_exploitability']}  Impact: {vuln['cvss_impact']}")
            print()
            if 'where' in vuln:
                print(f"      WHERE IT OCCURRED:")
                print(f"        URL:       {vuln['where']['url']}")
                print(f"        Parameter: {vuln['where']['parameter']}")
            if 'what' in vuln:
                print(f"      WHAT CAUSED IT:")
                print(f"        Type:      {vuln['what']['vulnerability_type']}  ({vuln['what']['cwe_id']})")
                print(f"        Payload:   {vuln['what']['payload_used'][:80]}")
                print(f"        Evidence:  {vuln['what']['evidence'][:120]}")
                print(f"        Details:   {vuln['what']['description'][:150]}")
            if 'how_to_fix' in vuln:
                print(f"      HOW TO FIX:")
                # Wrap remediation lines at 70 chars
                for line in vuln['how_to_fix']['remediation'].split('\n'):
                    print(f"        {line.strip()}")
            print()
            print(f"      ML: {vuln['explanation']}")
            print("      " + "-"*64)

    print("\n" + "="*70)
    print("Scan complete!")
    print("="*70 + "\n")
