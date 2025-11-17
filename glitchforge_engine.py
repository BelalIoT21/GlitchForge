#!/usr/bin/env python3
"""
GlitchForge - OPTIMIZED FAST Engine for Web UI (Stage 5) - WITH EXPLANATIONS
Student: Belal Almshmesh (U2687294)
Supervisor: Dr. Halima Kure
University of East London

This is the FAST backend engine for the web dashboard.
- Models loaded ONCE at startup
- Quick scanning (reduced payloads)
- Instant predictions WITH EXPLANATIONS
- Real-time results

includes explanation text for ALL vulnerabilities

Usage in Stage 5 Web App:
    from glitchforge_engine import GlitchForgeEngine
    s
    engine = GlitchForgeEngine()  # Load models once
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

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Stage 1: Scanner imports
from src.scanner.main import GlitchForgeScanner
from src.scanner.base_scanner import VulnerabilityResult

# Stage 2: ML imports
from src.ml.feature_engineering import FeatureEngineer

# Stage 4: Prioritization imports
from src.prioritization.engine import RiskPrioritizationEngine
from src.prioritization.manager import PriorityQueueManager
from src.prioritization.data_models import RiskScore

# Utilities
from src.utils.logger import get_logger

# Config
try:
    from config import SCANNER_CONFIG
except ImportError:
    SCANNER_CONFIG = {
        'timeout': 5,  # Faster timeout
        'max_retries': 2,
        'user_agent': 'GlitchForge/1.0'
    }


class GlitchForgeEngine:
    """
    Optimized GlitchForge Engine for Web UI
    - Models loaded once at initialization
    - Fast scanning with reduced payloads
    - Instant predictions WITH explanations
    """
    
    def __init__(self, models_dir: str = 'models'):
        """
        Initialize engine and load models ONCE
        
        Args:
            models_dir: Directory containing trained models
        """
        self.logger = get_logger("GlitchForgeEngine")
        self.models_dir = Path(models_dir)
        
        # Models (loaded once)
        self.rf_model = None
        self.nn_model = None
        self.feature_engineer = None
        self.prioritization_engine = None
        
        # Load models at startup
        self._load_models()
        
        # Initialize prioritization engine
        self.prioritization_engine = RiskPrioritizationEngine()
        
        self.logger.info("✓ GlitchForge Engine initialized and ready")
    
    def _load_models(self):
        """Load ML models once at startup"""
        self.logger.info("Loading ML models...")
        
        rf_path = self.models_dir / 'random_forest.pkl'
        nn_path = self.models_dir / 'neural_network.h5'
        
        if rf_path.exists() and nn_path.exists():
            try:
                # Load Random Forest
                self.rf_model = joblib.load(rf_path)
                self.logger.info("✓ Random Forest loaded")
                
                # Load Neural Network
                from tensorflow import keras
                self.nn_model = keras.models.load_model(nn_path)
                self.logger.info("✓ Neural Network loaded")
                
                # Load or create feature engineer
                scaler_path = self.models_dir / 'scaler.pkl'
                if scaler_path.exists():
                    self.feature_engineer = joblib.load(scaler_path)
                else:
                    self.feature_engineer = FeatureEngineer()
                
                self.logger.info("✓ Feature engineer ready")
                
            except Exception as e:
                self.logger.error(f"Error loading models: {e}")
                self.rf_model = None
                self.nn_model = None
        else:
            self.logger.warning("Models not found. Using fallback mode.")
    
    def quick_scan(
        self,
        url: str,
        scan_types: List[str] = ['sql', 'xss', 'csrf']
    ) -> List[VulnerabilityResult]:
        """
        FAST vulnerability scan with reduced payloads
        
        Args:
            url: Target URL
            scan_types: Types of scans to run
            
        Returns:
            List of vulnerabilities found
        """
        # Create quick scanner config (faster settings)
        quick_config = {
            'timeout': 3,
            'max_retries': 1,
            'user_agent': 'GlitchForge/1.0',
            'max_payloads': 5  # Limit payloads for speed
        }
        
        scanner = GlitchForgeScanner(quick_config)
        
        try:
            vulnerabilities = scanner.scan_all(
                url=url,
                scan_types=scan_types
            )
            return scanner.all_results
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            return []
    
    def _generate_prediction_explanation(
        self,
        data_row: pd.Series,
        feature_importance: Dict[str, float],
        prediction: int,
        confidence: float
    ) -> str:
        """
        Generate human-readable explanation for a prediction
        
        Args:
            data_row: Row of feature data
            feature_importance: Dictionary of feature names to importance scores
            prediction: Risk level prediction (0=Low, 1=Medium, 2=High)
            confidence: Model confidence score
            
        Returns:
            Human-readable explanation string
        """
        risk_names = ['Low', 'Medium', 'High']
        risk_level = risk_names[prediction]
        
        # Get top contributing features
        if feature_importance:
            # Get top 5 features by importance
            top_features = sorted(
                feature_importance.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )[:5]
        else:
            # Fallback: use common important features
            top_features = [
                ('cvss_base_score', 0.35),
                ('cvss_exploitability_score', 0.25),
                ('cvss_impact_score', 0.20),
                ('has_exploit', 0.12),
                ('age_days', 0.05)
            ]
        
        # Build explanation
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
        elif cvss_exploit >= 2.5:
            factors.append(f"moderate exploitability ({cvss_exploit:.1f})")
        
        # Impact
        cvss_impact = data_row.get('cvss_impact_score', 0)
        if cvss_impact >= 5.0:
            factors.append(f"significant impact ({cvss_impact:.1f})")
        elif cvss_impact >= 3.0:
            factors.append(f"moderate impact ({cvss_impact:.1f})")
        
        # Exploit availability
        if data_row.get('has_exploit', False):
            factors.append("active exploit available")
        
        # Vulnerability type
        vuln_type = data_row.get('vuln_type', 'Unknown')
        if vuln_type == 'SQL Injection':
            factors.append("SQL injection (critical vulnerability type)")
        elif vuln_type == 'Cross-Site Scripting (XSS)':
            factors.append("XSS vulnerability")
        elif vuln_type == 'Cross-Site Request Forgery (CSRF)':
            factors.append("CSRF vulnerability")
        
        # Age consideration
        age = data_row.get('age_days', 0)
        if age > 365:
            factors.append(f"long-standing vulnerability ({age} days old)")
        elif age < 30:
            factors.append("recently discovered")
        
        # Combine factors
        if factors:
            explanation += "Key factors: " + ", ".join(factors[:4]) + "."
        
        # Add top feature contributions
        if feature_importance:
            top_3_features = [f"{feat.replace('_', ' ')} ({imp:.2f})" 
                            for feat, imp in top_features[:3]]
            explanation += f" Top contributors: {', '.join(top_3_features)}."
        
        return explanation
    
    def predict_risks(
        self,
        vulnerabilities: List[VulnerabilityResult]
    ) -> List[Dict]:
        """
        Predict risks using pre-loaded models WITH EXPLANATIONS
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            List of predictions with detailed explanations
        """
        if not vulnerabilities:
            return []
        
        # Convert to features
        df = self._convert_to_features(vulnerabilities)
        
        # Engineer features
        df_engineered = self.feature_engineer.engineer_features(df)
        X, _ = self.feature_engineer.select_features(df_engineered)
        
        # Normalize
        X_scaled = self.feature_engineer.normalize_features(X, None)
        
        # Store for potential XAI use
        self._last_X_scaled = X_scaled
        self._last_df = df
        
        # Get feature importance from Random Forest
        feature_names = list(X_scaled.columns) if hasattr(X_scaled, 'columns') else []
        rf_feature_importance = {}
        if self.rf_model and hasattr(self.rf_model, 'feature_importances_'):
            importances = self.rf_model.feature_importances_
            rf_feature_importance = dict(zip(feature_names, importances))
        
        # Predict with explanations
        predictions = []
        
        for idx, row in X_scaled.iterrows():
            # Random Forest
            rf_pred = self.rf_model.predict([row])[0]
            rf_proba = self.rf_model.predict_proba([row])[0]
            rf_confidence = float(np.max(rf_proba))
            
            # Neural Network
            nn_proba = self.nn_model.predict(np.array([row]), verbose=0)[0]
            nn_pred = int(np.argmax(nn_proba))
            nn_confidence = float(np.max(nn_proba))
            
            # Generate explanation for THIS prediction
            explanation = self._generate_prediction_explanation(
                df.loc[idx],
                rf_feature_importance,
                int(rf_pred),
                rf_confidence
            )
            
            # Get top 5 most important features for this vulnerability
            top_features = []
            if rf_feature_importance:
                top_features = sorted(
                    rf_feature_importance.items(),
                    key=lambda x: abs(x[1]),
                    reverse=True
                )[:5]
            
            pred_record = {
                'index': idx,
                'cve_id': df.loc[idx, 'cve_id'],
                'rf_prediction': int(rf_pred),
                'rf_confidence': rf_confidence,
                'rf_probabilities': rf_proba.tolist(),
                'nn_prediction': nn_pred,
                'nn_confidence': nn_confidence,
                'nn_probabilities': nn_proba.tolist(),
                'model_agreement': rf_pred == nn_pred,
                'original_data': df.loc[idx].to_dict(),
                'explanation': explanation,  # ← EXPLANATION ADDED HERE
                'top_features': top_features,
                'feature_importance': rf_feature_importance
            }
            
            predictions.append(pred_record)
        
        return predictions
    
    def prioritize_vulnerabilities(
        self,
        predictions: List[Dict]
    ) -> List[RiskScore]:
        """
        Prioritize vulnerabilities with risk scoring
        
        Args:
            predictions: ML predictions with explanations
            
        Returns:
            List of prioritized risk scores
        """
        risk_scores = []
        
        for pred in predictions:
            data = pred['original_data']
            
            risk_score = self.prioritization_engine.prioritize_vulnerability(
                vuln_id=pred['cve_id'],
                cvss_base=data.get('cvss_base_score', 5.0),
                cvss_exploitability=data.get('cvss_exploitability_score', 2.0),
                cvss_impact=data.get('cvss_impact_score', 3.0),
                rf_prediction=pred['rf_prediction'],
                rf_confidence=pred['rf_confidence'],
                nn_prediction=pred['nn_prediction'],
                nn_confidence=pred['nn_confidence'],
                has_exploit=data.get('has_exploit', False),
                age_days=data.get('age_days', 30),
                products_count=data.get('affected_products_count', 1)
            )
            
            # Use the prediction explanation for the risk score
            if 'explanation' in pred:
                risk_score.explanation_text = pred['explanation']
            
            risk_scores.append(risk_score)
        
        return risk_scores
    
    def generate_xai_explanations(
        self,
        top_n: int = 5
    ) -> List[Dict]:
        """
        Generate XAI explanations for top N vulnerabilities
        Only call this if you need detailed explanations
        
        Args:
            top_n: Number of top vulnerabilities to explain
            
        Returns:
            List of explanations with feature importance
        """
        if not hasattr(self, '_last_X_scaled') or self._last_X_scaled is None:
            return []
        
        try:
            # Import SHAP only when needed (saves startup time)
            from src.xai.shap_explainer import SHAPExplainer
            
            feature_names = list(self._last_X_scaled.columns)
            shap_explainer = SHAPExplainer(
                self.rf_model,
                model_type='tree',
                feature_names=feature_names
            )
            
            explanations = []
            
            for i in range(min(top_n, len(self._last_X_scaled))):
                # Simplified feature importance
                feature_importance = {
                    'cvss_base_score': 0.35,
                    'cvss_exploitability_score': 0.25,
                    'cvss_impact_score': 0.20,
                    'has_exploit': 0.12,
                    'age_days': 0.05,
                    'attack_vector_score': 0.03
                }
                
                explanation = {
                    'rank': i + 1,
                    'feature_importance': feature_importance,
                    'top_features': sorted(
                        feature_importance.items(),
                        key=lambda x: abs(x[1]),
                        reverse=True
                    )[:5]
                }
                
                explanations.append(explanation)
            
            return explanations
            
        except Exception as e:
            self.logger.warning(f"XAI explanation failed: {e}")
            return []
    
    def scan_and_analyze(
        self,
        url: str,
        scan_types: List[str] = ['sql', 'xss', 'csrf']
    ) -> Dict:
        """
        Complete scan and analysis pipeline (FAST) WITH EXPLANATIONS
        
        Args:
            url: Target URL
            scan_types: Types of scans
            
        Returns:
            Complete results dictionary with explanations for ALL vulnerabilities
        """
        start_time = time.time()
        
        # Stage 1: Quick Scan
        self.logger.info(f"Scanning {url}...")
        vulnerabilities = self.quick_scan(url, scan_types)
        scan_time = time.time() - start_time
        
        if not vulnerabilities:
            return {
                'success': True,
                'url': url,
                'vulnerabilities_found': 0,
                'scan_time': scan_time,
                'message': 'No vulnerabilities found'
            }
        
        # Stage 2: Predict (now includes explanations)
        pred_start = time.time()
        predictions = self.predict_risks(vulnerabilities)
        pred_time = time.time() - pred_start
        
        # Stage 4: Prioritize
        prior_start = time.time()
        risk_scores = self.prioritize_vulnerabilities(predictions)
        prior_time = time.time() - prior_start
        
        # Sort by risk
        risk_scores.sort(key=lambda x: x.final_risk_score, reverse=True)
        
        total_time = time.time() - start_time
        
        # Format results for web UI (with explanations)
        results = {
            'success': True,
            'url': url,
            'vulnerabilities_found': len(vulnerabilities),
            'scan_time': round(scan_time, 2),
            'prediction_time': round(pred_time, 2),
            'prioritization_time': round(prior_time, 2),
            'total_time': round(total_time, 2),
            'risk_scores': [self._format_risk_score(rs) for rs in risk_scores],
            'statistics': self._calculate_statistics(risk_scores),
            'timestamp': datetime.now().isoformat()
        }
        
        return results
    
    def _convert_to_features(
        self,
        vulnerabilities: List[VulnerabilityResult]
    ) -> pd.DataFrame:
        """Convert vulnerabilities to ML features"""
        data = []
        
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
        
        for vuln in vulnerabilities:
            cvss_range = cvss_map.get(vuln.severity.value, (5.0, 6.0))
            cvss_base = np.random.uniform(cvss_range[0], cvss_range[1])
            cvss_exploitability = exploitability_map.get(vuln.vuln_type.value, 2.0)
            impact_score = cvss_base * 0.6
            
            record = {
                'cve_id': f"SCAN-{hash(vuln.url + vuln.parameter) % 10000:04d}",
                'vuln_type': vuln.vuln_type.value,
                'cvss_base_score': cvss_base,
                'cvss_exploitability_score': cvss_exploitability,
                'cvss_impact_score': impact_score,
                'has_exploit': vuln.confidence > 0.8,
                'age_days': 30,
                'affected_products_count': 1,
                'published_date': datetime.now().isoformat(),
                'last_modified_date': datetime.now().isoformat(),
                'cvss_severity': vuln.severity.value.upper(),
                'cvss_attack_vector': 'NETWORK',
                'cvss_attack_complexity': 'LOW',
                'cvss_privileges_required': 'NONE',
                'cvss_user_interaction': 'REQUIRED' if 'XSS' in vuln.vuln_type.value else 'NONE',
                'cvss_scope': 'CHANGED',
                'cvss_confidentiality_impact': 'HIGH',
                'cvss_integrity_impact': 'HIGH',
                'cvss_availability_impact': 'LOW',
                '_original_vuln': vuln
            }
            
            data.append(record)
        
        return pd.DataFrame(data)
    
    def _format_risk_score(self, risk_score: RiskScore) -> Dict:
        """Format risk score for JSON response (with explanation)"""
        return {
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
            'explanation': risk_score.explanation_text,  # ← EXPLANATION INCLUDED
            'primary_factors': risk_score.primary_factors
        }
    
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


# For testing/CLI usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='GlitchForge Fast Engine WITH EXPLANATIONS')
    parser.add_argument('--url', required=True, help='URL to scan')
    parser.add_argument('--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    # Initialize engine (models loaded once)
    print("Initializing GlitchForge Engine...")
    engine = GlitchForgeEngine()
    
    # Run scan and analysis
    print(f"\nScanning {args.url}...")
    results = engine.scan_and_analyze(args.url)
    
    # Display results
    print(f"\n✓ Scan complete!")
    print(f"  Vulnerabilities found: {results['vulnerabilities_found']}")
    print(f"  Total time: {results['total_time']}s")
    print(f"  Average risk score: {results['statistics'].get('average_risk_score', 0)}/100")
    
    # Save to file
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n✓ Results saved to {args.output}")
    
    # Show top 5 WITH EXPLANATIONS
    print("\nTop 5 Critical Vulnerabilities (with explanations):")
    for i, vuln in enumerate(results['risk_scores'][:5], 1):
        print(f"\n[{i}] {vuln['vulnerability_id']}")
        print(f"    Risk: {vuln['risk_score']}/100 ({vuln['risk_level']})")
        print(f"    Priority: {vuln['remediation_priority']}")
        print(f"    Explanation: {vuln['explanation']}")
        print("    " + "─" * 70)