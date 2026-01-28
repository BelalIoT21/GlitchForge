# app/core/prioritization/engine.py

import numpy as np
from typing import Dict, Tuple, List
from app.utils.logger import get_logger
from .data_models import RiskScore, RiskLevel, RemediationPriority

class RiskPrioritizationEngine:
    """
    Advanced risk prioritization engine combining multiple data sources
    """
    
    def __init__(self, config: Dict = None):
        """Initialize risk prioritization engine and set parameters."""
        self.config = config or {}
        self.logger = get_logger(__name__)
        
        # Risk scoring weights
        self.weights = {
            'cvss': 0.35,
            'exploitability': 0.25,
            'impact': 0.20,
            'ml_prediction': 0.15,
            'temporal': 0.05
        }
        
        # Thresholds (0-100 scale)
        self.thresholds = {
            'critical': 85.0,
            'high': 70.0,
            'medium': 50.0,
            'low': 30.0
        }
        
        # Adjustment multipliers
        self.multipliers = {
            'has_exploit': 1.3,
            'recent_vuln': 1.2,       # < 180 days
            'widespread': 1.15,        # > 10 products
            'high_exploitability': 1.25,  # exploitability >= 3.0
            'critical_impact': 1.2      # impact >= 8.0
        }
        
        self.logger.info("Risk Prioritization Engine initialized")

    def calculate_base_risk_score(
        self,
        cvss_base: float,
        exploitability: float,
        impact: float
    ) -> float:
        """Calculate base risk score from CVSS metrics (0-100)."""
        # Normalize scores
        cvss_normalized = (cvss_base / 10.0) * 100
        exploitability_normalized = (exploitability / 4.0) * 100
        impact_normalized = (impact / 10.0) * 100
        
        # Weighted combination
        base_score = (
            cvss_normalized * self.weights['cvss'] +
            exploitability_normalized * self.weights['exploitability'] +
            impact_normalized * self.weights['impact']
        ) / (self.weights['cvss'] + self.weights['exploitability'] + self.weights['impact'])
        
        return np.clip(base_score, 0, 100)

    def apply_ml_enhancement(
        self,
        base_score: float,
        rf_prediction: int,
        nn_prediction: int,
        rf_confidence: float,
        nn_confidence: float
    ) -> Tuple[float, float]:
        """Enhance risk score using ML predictions."""
        # Map predictions to risk multipliers: Low=0.7, Medium=1.0, High=1.3
        risk_map = {0: 0.7, 1: 1.0, 2: 1.3}
        
        rf_multiplier = risk_map.get(rf_prediction, 1.0)
        nn_multiplier = risk_map.get(nn_prediction, 1.0)
        
        avg_confidence = (rf_confidence + nn_confidence) / 2.0
        
        # Confidence weighting: Higher for agreement, lower for disagreement/low confidence
        if rf_prediction == nn_prediction:
            confidence_weight = 0.9 + (0.1 * avg_confidence)  # 0.9 to 1.0
        else:
            confidence_weight = 0.7 + (0.2 * avg_confidence)  # 0.7 to 0.9
        
        # Weighted average multiplier based on confidence
        total_confidence = rf_confidence + nn_confidence
        if total_confidence > 0:
            ml_multiplier = (
                rf_multiplier * rf_confidence + 
                nn_multiplier * nn_confidence
            ) / total_confidence
        else:
            ml_multiplier = 1.0
        
        ml_enhanced = base_score * ml_multiplier
        
        return np.clip(ml_enhanced, 0, 100), confidence_weight

    def apply_contextual_adjustments(
        self,
        score: float,
        has_exploit: bool,
        age_days: int,
        exploitability: float,
        impact: float,
        products_count: int
    ) -> Tuple[float, float, float]:
        """Apply temporal and exploit-related adjustments."""
        temporal_adj = 1.0
        exploit_adj = 1.0
        
        # Exploit availability adjustment
        if has_exploit:
            exploit_adj *= self.multipliers['has_exploit']
        
        # Temporal adjustment (recent vulnerabilities)
        if age_days < 180:
            temporal_adj *= self.multipliers['recent_vuln']
        elif age_days < 365:
            temporal_adj *= 1.1 # Moderate boost for 6 months to 1 year
        
        # High exploitability boost
        if exploitability >= 3.0:
            exploit_adj *= self.multipliers['high_exploitability']
        
        # Critical impact boost
        if impact >= 8.0:
            exploit_adj *= self.multipliers['critical_impact']
        
        # Widespread vulnerability
        if products_count > 10:
            exploit_adj *= self.multipliers['widespread']
        
        # Apply adjustments
        adjusted_score = score * temporal_adj * exploit_adj
        
        return temporal_adj, exploit_adj, np.clip(adjusted_score, 0, 100)

    def calculate_final_risk_score(
        self,
        base_score: float,
        ml_enhanced_score: float,
        confidence_weight: float
    ) -> float:
        """Calculate final score combining base and ML-enhanced scores."""
        # Weighted combination: 70% from enhanced score, 30% from base score
        final_score = (
            ml_enhanced_score * 0.7 + 
            base_score * 0.3
        ) * confidence_weight 
        
        return np.clip(final_score, 0, 100)

    def assign_risk_level(self, score: float) -> RiskLevel:
        """Assign risk level based on score."""
        if score >= self.thresholds['critical']:
            return RiskLevel.CRITICAL
        elif score >= self.thresholds['high']:
            return RiskLevel.HIGH
        elif score >= self.thresholds['medium']:
            return RiskLevel.MEDIUM
        elif score >= self.thresholds['low']:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def assign_remediation_priority(self, risk_level: RiskLevel) -> RemediationPriority:
        """Assign remediation priority based on risk level."""
        priority_map = {
            RiskLevel.CRITICAL: RemediationPriority.IMMEDIATE,
            RiskLevel.HIGH: RemediationPriority.URGENT,
            RiskLevel.MEDIUM: RemediationPriority.SCHEDULED,
            RiskLevel.LOW: RemediationPriority.ROUTINE,
            RiskLevel.INFO: RemediationPriority.MONITOR
        }
        return priority_map[risk_level]

    def generate_explanation(
        self,
        risk_score: RiskScore,
        feature_importance: Dict[str, float] = None
    ) -> str:
        """Generate human-readable explanation for risk score."""
        parts = []
        
        # Risk level
        parts.append(f"Risk Level: {risk_score.risk_level.value} ({risk_score.final_risk_score:.1f}/100)")
        
        # Primary factors
        factors = []
        
        # CVSS
        if risk_score.cvss_base_score >= 9.0:
            factors.append(f"Critical CVSS score ({risk_score.cvss_base_score:.1f})")
        elif risk_score.cvss_base_score >= 7.0:
            factors.append(f"High CVSS score ({risk_score.cvss_base_score:.1f})")
        
        # Exploit/Exploitability/Impact
        if risk_score.has_exploit:
            factors.append("Public exploit available")
        if risk_score.cvss_exploitability_score >= 3.0:
            factors.append(f"High exploitability ({risk_score.cvss_exploitability_score:.1f})")
        if risk_score.cvss_impact_score >= 8.0:
            factors.append(f"Critical impact ({risk_score.cvss_impact_score:.1f})")
        
        # Recency/Widespread
        if risk_score.age_days < 180:
            factors.append(f"Recent disclosure ({risk_score.age_days} days)")
        if risk_score.affected_products_count > 10:
            factors.append(f"Widespread ({risk_score.affected_products_count} products)")
        
        if factors:
            parts.append("Key Factors: " + ", ".join(factors))
        
        # Model agreement
        avg_conf = (risk_score.rf_confidence + risk_score.nn_confidence) / 2
        risk_names = ['Low', 'Medium', 'High']
        
        if risk_score.model_agreement:
            parts.append(f"Both ML models agree: {risk_names[risk_score.rf_prediction]} risk (Conf: {avg_conf:.0%})")
        else:
            rf_name = risk_names[risk_score.rf_prediction]
            nn_name = risk_names[risk_score.nn_prediction]
            parts.append(f"Models disagree: RF={rf_name}, NN={nn_name} (Conf: {avg_conf:.0%})")
        
        # Remediation
        parts.append(f"Action: {risk_score.remediation_priority.value}")
        
        return " | ".join(parts)
    
    def prioritize_vulnerability(
        self,
        vuln_id: str,
        cvss_base: float,
        cvss_exploitability: float,
        cvss_impact: float,
        rf_prediction: int,
        rf_confidence: float,
        nn_prediction: int,
        nn_confidence: float,
        has_exploit: bool,
        age_days: int,
        products_count: int,
        feature_importance: Dict[str, float] = None
    ) -> RiskScore:
        """Calculate comprehensive risk score for a vulnerability."""
        
        # Step 1: Calculate base risk score
        base_score = self.calculate_base_risk_score(
            cvss_base, cvss_exploitability, cvss_impact
        )
        
        # Step 2: Apply ML enhancement
        ml_enhanced, confidence_weight = self.apply_ml_enhancement(
            base_score, rf_prediction, nn_prediction,
            rf_confidence, nn_confidence
        )
        
        # Step 3: Apply contextual adjustments
        temporal_adj, exploit_adj, adjusted_score = self.apply_contextual_adjustments(
            ml_enhanced, has_exploit, age_days,
            cvss_exploitability, cvss_impact, products_count
        )
        
        # Step 4: Calculate final score
        final_score = self.calculate_final_risk_score(
            base_score, adjusted_score, confidence_weight
        )
        
        # Step 5: Assign risk level and priority
        risk_level = self.assign_risk_level(final_score)
        remediation_priority = self.assign_remediation_priority(risk_level)
        
        # Step 6: Create RiskScore object
        risk_score = RiskScore(
            vulnerability_id=vuln_id,
            cvss_base_score=cvss_base,
            cvss_exploitability_score=cvss_exploitability,
            cvss_impact_score=cvss_impact,
            rf_prediction=rf_prediction,
            rf_confidence=rf_confidence,
            nn_prediction=nn_prediction,
            nn_confidence=nn_confidence,
            model_agreement=(rf_prediction == nn_prediction),
            has_exploit=has_exploit,
            age_days=age_days,
            affected_products_count=products_count,
            base_risk_score=base_score,
            ml_enhanced_score=adjusted_score,
            temporal_adjustment=temporal_adj,
            exploit_adjustment=exploit_adj,
            confidence_weight=confidence_weight,
            final_risk_score=final_score,
            risk_level=risk_level,
            remediation_priority=remediation_priority,
            contributing_features=feature_importance or {}
        )
        
        # Step 7: Generate explanation
        risk_score.explanation_text = self.generate_explanation(risk_score, feature_importance)
        
        # Extract primary factors for quick summary
        risk_score.primary_factors = [
            f"CVSS: {cvss_base:.1f}",
            f"Exploitability: {cvss_exploitability:.1f}",
            f"Impact: {cvss_impact:.1f}"
        ]
        if has_exploit:
            risk_score.primary_factors.append("Exploit Available")
        if age_days < 180:
            risk_score.primary_factors.append(f"Recent ({age_days}d)")
        
        self.logger.debug(f"✓ {vuln_id}: {risk_level.value} ({final_score:.1f}/100)")
        
        return risk_score