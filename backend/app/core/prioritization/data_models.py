# src/prioritization/data_models.py

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List

class RiskLevel(Enum):
    """Risk priority levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

class RemediationPriority(Enum):
    """Remediation timeline priorities"""
    IMMEDIATE = "Immediate (0-24 hours)"
    URGENT = "Urgent (1-7 days)"
    SCHEDULED = "Scheduled (1-4 weeks)"
    ROUTINE = "Routine (1-3 months)"
    MONITOR = "Monitor Only"

@dataclass
class RiskScore:
    """Comprehensive risk score for a vulnerability"""
    vulnerability_id: str
    
    # Base metrics
    cvss_base_score: float
    cvss_exploitability_score: float
    cvss_impact_score: float
    
    # Model predictions
    rf_prediction: int  # 0=Low, 1=Medium, 2=High
    rf_confidence: float
    nn_prediction: int
    nn_confidence: float
    model_agreement: bool
    
    # Contextual factors
    has_exploit: bool
    age_days: int
    affected_products_count: int
    
    # Calculated scores
    base_risk_score: float = 0.0
    ml_enhanced_score: float = 0.0
    temporal_adjustment: float = 1.0
    exploit_adjustment: float = 1.0
    confidence_weight: float = 1.0
    final_risk_score: float = 0.0
    
    # Risk classification
    risk_level: RiskLevel = RiskLevel.MEDIUM
    remediation_priority: RemediationPriority = RemediationPriority.SCHEDULED
    
    # Ground truth (for evaluation)
    ground_truth_label: int = -1  # -1 means not set
    
    # Explanations
    primary_factors: List[str] = field(default_factory=list)
    contributing_features: Dict[str, float] = field(default_factory=dict)
    explanation_text: str = ""
    
    # Metadata
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        # Ensure all numeric types are standard floats/ints for JSON
        return {
            'vulnerability_id': self.vulnerability_id,
            'cvss_base_score': float(self.cvss_base_score),
            'cvss_exploitability_score': float(self.cvss_exploitability_score),
            'cvss_impact_score': float(self.cvss_impact_score),
            'rf_prediction': int(self.rf_prediction),
            'rf_confidence': float(self.rf_confidence),
            'nn_prediction': int(self.nn_prediction),
            'nn_confidence': float(self.nn_confidence),
            'model_agreement': bool(self.model_agreement),
            'has_exploit': bool(self.has_exploit),
            'age_days': int(self.age_days),
            'affected_products_count': int(self.affected_products_count),
            'base_risk_score': float(self.base_risk_score),
            'ml_enhanced_score': float(self.ml_enhanced_score),
            'temporal_adjustment': float(self.temporal_adjustment),
            'exploit_adjustment': float(self.exploit_adjustment),
            'confidence_weight': float(self.confidence_weight),
            'final_risk_score': float(self.final_risk_score),
            'risk_level': self.risk_level.value,
            'remediation_priority': self.remediation_priority.value,
            'primary_factors': self.primary_factors,
            'contributing_features': {k: float(v) for k, v in self.contributing_features.items()},
            'explanation_text': self.explanation_text,
            'timestamp': self.timestamp.isoformat()
        }