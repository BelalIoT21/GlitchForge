"""
GlitchForge Metrics Utility
Performance metrics calculation for vulnerability detection and model evaluation
"""
from typing import Dict, List, Tuple
import numpy as np
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    confusion_matrix, classification_report, roc_auc_score
)


class MetricsCalculator:
    """Calculate various performance metrics for vulnerability detection"""
    
    @staticmethod
    def calculate_detection_metrics(
        y_true: List[int],
        y_pred: List[int],
        labels: List[str] = None
    ) -> Dict[str, float]:
        """
        Calculate detection performance metrics
        
        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            labels: Class labels for multi-class classification
            
        Returns:
            Dictionary of metrics
        """
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_true, y_pred, average='weighted', zero_division=0),
            'f1_score': f1_score(y_true, y_pred, average='weighted', zero_division=0)
        }
        
        # Add per-class metrics if labels provided
        if labels:
            report = classification_report(
                y_true, y_pred,
                target_names=labels,
                output_dict=True,
                zero_division=0
            )
            metrics['per_class'] = report
        
        return metrics
    
    @staticmethod
    def calculate_confusion_matrix(
        y_true: List[int],
        y_pred: List[int]
    ) -> np.ndarray:
        """
        Calculate confusion matrix
        
        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            
        Returns:
            Confusion matrix
        """
        return confusion_matrix(y_true, y_pred)
    
    @staticmethod
    def calculate_false_positive_rate(
        true_negatives: int,
        false_positives: int
    ) -> float:
        """
        Calculate False Positive Rate (FPR)
        
        Args:
            true_negatives: Number of true negatives
            false_positives: Number of false positives
            
        Returns:
            FPR value
        """
        if true_negatives + false_positives == 0:
            return 0.0
        return false_positives / (false_positives + true_negatives)
    
    @staticmethod
    def calculate_true_positive_rate(
        true_positives: int,
        false_negatives: int
    ) -> float:
        """
        Calculate True Positive Rate (TPR) / Recall / Sensitivity
        
        Args:
            true_positives: Number of true positives
            false_negatives: Number of false negatives
            
        Returns:
            TPR value
        """
        if true_positives + false_negatives == 0:
            return 0.0
        return true_positives / (true_positives + false_negatives)
    
    @staticmethod
    def calculate_risk_metrics(
        y_true: np.ndarray,
        y_pred: np.ndarray
    ) -> Dict[str, float]:
        """
        Calculate risk prediction metrics
        
        Args:
            y_true: True risk scores
            y_pred: Predicted risk scores
            
        Returns:
            Dictionary of risk metrics
        """
        from scipy.stats import spearmanr
        from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
        
        metrics = {
            'mae': mean_absolute_error(y_true, y_pred),
            'mse': mean_squared_error(y_true, y_pred),
            'rmse': np.sqrt(mean_squared_error(y_true, y_pred)),
            'r2_score': r2_score(y_true, y_pred),
            'spearman_correlation': spearmanr(y_true, y_pred)[0]
        }
        
        return metrics
    
    @staticmethod
    def calculate_explainability_metrics(
        feature_importance_1: np.ndarray,
        feature_importance_2: np.ndarray
    ) -> Dict[str, float]:
        """
        Calculate explainability quality metrics (e.g., SHAP vs LIME comparison)
        
        Args:
            feature_importance_1: Feature importance from method 1
            feature_importance_2: Feature importance from method 2
            
        Returns:
            Dictionary of explainability metrics
        """
        from scipy.stats import pearsonr
        from sklearn.metrics import jaccard_score
        
        # Normalize feature importances
        fi1_norm = feature_importance_1 / np.sum(np.abs(feature_importance_1))
        fi2_norm = feature_importance_2 / np.sum(np.abs(feature_importance_2))
        
        # Pearson correlation (consistency)
        correlation, p_value = pearsonr(fi1_norm, fi2_norm)
        
        # Top-k feature agreement (stability)
        k = min(10, len(feature_importance_1))
        top_k_1 = set(np.argsort(np.abs(feature_importance_1))[-k:])
        top_k_2 = set(np.argsort(np.abs(feature_importance_2))[-k:])
        
        # Jaccard similarity
        if len(top_k_1.union(top_k_2)) == 0:
            jaccard_sim = 0.0
        else:
            jaccard_sim = len(top_k_1.intersection(top_k_2)) / len(top_k_1.union(top_k_2))
        
        metrics = {
            'correlation': correlation,
            'p_value': p_value,
            'jaccard_similarity': jaccard_sim,
            'top_k_agreement': len(top_k_1.intersection(top_k_2)) / k
        }
        
        return metrics
    
    @staticmethod
    def format_metrics_report(metrics: Dict) -> str:
        """
        Format metrics dictionary as readable report
        
        Args:
            metrics: Dictionary of metrics
            
        Returns:
            Formatted string report
        """
        report = "\n" + "="*60 + "\n"
        report += "PERFORMANCE METRICS REPORT\n"
        report += "="*60 + "\n\n"
        
        for key, value in metrics.items():
            if isinstance(value, dict):
                report += f"\n{key.upper().replace('_', ' ')}:\n"
                report += "-"*60 + "\n"
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, (int, float)):
                        report += f"  {sub_key:.<40} {sub_value:.4f}\n"
                    else:
                        report += f"  {sub_key:.<40} {sub_value}\n"
            elif isinstance(value, (int, float)):
                report += f"{key.replace('_', ' ').title():.<40} {value:.4f}\n"
            else:
                report += f"{key.replace('_', ' ').title():.<40} {value}\n"
        
        report += "\n" + "="*60 + "\n"
        return report


if __name__ == "__main__":
    # Test metrics calculation
    y_true = [0, 1, 2, 0, 1, 2, 0, 1, 2]
    y_pred = [0, 1, 2, 0, 2, 1, 0, 1, 2]
    
    calculator = MetricsCalculator()
    metrics = calculator.calculate_detection_metrics(
        y_true, y_pred,
        labels=['SQL Injection', 'XSS', 'CSRF']
    )
    
    print(calculator.format_metrics_report(metrics))