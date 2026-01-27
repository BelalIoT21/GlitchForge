"""
GlitchForge Quality Metrics - Stage 3
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

Measures quality of SHAP and LIME explanations
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Tuple, Union, Callable
from pathlib import Path
import pickle
import logging
from sklearn.metrics import jaccard_score
from scipy.spatial.distance import cosine
from scipy.stats import spearmanr

# Import config
from ..utils.config import Config

logger = logging.getLogger(__name__)


class ExplanationQualityMetrics:
    """
    Quality metrics for explainability results
    """
    
    def __init__(self, feature_names: List[str]):
        """
        Initialize with actual feature names from Stage 2
        """
        self.feature_names = feature_names
        logger.info(f"✓ Initialized quality metrics for {len(feature_names)} features")
    
    # ============================================
    # FIDELITY METRICS
    # ============================================
    
    def measure_fidelity_shap(self,
                             shap_values: np.ndarray,
                             predictions: np.ndarray,
                             base_value: float) -> Dict[str, float]:
        """
        Measure fidelity SHAP explanations
        """
        
        # Handle predictions first
        if predictions.ndim > 1:
            if predictions.shape[1] == 1:
                # NN model (e.g., shape (5, 1))
                predictions_flat = predictions.flatten() # Shape (5,)
            else:
                # RF model (e.g., shape (5, 2))
                predictions_flat = predictions[:, 1] # Shape (5,)
        else:
            predictions_flat = predictions # Already (5,)

        # Handle shap_values
        if isinstance(shap_values, list):
            # RF model (list of 2 arrays), select positive class
            shap_values_flat = shap_values[1] # Shape (5, 30)
        elif shap_values.ndim == 3:
            # NN model (3D array)
            if shap_values.shape[2] == 1:
                shap_values_flat = shap_values[:, :, 0] # Shape (5, 30)
            else:
                shap_values_flat = shap_values[:, :, 1] # Shape (5, 30)
        else:
            # Already a 2D array (regression or single-class output)
            shap_values_flat = shap_values # Shape (5, 30)
        
        # SHAP guarantee: sum(SHAP) + base = prediction
        shap_sums = shap_values_flat.sum(axis=1) + base_value # Shape (5,)
        
        # Now both arrays are (5,)
        errors = np.abs(predictions_flat - shap_sums)
        
        metrics = {
            'mean_absolute_error': errors.mean(),
            'max_error': errors.max(),
            'min_error': errors.min(),
            'std_error': errors.std(),
            'median_error': np.median(errors),
            'perfect_fidelity_rate': (errors < 0.001).mean()
        }
        
        logger.info(f"SHAP Fidelity: MAE={metrics['mean_absolute_error']:.8f}")
        
        return metrics
    
    def measure_fidelity_lime(self,
                             lime_explanations: List[Dict], # <-- Takes dicts
                             X_test: np.ndarray,
                             model_predict_fn: Callable) -> Dict[str, float]:
        """
        Measure fidelity of LIME explanations
        """
        scores = []
        local_preds = []
        global_preds = []
        
        if not lime_explanations:
            logger.warning("No LIME explanations to measure fidelity on.")
            return {}

        for i, exp in enumerate(lime_explanations):
        
            # 'exp' is a dictionary, so we use dictionary-style access
            scores.append(exp['score']) 
            local_preds.append(exp['local_pred'])
            
            global_pred_arr = model_predict_fn(X_test[i:i+1])
            if global_pred_arr.ndim > 1:
                global_pred = global_pred_arr[0, 1] # Get positive class prob
            else:
                global_pred = global_pred_arr[0]
            global_preds.append(global_pred)
        
        local_preds = np.array(local_preds)
        global_preds = np.array(global_preds)
        
        # Handle constant prediction case
        if np.std(local_preds) == 0 or np.std(global_preds) == 0:
            pred_corr = 1.0 if np.allclose(local_preds, global_preds) else 0.0
        else:
            pred_corr = np.corrcoef(local_preds, global_preds)[0, 1]

        metrics = {
            'mean_r2_score': np.mean(scores),
            'std_r2_score': np.std(scores),
            'min_r2_score': np.min(scores),
            'max_r2_score': np.max(scores),
            'prediction_correlation': pred_corr,
            'prediction_mae': np.abs(local_preds - global_preds).mean(),
            'high_fidelity_rate': (np.array(scores) > 0.9).mean()
        }
        
        logger.info(f"LIME Fidelity: Mean R²={metrics['mean_r2_score']:.4f}")
        
        return metrics
    
    # ============================================
    # STABILITY METRICS
    # ============================================
    
    def measure_stability(self,
                         explanations_runs: List[np.ndarray],
                         top_k: int = 10) -> Dict[str, float]:
        """
        Measure stability across multiple runs on data
        """
        if len(explanations_runs) < 2:
            logger.warning("Need at least 2 runs for stability. Returning 0s.")
            return {
                'mean_jaccard_similarity': 0, 'std_jaccard_similarity': 0,
                'mean_rank_correlation': 0, 'std_rank_correlation': 0,
                'stable_samples_rate': 0
            }

        
        n_samples = explanations_runs[0].shape[0]
        n_runs = len(explanations_runs)
        
        jaccard_scores = []
        rank_correlations = []
        
        for i in range(n_samples):
            sample_jaccards = []
            sample_correlations = []
            
            for run1 in range(n_runs):
                for run2 in range(run1 + 1, n_runs):
                    # Top-k features
                    top_k_run1 = self._get_top_k_features(explanations_runs[run1][i], top_k)
                    top_k_run2 = self._get_top_k_features(explanations_runs[run2][i], top_k)
                    
                    # Jaccard similarity
                    union_size = len(top_k_run1.union(top_k_run2))
                    if union_size == 0:
                        jaccard = 1.0 # Both sets are empty, so they are identical
                    else:
                        jaccard = len(top_k_run1.intersection(top_k_run2)) / union_size
                    sample_jaccards.append(jaccard)
                    
                    # Rank correlation
                    ranks1 = self._get_feature_ranks(explanations_runs[run1][i])
                    ranks2 = self._get_feature_ranks(explanations_runs[run2][i])
                    correlation, _ = spearmanr(ranks1, ranks2)
                    sample_correlations.append(correlation)
            
            jaccard_scores.append(np.mean(sample_jaccards))
            rank_correlations.append(np.mean(sample_correlations))
        
        metrics = {
            'mean_jaccard_similarity': np.mean(jaccard_scores),
            'std_jaccard_similarity': np.std(jaccard_scores),
            'mean_rank_correlation': np.mean(rank_correlations),
            'std_rank_correlation': np.std(rank_correlations),
            'stable_samples_rate': (np.array(jaccard_scores) > 0.8).mean()
        }
        
        logger.info(f"Stability: Jaccard={metrics['mean_jaccard_similarity']:.4f}")
        
        return metrics
    
    def _get_top_k_features(self, explanation: np.ndarray, k: int) -> set:
        """Get top-k features"""
        abs_values = np.abs(explanation)
        top_k_indices = np.argsort(abs_values)[-k:]
        return set(top_k_indices)
    
    def _get_feature_ranks(self, explanation: np.ndarray) -> np.ndarray:
        """Get feature ranks"""
        abs_values = np.abs(explanation)
        return np.argsort(np.argsort(abs_values))
    
    # ============================================
    # CONSISTENCY METRICS
    # ============================================

    def _safe_cosine_similarity(self, u, v):
        """Calculates cosine similarity, handling zero vectors."""
        uu = np.dot(u, u)
        vv = np.dot(v, v)
        uv = np.dot(u, v)
        
        norm_product = np.sqrt(uu * vv)
        
        if norm_product == 0:
            # If norm_product is 0, either u or v (or both) are zero vectors.
            # If both are zero vectors, similarity is 1 (they are identical).
            # If one is zero and the other is not, similarity is 0 (they are different).
            return 1.0 if uu == 0 and vv == 0 else 0.0
        
        # We return the similarity (1 - distance)
        return uv / norm_product

    
    def measure_consistency(self,
                          explanations: np.ndarray,
                          X_test: np.ndarray,
                          similarity_threshold: float = 0.9) -> Dict[str, float]:
        """
        Measure consistency on vulnerability data
        """
        n_samples = explanations.shape[0]
        similar_pairs = []
        
        if n_samples < 2:
            logger.warning("Need at least 2 samples for consistency. Returning 0s.")
            return {
                'n_similar_pairs': 0, 'mean_explanation_similarity': 0,
                'consistency_rate': 0
            }

        for i in range(n_samples):
            for j in range(i + 1, n_samples):
                input_sim = self._safe_cosine_similarity(X_test[i], X_test[j])
                
                if input_sim > similarity_threshold:
                    # Explanation similarity
                    exp_sim = self._safe_cosine_similarity(explanations[i], explanations[j])
                    
                    similar_pairs.append({
                        'input_similarity': input_sim,
                        'explanation_similarity': exp_sim
                    })
        
        if len(similar_pairs) == 0:
            logger.warning("No similar pairs found. Try lowering threshold.")
            return {
                'n_similar_pairs': 0,
                'mean_explanation_similarity': 0.0,
                'std_explanation_similarity': 0.0,
                'min_explanation_similarity': 0.0,
                'max_explanation_similarity': 0.0,
                'consistency_rate': 0.0
            }
        
        exp_sims = [p['explanation_similarity'] for p in similar_pairs]
        
        metrics = {
            'n_similar_pairs': len(similar_pairs),
            'mean_explanation_similarity': np.mean(exp_sims),
            'std_explanation_similarity': np.std(exp_sims),
            'min_explanation_similarity': np.min(exp_sims),
            'max_explanation_similarity': np.max(exp_sims),
            'consistency_rate': (np.array(exp_sims) > 0.7).mean()
        }
        
        logger.info(f"Consistency: {metrics['n_similar_pairs']} pairs")
        
        return metrics
    
    # ============================================
    # COMPREHENSIVE REPORT
    # ============================================
    
    def generate_quality_report(self,
                               method_name: str,
                               fidelity_metrics: Dict[str, float],
                               stability_metrics: Dict[str, float] = None,
                               consistency_metrics: Dict[str, float] = None,
                               computation_metrics: Dict[str, float] = None) -> pd.DataFrame:
        """
        Generate quality report for explanations
        """
        report_data = []
        
        # Fidelity
        for metric, value in fidelity_metrics.items():
            report_data.append({
                'method': method_name,
                'category': 'Fidelity',
                'metric': metric,
                'value': value
            })
        
        # Stability
        if stability_metrics:
            for metric, value in stability_metrics.items():
                report_data.append({
                    'method': method_name,
                    'category': 'Stability',
                    'metric': metric,
                    'value': value
                })
        
        # Consistency
        if consistency_metrics:
            for metric, value in consistency_metrics.items():
                report_data.append({
                    'method': method_name,
                    'category': 'Consistency',
                    'metric': metric,
                    'value': value
                })
        
        # Computation
        if computation_metrics:
            for metric, value in computation_metrics.items():
                report_data.append({
                    'method': method_name,
                    'category': 'Computation',
                    'metric': metric,
                    'value': value
                })
        
        report_df = pd.DataFrame(report_data)
        logger.info(f"Generated report: {len(report_data)} metrics")
        
        return report_df


# ============================================
# RUN QUALITY ANALYSIS ON STAGE 2 RESULTS
# ============================================

def analyze_stage2_quality():
    """
    Analyze quality of Stage 2 explanation results
    """
    print("="*70)
    print("Quality Metrics for Stage 2 Explanations")
    print("="*70)
    
    # Load feature names
    print("\n1. Loading feature names...")
    feature_names_path = Config.PROCESSED_DATA_DIR / "feature_names.txt"
    with open(feature_names_path, 'r') as f:
        feature_names = [line.strip() for line in f if line.strip()]
    
    print(f"✓ Loaded {len(feature_names)} features")
    
    # Initialize metrics
    quality_metrics = ExplanationQualityMetrics(feature_names)
    
    # Load SHAP results
    print("\n2. Loading SHAP results...")
    shap_rf_path = Config.EXPLANATIONS_DIR / "shap" / "shap_values_rf.npy"
    
    if not shap_rf_path.exists():
        print(f"❌ SHAP results not found at {shap_rf_path}")
        print("   Run SHAP analysis first: python stage3_xai.py")
        return
    
    # allow_pickle=True is needed if the .npy file contains a list (which it does)
    shap_values_rf = np.load(shap_rf_path, allow_pickle=True) 
    print(f"✓ Loaded SHAP values: {shap_values_rf.shape}")
    
    # Load test data
    print("\n3. Loading test data...")
    X_test = pd.read_csv(Config.X_TEST_PATH).values
    print(f"✓ Test data: {X_test.shape}")
    
    # Load model for fidelity check
    print("\n4. Loading Random Forest model...")
    with open(Config.RF_MODEL_PATH, 'rb') as f:
        rf_model = pickle.load(f)
    print(f"✓ Model loaded")
    
    # Get predictions
    predictions = rf_model.predict_proba(X_test)
    
    # Measure SHAP fidelity
    print("\n5. Measuring SHAP fidelity on data...")
    # Load SHAP metrics to get base value
    try:
        import shap
        explainer = shap.TreeExplainer(rf_model)
        base_value = explainer.expected_value[1] if isinstance(explainer.expected_value, (list, np.ndarray)) else explainer.expected_value
    except Exception as e:
        logger.warning(f"Could not get exact base_value from TreeExplainer ({e}). Falling back.")
        # Fallback: Calculate mean prediction of training data
        X_train = pd.read_csv(Config.X_TRAIN_PATH).values
        base_value = rf_model.predict_proba(X_train)[:, 1].mean()

    
    fidelity_shap = quality_metrics.measure_fidelity_shap(
        shap_values_rf,
        predictions,
        base_value
    )
    
    print(f"\nSHAP Fidelity Results:")
    print(f"   Mean Absolute Error: {fidelity_shap['mean_absolute_error']:.8f}")
    print(f"   Perfect Fidelity Rate: {fidelity_shap['perfect_fidelity_rate']:.2%}")
    
    # Measure consistency
    print("\n6. Measuring consistency on vulnerabilities...")
    
    # Standardize shap_values for consistency check
    if isinstance(shap_values_rf, list):
        shap_values_rf_cons = shap_values_rf[1]
    elif shap_values_rf.ndim == 3:
        shap_values_rf_cons = shap_values_rf[:,:,1]
    else:
        shap_values_rf_cons = shap_values_rf

    consistency_shap = quality_metrics.measure_consistency(
        shap_values_rf_cons,
        X_test,
        similarity_threshold=0.85
    )
    
    print(f"\nConsistency Results:")
    print(f"   Similar vulnerability pairs found: {consistency_shap['n_similar_pairs']}")
    print(f"   Mean explanation similarity: {consistency_shap['mean_explanation_similarity']:.4f}")
    
    # Generate report
    print("\n7. Generating comprehensive quality report...")
    report = quality_metrics.generate_quality_report(
        method_name="SHAP_RandomForest",
        fidelity_metrics=fidelity_shap,
        consistency_metrics=consistency_shap
    )
    
    # Save report
    report_path = Config.TABLES_DIR / "quality_report_shap_rf.csv"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(report_path, index=False)
    print(f"✓ Saved report: {report_path}")
    
    # Display summary
    print("\n" + "="*70)
    print("Quality Report Summary")
    print("="*70)
    print(report.to_string(index=False))
    
    print("\n" + "="*70)
    print("✓ Quality analysis complete!")
    print("="*70)
    print(f"\nReport saved to: {report_path}")
    print("\nUse this data for Chapter 4 Table 4.7: Quality Metrics Comparison")
    
    return report


if __name__ == "__main__":
    """
    Run quality analysis on Stage 2 explanation results
    """
    analyze_stage2_quality()