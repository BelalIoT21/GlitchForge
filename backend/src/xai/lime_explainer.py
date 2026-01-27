"""
GlitchForge LIME Explainer - Stage 3
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

Uses Stage 2 models and data
"""

import numpy as np
import pandas as pd
import lime
import lime.lime_tabular
import time
import pickle
from typing import Union, List, Tuple, Optional, Dict
from pathlib import Path
import logging

# Import config
from ..utils.config import Config

logger = logging.getLogger(__name__)


class LIMEExplainer:
    """
    Production LIME Explainer using Stage 2 trained models
    """
    
    def __init__(self,
                 model,
                 feature_names: List[str],
                 class_names: List[str] = None,
                 mode: str = 'classification'):
        """
        Initialize LIME explainer
        
        Args:
            model: trained model from Stage 2 (RF or NN)
            feature_names: feature names list
            class_names: Class labels (default: ['Low Risk', 'High Risk'])
            mode: 'classification' or 'regression'
        """
        self.model = model
        self.feature_names = feature_names
        self.class_names = class_names or ['Low Risk', 'High Risk']
        self.mode = mode
        self.explainer = None
        
        # Create a standardized predict_fn on initialization
        self.predict_fn = self._get_predict_fn()
        
        logger.info(f"✓ Initialized LIME explainer ({mode})")
        logger.info(f"   Features: {len(self.feature_names)}")

    def _get_predict_fn(self):
        """
        Returns a standardized prediction function that LIME expects,
        handling DataFrame conversion for sklearn models.
        """
        if 'Sequential' in type(self.model).__name__:
            # Keras/NN model: expects numpy, returns numpy
            def nn_predict_fn(X_numpy):
                preds = self.model(X_numpy, training=False).numpy()
                if preds.shape[1] == 1:
                    return np.hstack([1-preds, preds]) # Convert (N, 1) to (N, 2)
                return preds
            return nn_predict_fn
        
        elif hasattr(self.model, 'predict_proba'):
            # Sklearn model: expects DataFrame, returns numpy
            def sklearn_predict_fn(X_numpy):
                # Convert NumPy array from LIME back to a DataFrame
                X_df = pd.DataFrame(X_numpy, columns=self.feature_names)
                return self.model.predict_proba(X_df)
            return sklearn_predict_fn
        
        else:
            raise TypeError(f"Model type {type(self.model)} not supported for LIME")

    
    def create_explainer(self,
                         X_train: np.ndarray,
                         discretize_continuous: bool = False) -> lime.lime_tabular.LimeTabularExplainer:
        """
        Create LIME explainer using training data
        
        Args:
            X_train: training data from Stage 2
            discretize_continuous: Whether to discretize continuous features
        """
        logger.info("Creating LIME explainer...")
        logger.info(f"   Training data: {X_train.shape}")
        
        start_time = time.time()
        
        if self.mode == 'classification':
            self.explainer = lime.lime_tabular.LimeTabularExplainer(
                training_data=X_train,
                feature_names=self.feature_names,
                class_names=self.class_names,
                mode='classification',
                discretize_continuous=discretize_continuous,
                random_state=42
            )
        else:
            self.explainer = lime.lime_tabular.LimeTabularExplainer(
                training_data=X_train,
                feature_names=self.feature_names,
                mode='regression',
                discretize_continuous=discretize_continuous,
                random_state=42
            )
        
        elapsed = time.time() - start_time
        logger.info(f"✓ LIME explainer created in {elapsed:.2f} seconds")
        
        return self.explainer
    
    def explain_single(self,
                         X_sample: np.ndarray,
                         num_features: int = 10,
                         num_samples: int = 1000) -> lime.lime_tabular.explanation:
        """
        Explain a single vulnerability from test set
        """
        if self.explainer is None:
            raise ValueError("Explainer not created. Call create_explainer() first.")
        
        # Ensure 1D
        if len(X_sample.shape) > 1:
            X_sample = X_sample.flatten()
        
        start_time = time.time()
        
        # Generate explanation
        explanation = self.explainer.explain_instance(
            data_row=X_sample,
            predict_fn=self.predict_fn, # Use the class attribute
            num_features=num_features,
            num_samples=num_samples
        )
        
        elapsed = time.time() - start_time
        
        return explanation
    
    def explain_batch(self,
                        X_test: np.ndarray,
                        num_features: int = 10,
                        num_samples: int = 1000,
                        max_samples: int = None) -> Tuple[List[lime.lime_tabular.explanation], float]:
        """
        Explain batch of vulnerabilities test set
        """
        if self.explainer is None:
            raise ValueError("Explainer not created. Call create_explainer() first.")
        
        # Limit number of samples if specified
        if max_samples:
            X_test = X_test[:max_samples]
        
        if X_test.shape[0] == 0:
            logger.warning("LIME explain_batch received 0 samples. Skipping.")
            return [], 0.0

        logger.info(f"Generating LIME explanations for {X_test.shape[0]} vulnerabilities...")
        start_time = time.time()
        
        explanations = []
        for i, sample in enumerate(X_test):
            if (i + 1) % 10 == 0:
                logger.info(f"   Progress: {i + 1}/{X_test.shape[0]}")
            
            explanation = self.explain_single(sample, num_features, num_samples)
            explanations.append(explanation)
        
        elapsed = time.time() - start_time
        
        # Avoid division by zero
        if X_test.shape[0] > 0:
            avg_time = elapsed / X_test.shape[0]
            logger.info(f"✓ Completed in {elapsed:.2f} seconds")
            logger.info(f"   Average: {avg_time:.4f} seconds per vulnerability")
        else:
            logger.info(f"✓ Completed in {elapsed:.2f} seconds (0 samples)")
        
        return explanations, elapsed
    
    def get_explanation_as_dict(self, explanation: lime.lime_tabular.explanation) -> Dict:
        """
        Convert LIME explanation to dictionary
        """
        
        feature_map_list = []
        if self.mode == 'classification':
            # as_map() returns a dict of {class_label: [(feature_index, weight), ...]}
            # We want the map for the positive class (index 1)
            all_maps = explanation.as_map()
            if 1 in all_maps:
                feature_map_list = all_maps[1]
            elif all_maps:
                # Fallback if only one class is present (e.g., NN outputting 1 node)
                feature_map_list = list(all_maps.values())[0]
            else:
                logger.warning("LIME as_map() returned an empty dictionary.")
        else:
            # For regression, as_map() just returns the list
            feature_map_list = explanation.as_map()

        # Extract features and weights
        features = []
        weights = []

        # Sort by absolute weight value for consistency
        sorted_feature_map = sorted(feature_map_list, key=lambda item: abs(item[1]), reverse=True)

        for feature_index, weight in sorted_feature_map:
            try:
                # Use the index to get the name from our trusted list
                feature_name = self.feature_names[feature_index]
                features.append(feature_name)
                weights.append(weight)
            except IndexError:
                logger.warning(f"LIME returned feature index {feature_index} which is out of bounds for feature_names list (len {len(self.feature_names)}). Skipping.")

        return {
            'features': features,
            'weights': weights,
            'intercept': (
                explanation.intercept[1] # Access the intercept for the positive class
                if self.mode == 'classification'
                else explanation.intercept
            ),
            'score': explanation.score,
            'local_pred': (
                # local_pred is an array with one value, access it at index 0
                explanation.local_pred[0]
                if self.mode == 'classification'
                else explanation.local_pred
            ),
        }
    
    def get_feature_importance(self, explanations: List[lime.lime_tabular.explanation]) -> pd.DataFrame:
        """
        Calculate global feature importance from LIME explanations
        """
        # Aggregate feature weights
        feature_weights = {fname: [] for fname in self.feature_names}
        
        for explanation in explanations:
            exp_dict = self.get_explanation_as_dict(explanation)
            weights_map = dict(zip(exp_dict['features'], exp_dict['weights']))
            
            # Map weights to the features that were used
            for fname, fweight in weights_map.items():
                if fname in feature_weights:
                    feature_weights[fname].append(fweight)
            
            # Add 0 for features not used in this explanation
            unused_features = set(self.feature_names) - set(weights_map.keys())
            for fname in unused_features:
                 feature_weights[fname].append(0.0)

        
        # Calculate statistics
        importance_data = []
        for fname in self.feature_names:
            weights = np.array(feature_weights[fname])
            if len(weights) == 0: # Handle case where feature was never seen
                weights = np.array([0.0])
                
            importance_data.append({
                'feature': fname,
                'mean_abs_weight': np.abs(weights).mean(),
                'mean_weight': weights.mean(),
                'std_weight': weights.std(),
                'times_used': np.sum(weights != 0)
            })
        
        importance_df = pd.DataFrame(importance_data)
        importance_df = importance_df.sort_values('mean_abs_weight', ascending=False)
        importance_df['rank'] = range(1, len(importance_df) + 1)
        
        return importance_df
    
    def measure_fidelity(self, 
                         explanations: List[lime.lime_tabular.explanation],
                         X_test: np.ndarray) -> Dict[str, float]:
        """
        Measure LIME fidelity (R² of local model)
        """
        scores = []
        local_preds = []
        global_preds = []
        
        if not explanations:
             logger.warning("No explanations to measure fidelity on.")
             return {}

        predict_fn = self.predict_fn
        
        for i, explanation in enumerate(explanations):
            scores.append(explanation.score)
            
            if self.mode == 'classification':
                # local_pred is an array with one value, access it at index 0
                local_pred = explanation.local_pred[0]
                preds = predict_fn(X_test[i:i+1]) # This now uses the wrapper
                global_pred = preds[0, 1] if preds.ndim > 1 else preds[0]
            else:
                local_pred = explanation.local_pred
                global_pred = predict_fn(X_test[i:i+1])[0]
            
            local_preds.append(local_pred)
            global_preds.append(global_pred)
        
        # Calculate metrics
        mean_r2 = np.mean(scores)
        local_preds = np.array(local_preds)
        global_preds = np.array(global_preds)
        
        # Handle potential NaN if predictions are constant
        if np.std(local_preds) == 0 or np.std(global_preds) == 0:
            prediction_agreement = 1.0 if np.allclose(local_preds, global_preds) else 0.0
        else:
            prediction_agreement = np.corrcoef(local_preds, global_preds)[0, 1]
            
        mae = np.abs(local_preds - global_preds).mean()
        
        fidelity_metrics = {
            'mean_r2_score': mean_r2,
            'prediction_correlation': prediction_agreement,
            'mean_absolute_error': mae,
            'min_r2': np.min(scores),
            'max_r2': np.max(scores)
        }
        
        logger.info(f"LIME Fidelity:")
        logger.info(f"   Mean R² score: {mean_r2:.4f}")
        logger.info(f"   Prediction correlation: {prediction_agreement:.4f}")
        logger.info(f"   Mean absolute error: {mae:.4f}")
        
        if mean_r2 > 0.9:
            logger.info(f"   ✓ Excellent fidelity!")
        elif mean_r2 > 0.8:
            logger.info(f"   ✓ Good fidelity")
        else:
            logger.warning(f"   ⚠ Consider increasing num_samples")
        
        return fidelity_metrics
    
    def save_explanations(self,
                          explanations: List[lime.lime_tabular.explanation],
                          output_path: Union[str, Path]) -> None:
        """Save LIME explanations"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        explanations_data = [self.get_explanation_as_dict(exp) for exp in explanations]
        
        with open(output_path, 'wb') as f:
            pickle.dump(explanations_data, f)
        
        logger.info(f"✓ Saved {len(explanations)} LIME explanations to {output_path}")


# ============================================
# USAGE WITH STAGE 2 DATA
# ============================================

def run_lime_on_stage2_data(model_type: str = 'random_forest'):
    """
    Run LIME on Stage 2 models and data
    """
    print("="*70)
    print(f"Running LIME on Stage 2 {model_type.upper()}")
    print("="*70)
    
    # 1. Load trained model
    print("\n1. Loading trained model from Stage 2...")
    if model_type == 'random_forest':
        model_path = Config.RF_MODEL_PATH
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
    else:
        from tensorflow import keras
        model_path = Config.NN_MODEL_PATH
        model = keras.models.load_model(model_path)
    
    print(f"✓ Loaded model: {model_path}")
    
    # 2. Load data
    print("\n2. Loading Stage 2 data...")
    X_train_df = pd.read_csv(Config.X_TRAIN_PATH)
    X_train = X_train_df.values
    X_test = pd.read_csv(Config.X_TEST_PATH).values
    y_test = pd.read_csv(Config.Y_TEST_PATH).values.ravel()
    
    print(f"✓ Training data: {X_train.shape}")
    print(f"✓ Test data: {X_test.shape}")
    
    # 3. Load feature names
    print("\n3. Loading feature names...")
    feature_names = list(X_train_df.columns)
    print(f"✓ Loaded {len(feature_names)} features")
    
    # 4. Create LIME explainer
    print("\n4. Creating LIME explainer...")
    explainer = LIMEExplainer(
        model=model,
        feature_names=feature_names,
        class_names=['Low Risk', 'High Risk'],
        mode='classification'
    )
    
    explainer.create_explainer(X_train)
    
    # 5. Explain single vulnerability
    print("\n5. Explaining single vulnerability...")
    if len(X_test) > 0:
        explanation = explainer.explain_single(X_test[0], num_features=10)
        exp_dict = explainer.get_explanation_as_dict(explanation)
        print(f"   Local model R² score: {exp_dict['score']:.4f}")
        print(f"   True label: {y_test[0]}")
    else:
        print("   Skipping single explanation (no test data).")
    
    # 6. Explain batch
    print("\n6. Explaining batch...")
    X_test_subset = X_test[:100]  # LIME is fast, can do 100
    explanations, comp_time = explainer.explain_batch(
        X_test_subset,
        num_features=10,
        num_samples=1000
    )
    
    # 7. Feature importance
    print("\n7. Calculating feature importance...")
    importance_df = explainer.get_feature_importance(explanations)
    print("\nTop 10 Most Important Features:")
    print(importance_df.head(10).to_string(index=False))
    
    # 8. Measure fidelity
    print("\n8. Measuring fidelity...")
    fidelity = explainer.measure_fidelity(explanations, X_test_subset)
    
    # 9. Save results
    print("\n9. Saving LIME explanations...")
    output_dir = Config.EXPLANATIONS_DIR / "lime"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_path = output_dir / f"lime_explanations_{model_type}.pkl"
    explainer.save_explanations(explanations, output_path)
    
    # Save feature importance
    importance_path = Config.TABLES_DIR / f"lime_importance_{model_type}.csv"
    importance_path.parent.mkdir(parents=True, exist_ok=True)
    importance_df.to_csv(importance_path, index=False)
    print(f"✓ Saved feature importance: {importance_path}")
    
    # Save metrics
    metrics_path = Config.TABLES_DIR / f"lime_metrics_{model_type}.csv"
    metrics_df = pd.DataFrame([{
        'model': model_type,
        'n_samples': len(X_test_subset),
        'mean_r2_score': fidelity.get('mean_r2_score', 0),
        'prediction_correlation': fidelity.get('prediction_correlation', 0),
        'mean_absolute_error': fidelity.get('mean_absolute_error', 0),
        'computation_time_total': comp_time,
        'computation_time_per_sample': comp_time / len(X_test_subset) if len(X_test_subset) > 0 else 0
    }])
    metrics_df.to_csv(metrics_path, index=False)
    print(f"✓ Saved metrics: {metrics_path}")
    
    print("\n" + "="*70)
    print(f"✓ LIME analysis complete for {model_type}!")
    print("="*70)
    
    return explainer, explanations, importance_df


if __name__ == "__main__":
    """
    Run this to analyze Stage 2 models with LIME
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Run LIME on Stage 2 models')
    parser.add_argument('--model', type=str, default='random_forest',
                        choices=['random_forest', 'neural_network'],
                        help='Model type to explain')
    
    args = parser.parse_args()
    
    run_lime_on_stage2_data(model_type=args.model)