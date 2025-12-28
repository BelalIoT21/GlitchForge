"""
GlitchForge SHAP Explainer - Stage 3
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

Uses Stage 2 models and data
"""

import numpy as np
import pandas as pd
import pickle
import shap
import time
from typing import Union, List, Tuple, Optional
from pathlib import Path
import logging

# Import config
from app.config import Config

logger = logging.getLogger(__name__)


class SHAPExplainer:
    """
    Production SHAP Explainer using your Stage 2 trained models
    """
    
    def __init__(self, 
                 model, 
                 feature_names: List[str],
                 model_type: str = 'auto',
                 background_samples: int = 100):
        """
        Initialize SHAP explainer
        
        Args:
            model: Your trained model from Stage 2 (RF or NN)
            feature_names: Your actual feature names list
            model_type: 'random_forest', 'neural_network', or 'auto'
            background_samples: Number of background samples
        """
        self.model = model
        self.feature_names = feature_names
        self.background_samples = background_samples
        self.explainer = None
        self.background_data = None
        
        # Auto-detect model type
        if model_type == 'auto':
            self.model_type = self._detect_model_type()
        else:
            self.model_type = model_type
        
        logger.info(f"✓ Initialized SHAP explainer for {self.model_type}")
        logger.info(f"   Features: {len(self.feature_names)}")
    
    def _detect_model_type(self) -> str:
        """Detect if Random Forest or Neural Network"""
        model_class = type(self.model).__name__
        
        if 'RandomForest' in model_class or 'Tree' in model_class:
            return 'random_forest'
        elif 'Sequential' in model_class or 'Model' in model_class or 'Functional' in model_class:
            return 'neural_network'
        else:
            logger.warning(f"Unknown model type: {model_class}, defaulting to 'random_forest'")
            return 'random_forest'
    
    def create_explainer(self, X_train: np.ndarray, method: str = 'auto') -> shap.Explainer:
        """
        Create appropriate SHAP explainer
        
        Args:
            X_train: Your actual training data from Stage 2
            method: 'auto', 'tree', 'kernel', or 'deep'
        """
        logger.info(f"Creating SHAP explainer...")
        logger.info(f"   Model type: {self.model_type}")
        logger.info(f"   Training data: {X_train.shape}")
        
        start_time = time.time()
        
        # Sample background data
        if X_train.shape[0] > self.background_samples:
            indices = np.random.choice(X_train.shape[0], self.background_samples, replace=False)
            self.background_data = X_train[indices]
            logger.info(f"   Sampled {self.background_samples} background samples")
        else:
            self.background_data = X_train
            logger.info(f"   Using all {X_train.shape[0]} samples as background")
        
        # Select method
        if method == 'auto':
            method = 'tree' if self.model_type == 'random_forest' else 'kernel'
        
        # Create explainer
        if method == 'tree':
            self.explainer = shap.TreeExplainer(self.model)
            logger.info("   ✓ Created TreeExplainer (exact, fast)")
        
        elif method == 'kernel':
            if self.model_type == 'neural_network':
                # Ensure NN output is consistently logit (unscaled output) for KernelExplainer 
                def nn_logit_wrapper(X_numpy):
                    """Returns raw logits (pre-sigmoid/softmax) for SHAP."""
                    preds = self.model(X_numpy, training=False).numpy()
                    
                    if preds.ndim == 2 and preds.shape[1] == 4:
                        # Multi-class output (4 classes) is already in the correct logit format
                        return preds
                    
                    if preds.ndim == 2 and preds.shape[1] == 1:
                        # Binary Keras output: convert from probability to logit
                        preds = np.clip(preds, 1e-7, 1 - 1e-7) 
                        logits = np.log(preds / (1 - preds))
                        # Stack [-logit, logit] to match binary explainer expectation
                        return np.hstack([-logits, logits]) 
                    return preds
                
                predict_fn = nn_logit_wrapper
            else:
                predict_fn = self.model.predict_proba
                
            self.explainer = shap.KernelExplainer(predict_fn, self.background_data)
            logger.info("   ✓ Created KernelExplainer (model-agnostic, slower)")
        
        elif method == 'deep':
            self.explainer = shap.DeepExplainer(self.model, self.background_data)
            logger.info("   ✓ Created DeepExplainer (NN-specific)")
        
        elapsed = time.time() - start_time
        logger.info(f"✓ Explainer created in {elapsed:.2f} seconds")
        
        return self.explainer
    
    def explain_single(self, 
                       X_sample: np.ndarray,
                       nsamples: int = 1000) -> Tuple[np.ndarray, float, float]:
        """
        Explain a single vulnerability from your test set
        """
        if self.explainer is None:
            raise ValueError("Explainer not created. Call create_explainer() first.")
        
        # Ensure 2D
        if len(X_sample.shape) == 1:
            X_sample = X_sample.reshape(1, -1)
        
        start_time = time.time()
        
        # Get SHAP values
        if isinstance(self.explainer, shap.KernelExplainer):
            shap_values = self.explainer.shap_values(X_sample, nsamples=nsamples, show_progress=False)
        else:
            shap_values = self.explainer.shap_values(X_sample)
        
        # Get prediction (using original model probability output for check)
        if hasattr(self.model, 'predict_proba'):
            prediction = self.model.predict_proba(X_sample)[0]
        elif hasattr(self.model, 'predict'):
            prediction = self.model.predict(X_sample)[0]
        else: # Neural Network
            prediction = self.model(X_sample, training=False).numpy()[0]
        
        # Get base value
        base_value = self.explainer.expected_value
        if isinstance(base_value, (list, np.ndarray)):
            # Use Index 2 (HIGH Risk) for NN, Index 1 for RF (Binary Positive)
            if self.model_type == 'neural_network':
                # Use HIGH Risk index (2) for multi-class, or the first index if only 1 output
                base_value = base_value[2] if len(base_value) > 2 else base_value[0]
            else:
                # RF is binary, use positive class (index 1)
                base_value = base_value[1] if len(base_value) > 1 else base_value[0]
        
        elapsed = time.time() - start_time
        
        return shap_values, base_value, prediction
    
    def explain_batch(self,
                        X_test: np.ndarray,
                        nsamples: int = 1000,
                        show_progress: bool = True) -> Tuple[np.ndarray, np.ndarray, float]:
        """
        Explain batch of vulnerabilities from your test set
        """
        if self.explainer is None:
            raise ValueError("Explainer not created. Call create_explainer() first.")
        
        logger.info(f"Generating SHAP explanations for {X_test.shape[0]} vulnerabilities...")
        start_time = time.time()
        
        # Get SHAP values
        if isinstance(self.explainer, shap.KernelExplainer):
            logger.info(f"   Using KernelSHAP with {nsamples} samples (this may take a while...)")
            shap_values = self.explainer.shap_values(X_test, nsamples=nsamples, show_progress=False) 
        else:
            shap_values = self.explainer.shap_values(X_test)
        
        # Get predictions (Original model probability output)
        if hasattr(self.model, 'predict_proba'):
            predictions = self.model.predict_proba(X_test)
        elif hasattr(self.model, 'predict'):
            predictions = self.model.predict(X_test)
        else: # Neural Network
            predictions = self.model(X_test, training=False).numpy()
        
        elapsed = time.time() - start_time
        
        if X_test.shape[0] > 0:
            avg_time = elapsed / X_test.shape[0]
            logger.info(f"✓ Completed in {elapsed:.2f} seconds")
            logger.info(f"   Average: {avg_time:.4f} seconds per vulnerability")
        else:
            logger.info(f"✓ Completed in {elapsed:.2f} seconds (0 samples)")

        
        return shap_values, predictions, elapsed
    
    def get_feature_importance(self, shap_values: np.ndarray) -> pd.DataFrame:
        """
        Get feature importance from SHAP values
        """
        
        # Standardize SHAP array to 2D before calculating mean
        
        # 1. Handle list output (standard for Tree/Kernel classifiers)
        if isinstance(shap_values, list):
            if self.model_type == 'neural_network' and len(shap_values) > 2:
                # Multi-class 4-output NN: Use HIGH Risk index (2)
                shap_values = shap_values[2]
            elif len(shap_values) > 1:
                 # RF is binary, use positive class (index 1)
                 shap_values = shap_values[1] 
            else:
                 # Single output class (index 0)
                 shap_values = shap_values[0]
        
        # 2. Handle 3D array output (e.g., from DeepExplainer)
        elif shap_values.ndim == 3:
            if shap_values.shape[2] == 4 and self.model_type == 'neural_network':
                # Multi-class 4-output NN: Use HIGH Risk index (2)
                shap_values = shap_values[:, :, 2]
            elif shap_values.shape[2] > 1:
                # Binary or general multi-output: default to index 1
                shap_values = shap_values[:, :, 1]
            else:
                # Single output node
                shap_values = shap_values[:, :, 0]
        
        # At this point, shap_values should be 2D: (n_samples, n_features)
        
        # Calculate mean absolute SHAP
        feature_importance = np.abs(shap_values).mean(axis=0)
        
        # Create DataFrame
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': feature_importance,
            'importance_normalized': feature_importance / feature_importance.sum() if feature_importance.sum() > 0 else 0
        }).sort_values('importance', ascending=False)
        
        importance_df['rank'] = range(1, len(importance_df) + 1)
        
        return importance_df
    
    def measure_fidelity(self, shap_values: np.ndarray, X_test: np.ndarray) -> float:
        """
        Measure how accurate SHAP explanations are (Logit scale for NN, Probability scale for RF).
        """
        # Get predictions (Original model probability output)
        if hasattr(self.model, 'predict_proba'):
            predictions = self.model.predict_proba(X_test)
        elif hasattr(self.model, 'predict'):
            predictions = self.model.predict(X_test)
        else: # Neural Network
            predictions = self.model(X_test, training=False).numpy()
        
        # Get base value
        base_value = self.explainer.expected_value
        
        # --- 1. DETERMINE TARGET INDEX & STANDARD SHAP VALUE ARRAY ---
        
        target_index = 1
        # Check if it's the 4-class multi-output NN (Index 2 for HIGH Risk)
        is_multi_class = self.model_type == 'neural_network' and predictions.ndim == 2 and predictions.shape[1] > 2
        
        if is_multi_class:
            target_index = 2 # HIGH Risk (Index 2)
        
        # Determine shap_values_check and base_value
        if isinstance(shap_values, list):
            shap_values_check = shap_values[target_index]
            base_value = base_value[target_index]
        
        elif shap_values.ndim == 3:
            shap_values_check = shap_values[:, :, target_index]
            base_value = base_value[target_index]
        
        else: # Regressor or pre-sliced 2D array
            shap_values_check = shap_values

        # Ensure base_value is a single float
        if isinstance(base_value, (list, np.ndarray)):
             base_value = base_value.flatten()[0]

        # --- 2. PREDICTON CONVERSION (The Logit/Prob Scale Check) ---

        if self.model_type == 'neural_network':
            # Fidelity is calculated on the LOGIT scale due to the wrapper used in create_explainer.
            
            # Take the probability output corresponding to the target index/column.
            if predictions.ndim == 2 and predictions.shape[1] > 1:
                prob_preds = predictions[:, target_index]
            else:
                prob_preds = predictions.flatten() # Single column output
            
            # Convert probability to logit: log(p / (1 - p))
            prob_preds = np.clip(prob_preds, 1e-7, 1 - 1e-7)
            preds = np.log(prob_preds / (1 - prob_preds))
        
        elif predictions.ndim > 1 and predictions.shape[1] > 1:
            # RF/Tree model: uses probability scale, take positive class (index 1)
            preds = predictions[:, 1] 
        else:
            preds = predictions.flatten() 

        # --- 3. CALCULATE FIDELITY ---
        
        # SHAP guarantee: sum(SHAP) + base = prediction (on the correct scale)
        shap_sums = shap_values_check.sum(axis=1) + base_value
        errors = np.abs(preds - shap_sums)
        mean_error = errors.mean()
        
        logger.info(f"SHAP Fidelity:")
        logger.info(f"   Mean absolute error: {mean_error:.8f}")
        logger.info(f"   Max error: {errors.max():.8f}")
        
        if mean_error < 0.001:
            logger.info(f"   ✓ Excellent fidelity!")
        elif mean_error < 0.01:
            logger.info(f"   ✓ Good fidelity")
        else:
            logger.warning(f"   ⚠ Consider increasing nsamples (MAE: {mean_error:.4f})")
        
        return mean_error
    
    def save_explanations(self, shap_values: np.ndarray, output_path: Union[str, Path]) -> None:
        """Save SHAP values"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Determine the target index for the 4-class NN case
        target_index = 1
        if isinstance(shap_values, list) and len(shap_values) > 2:
            target_index = 2 # HIGH Risk
        elif shap_values.ndim == 3 and shap_values.shape[2] > 2:
            target_index = 2 # HIGH Risk
        
        if isinstance(shap_values, list):
            # For classification, save both classes
            save_path = output_path.parent / f"{output_path.stem}_multiclass.pkl"
            with open(save_path, 'wb') as f:
                pickle.dump(shap_values, f)
            logger.info(f"✓ Saved (multiclass): {save_path}")
            
            # Also save just the positive class (or target index) for easier loading
            np.save(output_path, shap_values[target_index])
            logger.info(f"✓ Saved (target class {target_index}): {output_path}")

        elif shap_values.ndim == 3:
             # Save 3D array as pkl
            save_path = output_path.parent / f"{output_path.stem}_3d_array.pkl"
            with open(save_path, 'wb') as f:
                pickle.dump(shap_values, f)
            logger.info(f"✓ Saved (3D array): {save_path}")

            if shap_values.shape[2] == 1:
                np.save(output_path, shap_values[:, :, 0]) # Index 0 for single output
            else:
                np.save(output_path, shap_values[:, :, target_index]) # Index target_index
            logger.info(f"✓ Saved (target class {target_index}): {output_path}")

        else: # Regressor (2D)
            np.save(output_path, shap_values)
            logger.info(f"✓ Saved: {output_path}")


# ============================================
# USAGE WITH YOUR STAGE 2 DATA
# ============================================

def run_shap_on_stage2_data(model_type: str = 'random_forest'):
    """
    Run SHAP on your actual Stage 2 models and data
    
    Args:
        model_type: 'random_forest' or 'neural_network'
    """
    print("="*70)
    print(f"Running SHAP on Stage 2 {model_type.upper()}")
    print("="*70)
    
    # 1. Load your trained model
    print("\n1. Loading your trained model from Stage 2...")
    if model_type == 'random_forest':
        model_path = Config.RF_MODEL_PATH
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
    else:  # neural_network
        from tensorflow import keras
        model_path = Config.NN_MODEL_PATH
        model = keras.models.load_model(model_path)
    
    print(f"✓ Loaded model: {model_path}")
    
    # 2. Load your data
    print("\n2. Loading your Stage 2 data...")
    X_train = pd.read_csv(Config.X_TRAIN_PATH).values
    X_test = pd.read_csv(Config.X_TEST_PATH).values
    y_test = pd.read_csv(Config.Y_TEST_PATH).values.ravel()
    
    print(f"✓ Training data: {X_train.shape}")
    print(f"✓ Test data: {X_test.shape}")
    
    # 3. Load feature names
    print("\n3. Loading feature names...")
    feature_names_path = Config.PROCESSED_DATA_DIR / "feature_names.txt"
    with open(feature_names_path, 'r') as f:
        feature_names = [line.strip() for line in f if line.strip()]
    
    print(f"✓ Loaded {len(feature_names)} features")
    
    # 4. Create SHAP explainer
    print("\n4. Creating SHAP explainer...")
    explainer = SHAPExplainer(
        model=model,
        feature_names=feature_names,
        model_type=model_type,
        background_samples=100
    )
    
    explainer.create_explainer(X_train)
    
    # 5. Explain single vulnerability
    print("\n5. Explaining single vulnerability...")
    if len(X_test) > 0:
        shap_values, base_value, prediction = explainer.explain_single(X_test[0])
        print(f"   Base value: {base_value:.4f}")
        print(f"   Prediction: {prediction}")
        print(f"   True label: {y_test[0]}")
    else:
        print("   Skipping single explanation (no test data).")

    
    # 6. Explain batch
    print("\n6. Explaining batch...")
    # Use subset for initial test, then expand to full test set
    X_test_subset = X_test[:100] # Start with 100, then do all
    shap_values_batch, predictions, comp_time = explainer.explain_batch(X_test_subset)
    
    # 7. Feature importance
    print("\n7. Calculating feature importance...")
    importance_df = explainer.get_feature_importance(shap_values_batch)
    print("\nTop 10 Most Important Features:")
    print(importance_df.head(10).to_string(index=False))
    
    # 8. Measure fidelity
    print("\n8. Measuring fidelity...")
    fidelity = explainer.measure_fidelity(shap_values_batch, X_test_subset)
    
    # 9. Save results
    print("\n9. Saving SHAP values...")
    output_dir = Config.EXPLANATIONS_DIR / "shap"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_path = output_dir / f"shap_values_{model_type}.npy"
    explainer.save_explanations(shap_values_batch, output_path)
    
    # Save feature importance
    importance_path = Config.TABLES_DIR / f"shap_importance_{model_type}.csv"
    importance_path.parent.mkdir(parents=True, exist_ok=True)
    importance_df.to_csv(importance_path, index=False)
    print(f"✓ Saved feature importance: {importance_path}")
    
    print("\n" + "="*70)
    print(f"✓ SHAP analysis complete for {model_type}!")
    print("="*70)
    print(f"\nNext: Run visualization.py to create plots")
    
    return explainer, shap_values_batch, importance_df


if __name__ == "__main__":
    """
    Run this to analyze your Stage 2 models with SHAP
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Run SHAP on Stage 2 models')
    parser.add_argument('--model', type=str, default='random_forest',
                        choices=['random_forest', 'neural_network'],
                        help='Model type to explain')
    
    args = parser.parse_args()
    
    run_shap_on_stage2_data(model_type=args.model)