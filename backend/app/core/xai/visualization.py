"""
GlitchForge Visualization - Stage 3
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

Creates plots for SHAP and LIME explanations
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import shap
from typing import List, Dict, Union, Optional, Tuple
from pathlib import Path
import pickle
import logging
import matplotlib
matplotlib.use('Agg')

# Import config
from app.config import Config

logger = logging.getLogger(__name__)

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.dpi'] = 100
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10


class ExplanationVisualizer:
    """
    Create visualizations for Stage 2 explanations
    """
    
    def __init__(self, feature_names: List[str]):
        """
        Initialize with actual feature names
        """
        self.feature_names = feature_names
        logger.info(f"✓ Initialized visualizer for {len(feature_names)} features")
    
    # ============================================
    # SHAP VISUALIZATIONS
    # ============================================
    
    def plot_shap_waterfall(self,
                            shap_values: np.ndarray,
                            X_sample: np.ndarray,
                            base_value: float,
                            max_display: int = 10,
                            title: str = "SHAP Waterfall Plot",
                            save_path: Optional[Union[str, Path]] = None):
        """
        Create waterfall plot for vulnerability
        """
        # Handle multi-class/3D array
        if isinstance(shap_values, list):
            shap_values_sample = shap_values[1][0] # Positive class, first sample
        elif shap_values.ndim == 3:
            if shap_values.shape[2] == 1:
                shap_values_sample = shap_values[0, :, 0] # 1st sample, all features, class 0
            else:
                shap_values_sample = shap_values[0, :, 1] # 1st sample, all features, class 1
        elif len(shap_values.shape) > 1:
            shap_values_sample = shap_values[0] # Already 1D for a single sample
        else:
            shap_values_sample = shap_values # Already 1D

        if len(X_sample.shape) > 1:
            X_sample = X_sample[0]
        
        # Create explanation
        explanation = shap.Explanation(
            values=shap_values_sample,
            base_values=base_value,
            data=X_sample,
            feature_names=self.feature_names
        )
        
        # Plot
        plt.figure(figsize=(10, 6))
        shap.plots.waterfall(explanation, max_display=max_display, show=False)
        plt.title(title, fontsize=14, fontweight='bold')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            logger.info(f"✓ Saved: {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_shap_summary(self,
                          shap_values: np.ndarray,
                          X_test: np.ndarray,
                          plot_type: str = "dot",
                          max_display: int = 20,
                          title: str = "SHAP Summary Plot",
                          save_path: Optional[Union[str, Path]] = None):
        """
        Create summary plot for test set
        """
        # Handle multi-class/3D array
        if isinstance(shap_values, list):
            shap_values = shap_values[1] # List from KernelExplainer
        elif shap_values.ndim == 3:
            if shap_values.shape[2] == 1:
                shap_values = shap_values[:, :, 0] # NN with 1 output
            else:
                shap_values = shap_values[:, :, 1] # NN with 2 outputs
        
        plt.figure(figsize=(10, 8))
        shap.summary_plot(
            shap_values,
            X_test,
            feature_names=self.feature_names,
            plot_type=plot_type,
            max_display=max_display,
            show=False
        )
        
        # Adjust plot for title
        plt.title(title, fontsize=14, fontweight='bold', pad=20)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            logger.info(f"✓ Saved: {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    def plot_shap_bar(self,
                      shap_values: np.ndarray,
                      top_k: int = 15,
                      title: str = "SHAP Feature Importance",
                      save_path: Optional[Union[str, Path]] = None):
        """
        Create bar plot of feature importance
        """
        # Handle multi-class/3D array
        if isinstance(shap_values, list):
            shap_values = shap_values[1] # List from KernelExplainer
        elif shap_values.ndim == 3:
            if shap_values.shape[2] == 1:
                shap_values = shap_values[:, :, 0] # NN with 1 output
            else:
                shap_values = shap_values[:, :, 1] # NN with 2 outputs
        
        # Calculate mean absolute SHAP
        mean_abs_shap = np.abs(shap_values).mean(axis=0)
        
        # Get top-k
        top_k = min(top_k, len(self.feature_names)) # Ensure top_k is not > num features
        top_indices = np.argsort(mean_abs_shap)[-top_k:]
        
        # Cast numpy int 'i' to a standard python 'int' for list indexing
        top_features = [self.feature_names[int(i)] for i in top_indices]
        
        top_values = mean_abs_shap[top_indices]
        
        # Plot
        fig, ax = plt.subplots(figsize=(10, max(6, top_k * 0.4))) # Adjust height
        y_pos = np.arange(len(top_features))
        
        bars = ax.barh(y_pos, top_values, color='steelblue', alpha=0.8)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(top_features)
        ax.set_xlabel('Mean |SHAP value|', fontsize=12)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            logger.info(f"✓ Saved: {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    # ============================================
    # LIME VISUALIZATIONS
    # ============================================
    
    def plot_lime_explanation(self,
                              lime_exp_dict: Dict,
                              title: str = "LIME Explanation",
                              save_path: Optional[Union[str, Path]] = None):
        """
        Create bar plot for LIME explanation
        """
        if not lime_exp_dict['features']:
            logger.warning(f"Skipping LIME plot '{title}', no features to show.")
            return

        features = lime_exp_dict['features'][:10]  # Top 10
        weights = lime_exp_dict['weights'][:10]
        
        # Sort by absolute weight for plotting
        sorted_indices = np.argsort(np.abs(weights))
        features = np.array(features)[sorted_indices]
        weights = np.array(weights)[sorted_indices]

        # Create plot
        fig, ax = plt.subplots(figsize=(10, 6))
        
        colors = ['green' if w > 0 else 'red' for w in weights]
        y_pos = np.arange(len(features))
        
        ax.barh(y_pos, weights, color=colors, alpha=0.7)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(features)
        ax.set_xlabel('Feature Weight', fontsize=12)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.axvline(x=0, color='black', linestyle='-', linewidth=0.5)
        ax.grid(axis='x', alpha=0.3)
        
        # Add R² score
        ax.text(0.02, 0.98, f"Local R² = {lime_exp_dict['score']:.3f}",
                transform=ax.transAxes, verticalalignment='top',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            logger.info(f"✓ Saved: {save_path}")
        else:
            plt.show()
        
        plt.close()
    
    # ============================================
    # COMPARISON PLOTS
    # ============================================
    
    def plot_shap_vs_lime_importance(self,
                                     shap_importance: pd.DataFrame,
                                     lime_importance: pd.DataFrame,
                                     top_k: int = 15,
                                     title: str = "SHAP vs LIME Feature Importance",
                                     save_path: Optional[Union[str, Path]] = None):
        """
        Compare SHAP vs LIME feature importance
        """
        # Normalize importance
        shap_norm_col = 'importance_normalized'
        lime_norm_col = 'mean_abs_weight' # LIME weights are not inherently normalized, so we use mean_abs_weight
        
        if shap_importance['importance'].sum() > 0:
            shap_importance['norm_imp'] = shap_importance['importance'] / shap_importance['importance'].sum()
        else:
            shap_importance['norm_imp'] = 0
            
        if lime_importance['mean_abs_weight'].sum() > 0:
            lime_importance['norm_imp'] = lime_importance['mean_abs_weight'] / lime_importance['mean_abs_weight'].sum()
        else:
             lime_importance['norm_imp'] = 0
        
        # Get top k from each
        shap_top = shap_importance.nlargest(top_k, 'norm_imp')
        lime_top = lime_importance.nlargest(top_k, 'norm_imp')
        
        # Combine
        all_features = set(shap_top['feature'].tolist() + lime_top['feature'].tolist())
        
        comparison_data = []
        for feat in all_features:
            shap_imp = shap_top[shap_top['feature'] == feat]['norm_imp'].values
            shap_imp = shap_imp[0] if len(shap_imp) > 0 else 0
            
            lime_imp = lime_top[lime_top['feature'] == feat]['norm_imp'].values
            lime_imp = lime_imp[0] if len(lime_imp) > 0 else 0
            
            comparison_data.append({
                'feature': feat,
                'shap': shap_imp,
                'lime': lime_imp
            })
        
        df = pd.DataFrame(comparison_data)
        df['total'] = df['shap'] + df['lime']
        df = df.sort_values('total', ascending=True).head(top_k) # Ascending for barh
        
        # Plot
        fig, ax = plt.subplots(figsize=(12, max(8, len(df) * 0.4)))
        
        x = np.arange(len(df))
        width = 0.35
        
        ax.barh(x - width/2, df['shap'], width, label='SHAP', color='steelblue', alpha=0.8)
        ax.barh(x + width/2, df['lime'], width, label='LIME', color='coral', alpha=0.8)
        
        ax.set_yticks(x)
        ax.set_yticklabels(df['feature'])
        ax.set_xlabel('Normalized Importance', fontsize=12)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.legend()
        ax.grid(axis='x', alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            logger.info(f"✓ Saved: {save_path}")
        else:
            plt.show()
        
        plt.close()


# ============================================
# CREATE ALL PLOTS FOR STAGE 2 RESULTS
# ============================================

def create_all_visualizations():
    """
    Create all plots for Stage 2 explanation results
    """
    print("="*70)
    print("Creating Visualizations for Stage 2 Results")
    print("="*70)
    
    # Load feature names
    print("\n1. Loading feature names...")
    feature_names_path = Config.PROCESSED_DATA_DIR / "feature_names.txt"
    if not feature_names_path.exists():
        print(f"❌ Feature names not found at {feature_names_path}")
        return
    with open(feature_names_path, 'r') as f:
        feature_names = [line.strip() for line in f if line.strip()]
    print(f"✓ Loaded {len(feature_names)} features")
    
    # Initialize visualizer
    visualizer = ExplanationVisualizer(feature_names)
    
    # Create output directory
    plots_dir = Config.PLOTS_DIR / "shap"
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # Load SHAP results
    print("\n2. Loading SHAP results...")
    shap_path = Config.EXPLANATIONS_DIR / "shap" / "shap_values_rf.npy"
    
    if not shap_path.exists():
        print(f"❌ SHAP results not found. Run SHAP analysis first!")
        return
    
    shap_values = np.load(shap_path, allow_pickle=True) # Add allow_pickle
    print(f"✓ SHAP values: {shap_values.shape}")
    
    # Load test data
    X_test_df = pd.read_csv(Config.X_TEST_PATH)
    X_test = X_test_df.values
    print(f"✓ Test data: {X_test.shape}")
    
    # Load model for base value
    print("\n3. Loading model...")
    if not Config.RF_MODEL_PATH.exists():
        print(f"❌ RF Model not found at {Config.RF_MODEL_PATH}")
        return
    with open(Config.RF_MODEL_PATH, 'rb') as f:
        rf_model = pickle.load(f)
    
    try:
        explainer = shap.TreeExplainer(rf_model)
        base_value = explainer.expected_value[1] if isinstance(explainer.expected_value, (list, np.ndarray)) else explainer.expected_value
    except Exception as e:
        logger.warning(f"Could not get exact base_value from TreeExplainer ({e}). Falling back.")
        X_train = pd.read_csv(Config.X_TRAIN_PATH).values
        base_value = rf_model.predict_proba(X_train)[:, 1].mean()

    
    # Create SHAP waterfall plots
    print("\n4. Creating SHAP waterfall plots...")
    for i in [0, 1, 2, 5, 10]:  # 5 examples
        if i < len(X_test):
            save_path = plots_dir / f"waterfall_case_{i+1}.png"
            
            # Handle shap_values format
            if isinstance(shap_values, list):
                sv_sample = shap_values[1][i:i+1] # Positive class
            elif shap_values.ndim == 3:
                sv_sample = shap_values[i:i+1, :, 1] # Positive class
            else:
                sv_sample = shap_values[i:i+1] # 2D array
            
            visualizer.plot_shap_waterfall(
                sv_sample, # Pass only the sample
                X_test[i:i+1],
                base_value,
                title=f"SHAP Explanation - Vulnerability {i+1}",
                save_path=save_path
            )
    
    # Create SHAP summary plot
    print("\n5. Creating SHAP summary plot...")
    save_path = plots_dir / "summary_plot.png"
    visualizer.plot_shap_summary(
        shap_values,
        X_test_df, # Pass dataframe for summary plot
        plot_type="dot",
        title="SHAP Feature Importance Summary",
        save_path=save_path
    )
    
    # Create SHAP bar plot
    print("\n6. Creating SHAP bar plot...")
    save_path = plots_dir / "importance_bar.png"
    visualizer.plot_shap_bar(
        shap_values,
        top_k=15,
        title="Top 15 Features by SHAP Importance",
        save_path=save_path
    )
    
    print("\n" + "="*70)
    print("✓ All visualizations created!")
    print("="*70)
    print(f"\nPlots saved to: {plots_dir}")
    print("\nCreated files:")
    print("   - waterfall_case_1.png (and others)")
    print("   - summary_plot.png")
    print("   - importance_bar.png")


if __name__ == "__main__":
    """
    Create all plots for Stage 2 results
    """
    create_all_visualizations()