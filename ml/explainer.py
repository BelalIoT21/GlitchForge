"""
SHAP Explainability for Vulnerability Predictions
"""

import shap
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from pathlib import Path
import pickle
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import MODELS_DIR, PROCESSED_DATA_DIR

class VulnerabilityExplainer:
    """Generate SHAP explanations for vulnerability predictions"""
    
    def __init__(self, model_path: str = 'xgboost_vulnerability_model.pkl'):
        """Load trained model"""
        
        print("\n[*] Loading trained model...")
        
        filepath = MODELS_DIR / model_path
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        
        print(f"✓ Model loaded: {len(self.feature_names)} features")
        
        self.explainer = None
        self.shap_values = None
        self.X_sample = None
    
    def load_data(self, filename: str = 'processed_nvd_data.csv', sample_size: int = 100):
        """Load processed data for explanation"""
        
        print(f"\n[*] Loading data for explanation...")
        
        filepath = PROCESSED_DATA_DIR / filename
        df = pd.read_csv(filepath)
        
        # Get features only
        exclude_cols = ['cve_id', 'risk_score', 'cwe_ids', 'description', 
                       'published_date', 'modified_date']
        
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        X = df[feature_cols]
        
        # CRITICAL FIX: Ensure all data is numeric
        print(f"[*] Converting data to numeric types...")
        
        # Convert boolean columns to int
        for col in X.columns:
            if X[col].dtype == 'bool':
                X[col] = X[col].astype(int)
            elif X[col].dtype == 'object':
                # Try to convert object columns to numeric
                try:
                    X[col] = pd.to_numeric(X[col])
                except:
                    # If conversion fails, one-hot encode
                    X = pd.get_dummies(X, columns=[col], drop_first=True)
        
        # Ensure all columns are float64
        X = X.astype('float64')
        
        print(f"✓ All features converted to numeric")
        
        # Take a sample for SHAP (SHAP can be slow on large datasets)
        if len(X) > sample_size:
            self.X_sample = X.sample(n=sample_size, random_state=42)
            print(f"✓ Loaded {sample_size} samples (sampled from {len(X)})")
        else:
            self.X_sample = X
            print(f"✓ Loaded {len(X)} samples")
        
        # Store full dataframe for reference
        self.df_full = df
        
        # Update feature names after any transformations
        self.feature_names = list(self.X_sample.columns)
        
        return self.X_sample
    
    def create_explainer(self, background_samples: int = 50):
        """Create SHAP explainer"""
        
        print(f"\n[*] Creating SHAP explainer...")
        print(f"    Using {background_samples} background samples")
        
        # Use a background dataset (subset for speed)
        if len(self.X_sample) > background_samples:
            background = shap.sample(self.X_sample, background_samples)
        else:
            background = self.X_sample
        
        # Ensure background is numpy array of float64
        background_array = background.values.astype('float64')
        
        # Create TreeExplainer (optimized for XGBoost)
        # Use data=None to avoid the NULL array issue
        self.explainer = shap.TreeExplainer(self.model)
        
        print(f"✓ SHAP explainer created")
        
        return self.explainer
    
    def calculate_shap_values(self):
        """Calculate SHAP values for the sample"""
        
        print(f"\n[*] Calculating SHAP values...")
        print(f"    This may take 30-60 seconds...")
        
        # Convert to numpy array
        X_array = self.X_sample.values.astype('float64')
        
        self.shap_values = self.explainer.shap_values(X_array)
        
        print(f"✓ SHAP values calculated for {len(self.X_sample)} samples")
        
        return self.shap_values
    
    def plot_summary(self, max_display: int = 20, save_path: str = None):
        """Create SHAP summary plot"""
        
        print(f"\n[*] Creating SHAP summary plot...")
        
        plt.figure(figsize=(10, 8))
        shap.summary_plot(
            self.shap_values, 
            self.X_sample.values,
            feature_names=self.feature_names,
            max_display=max_display,
            show=False
        )
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            print(f"✓ Summary plot saved to: {save_path}")
        else:
            plt.savefig('shap_summary.png', bbox_inches='tight', dpi=300)
            print(f"✓ Summary plot saved to: shap_summary.png")
        
        plt.close()
    
    def plot_bar(self, max_display: int = 20, save_path: str = None):
        """Create SHAP bar plot (feature importance)"""
        
        print(f"\n[*] Creating feature importance plot...")
        
        plt.figure(figsize=(10, 8))
        shap.summary_plot(
            self.shap_values,
            self.X_sample.values,
            feature_names=self.feature_names,
            plot_type="bar",
            max_display=max_display,
            show=False
        )
        
        if save_path:
            plt.savefig(save_path, bbox_inches='tight', dpi=300)
            print(f"✓ Bar plot saved to: {save_path}")
        else:
            plt.savefig('shap_bar.png', bbox_inches='tight', dpi=300)
            print(f"✓ Bar plot saved to: shap_bar.png")
        
        plt.close()
    
    def explain_single_vulnerability(self, index: int = 0):
        """Explain a single vulnerability prediction"""
        
        print(f"\n" + "="*60)
        print(f"  Explaining Single Vulnerability")
        print("="*60)
        
        # Get the vulnerability
        vuln = self.X_sample.iloc[index]
        vuln_full = self.df_full.iloc[self.X_sample.index[index]]
        
        # Get prediction
        prediction = self.model.predict(vuln.values.reshape(1, -1))[0]
        
        # Get SHAP values
        shap_vals = self.shap_values[index]
        
        # Get base value (expected value)
        base_value = self.explainer.expected_value
        
        print(f"\nVulnerability: {vuln_full.get('cve_id', 'Unknown')}")
        print(f"CVSS Base Score: {vuln_full.get('cvss_base_score', 0):.1f}")
        print(f"Predicted Risk Score: {prediction:.2f}")
        print(f"Base Risk (Average): {base_value:.2f}")
        print(f"Deviation from Base: {prediction - base_value:+.2f}")
        
        # Get top contributing features
        feature_contributions = pd.DataFrame({
            'feature': self.feature_names,
            'value': vuln.values,
            'shap_value': shap_vals
        }).sort_values('shap_value', key=abs, ascending=False)
        
        print(f"\nTop 10 Risk Contributors:")
        print(f"{'Feature':<30} {'Value':<15} {'SHAP Impact':>12}")
        print("-" * 60)
        
        for _, row in feature_contributions.head(10).iterrows():
            impact = f"{row['shap_value']:+.3f}"
            value_str = f"{row['value']:.3f}" if isinstance(row['value'], (int, float)) else str(row['value'])
            print(f"{row['feature']:<30} {value_str:<15} {impact:>12}")
        
        # Create waterfall plot
        print(f"\n[*] Creating waterfall plot...")
        
        plt.figure(figsize=(10, 8))
        shap.waterfall_plot(
            shap.Explanation(
                values=shap_vals,
                base_values=base_value,
                data=vuln.values,
                feature_names=self.feature_names
            ),
            max_display=15,
            show=False
        )
        
        save_path = f'shap_waterfall_example_{index}.png'
        plt.savefig(save_path, bbox_inches='tight', dpi=300)
        print(f"✓ Waterfall plot saved to: {save_path}")
        plt.close()
        
        return {
            'cve_id': vuln_full.get('cve_id', 'Unknown'),
            'prediction': prediction,
            'base_value': base_value,
            'top_features': feature_contributions.head(10).to_dict('records')
        }
    
    def get_feature_importance(self):
        """Get global feature importance from SHAP values"""
        
        print(f"\n[*] Calculating global feature importance...")
        
        # Mean absolute SHAP values
        mean_shap = np.abs(self.shap_values).mean(axis=0)
        
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': mean_shap
        }).sort_values('importance', ascending=False)
        
        print(f"\nTop 15 Most Important Features (by mean |SHAP|):")
        print(f"{'Rank':<6} {'Feature':<35} {'Importance':>12}")
        print("-" * 60)
        
        for idx, (_, row) in enumerate(importance_df.head(15).iterrows(), 1):
            print(f"{idx:<6} {row['feature']:<35} {row['importance']:>12.4f}")
        
        return importance_df


def generate_shap_explanations():
    """Main function to generate SHAP explanations"""
    
    print("\n" + "="*60)
    print("  GlitchForge SHAP Explainability Analysis")
    print("="*60)
    
    # Initialize explainer
    explainer = VulnerabilityExplainer()
    
    # Load data
    explainer.load_data(sample_size=100)
    
    # Create SHAP explainer
    explainer.create_explainer(background_samples=50)
    
    # Calculate SHAP values
    explainer.calculate_shap_values()
    
    # Generate visualizations
    print("\n" + "="*60)
    print("  Generating Visualizations")
    print("="*60)
    
    explainer.plot_summary(max_display=20)
    explainer.plot_bar(max_display=20)
    
    # Get global feature importance
    importance = explainer.get_feature_importance()
    
    # Explain a few example vulnerabilities
    print("\n" + "="*60)
    print("  Example Explanations")
    print("="*60)
    
    # Explain 3 random vulnerabilities
    for i in [0, 25, 50]:
        if i < len(explainer.X_sample):
            explainer.explain_single_vulnerability(index=i)
    
    print("\n" + "="*60)
    print("  SHAP Analysis Complete!")
    print("="*60)
    print("\nGenerated files:")
    print("  - shap_summary.png (feature importance with values)")
    print("  - shap_bar.png (mean feature importance)")
    print("  - shap_waterfall_example_*.png (single prediction explanations)")
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    generate_shap_explanations()