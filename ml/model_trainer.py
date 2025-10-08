"""
XGBoost Model Trainer for Vulnerability Risk Prediction
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
from scipy.stats import spearmanr
import xgboost as xgb
import pickle
from pathlib import Path
import sys

# Fix import path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import MODELS_DIR, PROCESSED_DATA_DIR, ML_CONFIG

class VulnerabilityModelTrainer:
    """Train XGBoost model for vulnerability risk prediction"""
    
    def __init__(self):
        self.model = None
        self.feature_names = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        
    def load_data(self, filename: str = 'processed_nvd_data.csv'):
        """Load processed vulnerability data"""
        
        filepath = PROCESSED_DATA_DIR / filename
        
        print(f"\n[*] Loading processed data from {filepath}...")
        df = pd.read_csv(filepath)
        
        print(f"✓ Loaded {len(df)} records")
        
        return df
    
    def prepare_training_data(self, df: pd.DataFrame, test_size: float = 0.2):
        """Prepare data for training"""
        
        print(f"\n[*] Preparing training data...")
        
        # Separate features and target
        # Exclude non-feature columns
        exclude_cols = ['cve_id', 'risk_score', 'cwe_ids', 'description', 
                       'published_date', 'modified_date']
        
        feature_cols = [col for col in df.columns if col not in exclude_cols]
        
        X = df[feature_cols]
        y = df['risk_score']
        
        # Store feature names
        self.feature_names = feature_cols
        
        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, 
            test_size=test_size, 
            random_state=ML_CONFIG['random_state']
        )
        
        print(f"✓ Training set: {len(self.X_train)} samples")
        print(f"✓ Test set: {len(self.X_test)} samples")
        print(f"✓ Features: {len(feature_cols)}")
        
        return self.X_train, self.X_test, self.y_train, self.y_test
    
    def train_xgboost(self):
        """Train XGBoost model"""
        
        print(f"\n[*] Training XGBoost model...")
        
        # Initialize model with parameters from config
        self.model = xgb.XGBRegressor(**ML_CONFIG['xgboost_params'])
        
        # Train model
        self.model.fit(
            self.X_train, 
            self.y_train,
            eval_set=[(self.X_test, self.y_test)],
            verbose=False
        )
        
        print(f"✓ Model training complete")
        
        return self.model
    
    def evaluate_model(self):
        """Evaluate model performance"""
        
        print(f"\n" + "="*60)
        print("  Model Evaluation Results")
        print("="*60)
        
        # Make predictions
        y_train_pred = self.model.predict(self.X_train)
        y_test_pred = self.model.predict(self.X_test)
        
        # Calculate metrics
        # Training metrics
        train_mse = mean_squared_error(self.y_train, y_train_pred)
        train_mae = mean_absolute_error(self.y_train, y_train_pred)
        train_r2 = r2_score(self.y_train, y_train_pred)
        
        # Test metrics
        test_mse = mean_squared_error(self.y_test, y_test_pred)
        test_mae = mean_absolute_error(self.y_test, y_test_pred)
        test_r2 = r2_score(self.y_test, y_test_pred)
        
        # Spearman correlation (ranking quality)
        test_spearman, _ = spearmanr(self.y_test, y_test_pred)
        
        # Print results
        print(f"\nTraining Set Performance:")
        print(f"  MSE: {train_mse:.3f}")
        print(f"  MAE: {train_mae:.3f}")
        print(f"  R²: {train_r2:.3f}")
        
        print(f"\nTest Set Performance:")
        print(f"  MSE: {test_mse:.3f}")
        print(f"  MAE: {test_mae:.3f}")
        print(f"  R²: {test_r2:.3f}")
        print(f"  Spearman Correlation: {test_spearman:.3f}")
        
        # Cross-validation
        print(f"\n[*] Performing 5-fold cross-validation...")
        cv_scores = cross_val_score(
            self.model, 
            self.X_train, 
            self.y_train,
            cv=ML_CONFIG['cv_folds'],
            scoring='r2'
        )
        
        print(f"✓ Cross-validation R² scores: {cv_scores}")
        print(f"  Mean: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")
        
        # Feature importance
        print(f"\n" + "="*60)
        print("  Top 10 Most Important Features")
        print("="*60)
        
        feature_importance = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print()
        for idx, row in feature_importance.head(10).iterrows():
            print(f"  {row['feature']:<40} {row['importance']:.4f}")
        
        # Precision@10 (top 10% prediction accuracy)
        print(f"\n" + "="*60)
        print("  Precision@10 Analysis")
        print("="*60)
        
        # Get top 10% by predicted risk
        top_10_percent = int(len(self.y_test) * 0.1)
        top_predicted_indices = np.argsort(y_test_pred)[-top_10_percent:]
        
        # Check how many are actually high risk (>= 7.0)
        actual_high_risk = self.y_test.iloc[top_predicted_indices] >= 7.0
        precision_at_10 = actual_high_risk.sum() / len(actual_high_risk)
        
        print(f"\n  Top 10% predictions: {top_10_percent} vulnerabilities")
        print(f"  Actually high-risk (≥7.0): {actual_high_risk.sum()}")
        print(f"  Precision@10: {precision_at_10:.2%}")
        
        return {
            'test_mse': test_mse,
            'test_mae': test_mae,
            'test_r2': test_r2,
            'test_spearman': test_spearman,
            'cv_mean_r2': cv_scores.mean(),
            'cv_std_r2': cv_scores.std(),
            'precision_at_10': precision_at_10
        }
    
    def save_model(self, filename: str = 'xgboost_model.pkl'):
        """Save trained model"""
        
        filepath = MODELS_DIR / filename
        
        model_data = {
            'model': self.model,
            'feature_names': self.feature_names
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"\n✓ Model saved to: {filepath}")
        
        return str(filepath)
    
    def load_model(self, filename: str = 'xgboost_model.pkl'):
        """Load trained model"""
        
        filepath = MODELS_DIR / filename
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.feature_names = model_data['feature_names']
        
        print(f"✓ Model loaded from: {filepath}")
        
        return self.model


def train_vulnerability_model():
    """Main training function"""
    
    print("\n" + "="*60)
    print("  GlitchForge ML Model Training")
    print("="*60)
    
    # Initialize trainer
    trainer = VulnerabilityModelTrainer()
    
    # Load data
    df = trainer.load_data('processed_nvd_data.csv')
    
    # Prepare training data
    trainer.prepare_training_data(df)
    
    # Train model
    trainer.train_xgboost()
    
    # Evaluate model
    metrics = trainer.evaluate_model()
    
    # Save model
    trainer.save_model('xgboost_vulnerability_model.pkl')
    
    print("\n" + "="*60)
    print("  Training Complete!")
    print("="*60)
    print(f"\n  Model Performance Summary:")
    print(f"    Test R²: {metrics['test_r2']:.3f}")
    print(f"    Test MAE: {metrics['test_mae']:.3f}")
    print(f"    Spearman: {metrics['test_spearman']:.3f}")
    print(f"    Precision@10: {metrics['precision_at_10']:.2%}")
    print("="*60 + "\n")


if __name__ == "__main__":
    train_vulnerability_model()