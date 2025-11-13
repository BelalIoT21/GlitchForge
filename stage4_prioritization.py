"""
GlitchForge Stage 4: Master Script
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

RUNS THE COMPLETE STAGE 4 PRIORITIZATION (SCORING, QUEUE MANAGEMENT, REPORTING, EVALUATION)
This script orchestrates the comprehensive, multi-factor risk scoring system and generates all final outputs.
"""

# Silence TensorFlow/Keras warnings
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import logging
logging.getLogger('tensorflow').setLevel(logging.ERROR)
logging.getLogger('absl').setLevel(logging.ERROR)

import sys
from pathlib import Path
# Insert root project path to allow imports from src/utils and src/prioritization
# NOTE: This line assumes this file is outside the src directory in the project root.
# Adjust the path as needed based on your actual project structure.
sys.path.insert(0, str(Path(__file__).parent.parent)) 

import pandas as pd
import numpy as np
import pickle
from datetime import datetime
from typing import Dict, List, Tuple

# Import the refactored classes
from src.utils.config import Config
from src.utils.logger import get_logger
# NOTE: MetricsCalculator was in the original imports but not used. Removing for cleanliness.
# If needed, you would import it here: from src.utils.metrics import MetricsCalculator

from src.prioritization.engine import RiskPrioritizationEngine
from src.prioritization.manager import PriorityQueueManager

# For NN model loading
try:
    from tensorflow import keras
except ImportError:
    print("Warning: TensorFlow not installed. NN model loading will fail if needed.")
    keras = None

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

logger = get_logger(__name__)

# The rest of the original main() function logic follows:

def main():
    """
    Main execution: Load Stage 2/3 outputs and generate risk prioritization
    Handles 15,000 CVE records with class imbalance
    """
    logger.info("="*70)
    logger.info("GLITCHFORGE STAGE 4: RISK PRIORITIZATION")
    logger.info("="*70)
    
    # Create output directory
    # NOTE: Assuming Config is properly defined in src/utils/config.py
    # Config.create_directories() 
    # output_dir = Config.OUTPUTS_DIR / "risk_prioritization"
    # output_dir.mkdir(parents=True, exist_ok=True)
    
    # Placeholder for Config and directories since they are missing here
    class MockConfig:
        OUTPUTS_DIR = Path("./outputs")
        TABLES_DIR = Path("./outputs/tables")
        PROCESSED_DATA_DIR = Path("./data/processed")
        RF_MODEL_PATH = Path("./models/rf_model.pkl")
        NN_MODEL_PATH = Path("./models/nn_model.h5")
        X_TRAIN_PATH = Path("./data/processed/X_train.csv")
        X_TEST_PATH = Path("./data/processed/X_test.csv")
        Y_TRAIN_PATH = Path("./data/processed/y_train.csv")
        Y_TEST_PATH = Path("./data/processed/y_test.csv")
        
        @staticmethod
        def create_directories():
            MockConfig.OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
            (MockConfig.OUTPUTS_DIR / "risk_prioritization").mkdir(parents=True, exist_ok=True)
            MockConfig.TABLES_DIR.mkdir(parents=True, exist_ok=True)
            MockConfig.PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Use the mock or actual Config
    Config.create_directories() # Ensure directories exist
    output_dir = Config.OUTPUTS_DIR / "risk_prioritization"
    
    # Step 1: Load data from Stage 2
    # ... (rest of the original main function logic, using the imported classes)
    
    logger.info("\n[Step 1/6] Loading Stage 2 data...")
    
    try:
        # Load models
        logger.info("  Loading models...")
        with open(Config.RF_MODEL_PATH, 'rb') as f:
            rf_model = pickle.load(f)
        
        if keras:
            nn_model = keras.models.load_model(Config.NN_MODEL_PATH)
        else:
            logger.error("TensorFlow/Keras not available. Cannot load NN model.")
            return

        # Load ALL processed data (training + test)
        logger.info("  Loading complete dataset...")
        X_train = pd.read_csv(Config.X_TRAIN_PATH)
        X_test = pd.read_csv(Config.X_TEST_PATH)
        y_train = pd.read_csv(Config.Y_TRAIN_PATH).values.ravel()
        y_test = pd.read_csv(Config.Y_TEST_PATH).values.ravel()
        
        # Combine for full dataset prioritization
        X_full = pd.concat([X_train, X_test], axis=0, ignore_index=True)
        y_full = np.concatenate([y_train, y_test])
        
        logger.info(f"  Training set: {len(X_train)} samples")
        logger.info(f"  Test set: {len(X_test)} samples")
        logger.info(f"  TOTAL: {len(X_full)} samples")
        
        # Show class distribution
        unique, counts = np.unique(y_full, return_counts=True)
        logger.info(f"\n  Ground Truth Risk Distribution:")
        risk_names = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}
        for label, count in zip(unique, counts):
            risk_name = risk_names.get(label, f'Class {label}')
            percentage = (count / len(y_full)) * 100
            logger.info(f"    {risk_name} ({label}): {count:,} ({percentage:.1f}%)")
        
        # Load feature names
        feature_names_path = Config.PROCESSED_DATA_DIR / 'feature_names.txt'
        with open(feature_names_path, 'r') as f:
            feature_names = [line.strip() for line in f.readlines()]
        
        logger.info(f"\n✓ Loaded: {len(X_full):,} total samples, {len(feature_names)} features")
        
    except FileNotFoundError as e:
        logger.error(f"✗ Failed to load Stage 2 data: {e}")
        logger.error("Please ensure Stage 2 (model training) has been run and paths are correct!")
        return
    except Exception as e:
        logger.error(f"An unexpected error occurred during data loading: {e}")
        return
    
    # Step 2: Load SHAP importance from Stage 3
    logger.info("\n[Step 2/6] Loading Stage 3 XAI data...")
    
    try:
        shap_importance_path = Config.TABLES_DIR / 'shap_importance.csv'
        shap_importance = pd.read_csv(shap_importance_path)
        
        # Create feature importance dictionary
        feature_importance = dict(zip(
            shap_importance['feature'],
            shap_importance['importance']
        ))
        
        logger.info(f"✓ Loaded SHAP importance for {len(feature_importance)} features")
        
    except FileNotFoundError:
        logger.warning("⚠ SHAP importance not found, continuing without it")
        feature_importance = {}
    
    # Step 3: Get ML predictions for FULL dataset
    logger.info("\n[Step 3/6] Getting ML model predictions...")
    logger.info(f"  Predicting {len(X_full):,} vulnerabilities...")
    
    # Random Forest predictions
    logger.info("  Random Forest predicting...")
    rf_predictions = rf_model.predict(X_full)
    rf_probabilities = rf_model.predict_proba(X_full)
    rf_confidences = rf_probabilities.max(axis=1)
    
    # Neural Network predictions
    logger.info("  Neural Network predicting...")
    nn_probabilities = nn_model.predict(X_full, verbose=0)
    nn_predictions = np.argmax(nn_probabilities, axis=1)
    nn_confidences = nn_probabilities.max(axis=1)
    
    # Show prediction distribution
    # ... (Distribution logging)
    logger.info(f"\n  RF Prediction Distribution:")
    unique_rf, counts_rf = np.unique(rf_predictions, return_counts=True)
    for label, count in zip(unique_rf, counts_rf):
        risk_name = risk_names.get(label, f'Class {label}')
        percentage = (count / len(rf_predictions)) * 100
        logger.info(f"    {risk_name}: {count:,} ({percentage:.1f}%)")
    
    logger.info(f"\n  NN Prediction Distribution:")
    unique_nn, counts_nn = np.unique(nn_predictions, return_counts=True)
    for label, count in zip(unique_nn, counts_nn):
        risk_name = risk_names.get(label, f'Class {label}')
        percentage = (count / len(nn_predictions)) * 100
        logger.info(f"    {risk_name}: {count:,} ({percentage:.1f}%)")
    
    # Model agreement
    agreement = np.mean(rf_predictions == nn_predictions)
    logger.info(f"\n  Model Agreement: {agreement:.1%}")
    
    logger.info(f"\n✓ Predictions obtained for {len(X_full):,} vulnerabilities")
    
    # Step 4: Calculate risk scores for ALL vulnerabilities
    logger.info("\n[Step 4/6] Calculating risk scores...")
    logger.info(f"  Processing {len(X_full):,} vulnerabilities...")
    
    engine = RiskPrioritizationEngine()
    queue_manager = PriorityQueueManager()
    
    # Process in batches with progress tracking
    batch_size = 1000
    total_batches = (len(X_full) + batch_size - 1) // batch_size
    
    for batch_idx in range(total_batches):
        start_idx = batch_idx * batch_size
        end_idx = min((batch_idx + 1) * batch_size, len(X_full))
        
        logger.info(f"  Batch {batch_idx + 1}/{total_batches}: Processing {start_idx:,} to {end_idx:,}")
        
        for idx in range(start_idx, end_idx):
            vuln_features = X_full.iloc[idx]
            
            # Extract required features with safe defaults
            cvss_base = float(vuln_features.get('cvss_base_score', 0.0))
            cvss_exploitability = float(vuln_features.get('exploitability_score', 0.0))
            cvss_impact = float(vuln_features.get('impact_score', 0.0))
            has_exploit = bool(vuln_features.get('has_exploit', 0))
            age_days = int(vuln_features.get('age_days', 365))
            products_count = int(vuln_features.get('product_count', 0))
            
            # Get feature importance for this vulnerability
            # NOTE: Global SHAP importance is used as a proxy for feature importance here.
            # In a real implementation, per-sample SHAP/LIME values would be loaded.
            vuln_importance = {
                feat: feature_importance.get(feat, 0.0)
                for feat in feature_names
            }
            
            # Calculate risk score
            risk_score = engine.prioritize_vulnerability(
                vuln_id=f"CVE-{idx:05d}",
                cvss_base=cvss_base,
                cvss_exploitability=cvss_exploitability,
                cvss_impact=cvss_impact,
                rf_prediction=int(rf_predictions[idx]),
                rf_confidence=float(rf_confidences[idx]),
                nn_prediction=int(nn_predictions[idx]),
                nn_confidence=float(nn_confidences[idx]),
                has_exploit=has_exploit,
                age_days=age_days,
                products_count=products_count,
                feature_importance=vuln_importance
            )
            
            # Add ground truth label for comparison
            risk_score.ground_truth_label = int(y_full[idx])
            
            queue_manager.add_vulnerability(risk_score)
    
    logger.info(f"✓ Calculated risk scores for {len(X_full):,} vulnerabilities")
    
    # Step 5: Sort and analyze
    logger.info("\n[Step 5/6] Sorting and analyzing priority queue...")
    
    queue_manager.sort_by_risk()
    queue_manager.calculate_statistics()
    
    stats = queue_manager.statistics
    
    # ... (Statistics logging)
    logger.info(f"\n  Priority Queue Statistics:")
    logger.info(f"    Total Vulnerabilities: {stats['total_vulnerabilities']:,}")
    logger.info(f"    Average Risk Score: {stats['average_score']:.2f}/100")
    logger.info(f"    Median Risk Score: {stats['median_score']:.2f}/100")
    logger.info(f"    Model Agreement: {stats['model_agreement_rate']:.1%}")
    logger.info(f"    Average Confidence: {stats['average_confidence']:.1%}")
    
    logger.info(f"\n  Risk Level Distribution:")
    for level, count in stats['by_risk_level'].items():
        percentage = (count / stats['total_vulnerabilities']) * 100
        logger.info(f"    {level}: {count:,} ({percentage:.1f}%)")
    
    logger.info(f"\n  Remediation Priority Distribution:")
    for priority, count in stats['by_remediation_priority'].items():
        percentage = (count / stats['total_vulnerabilities']) * 100
        logger.info(f"    {priority}: {count:,} ({percentage:.1f}%)")
    
    # Step 6: Compare with ground truth and generate outputs
    logger.info("\n[Step 6/6] Generating outputs and evaluation metrics...")
    
    # Calculate accuracy metrics
    df_queue = queue_manager.export_to_dataframe()
    
    # Map risk levels to numeric for comparison
    risk_level_map = {
        'Critical': 3,
        'High': 2,
        'Medium': 1,
        'Low': 0,
        'Informational': 0
    }
    
    df_queue['predicted_risk_numeric'] = df_queue['risk_level'].map(risk_level_map)
    df_queue['ground_truth_risk'] = [risk.ground_truth_label for risk in queue_manager.queue]
    
    y_true = df_queue['ground_truth_risk'].values
    y_pred_rf = df_queue['rf_prediction'].values
    y_pred_nn = df_queue['nn_prediction'].values
    y_pred_final = df_queue['predicted_risk_numeric'].values
    
    # Adjust if ground truth has 4 classes (0,1,2,3) but predictions are 3 (0,1,2)
    if y_true.max() > 2:
        logger.info("\n  Note: Ground truth has 4 risk levels, mapping to 3 (Critical->High) for comparison")
        y_true_mapped = y_true.copy()
        y_true_mapped[y_true == 3] = 2  # Map Critical to High
    else:
        y_true_mapped = y_true
    
    logger.info(f"\n  Evaluation Metrics:")
    
    # RF Accuracy
    rf_accuracy = accuracy_score(y_true_mapped, y_pred_rf)
    logger.info(f"    Random Forest Accuracy: {rf_accuracy:.2%}")
    
    # NN Accuracy  
    nn_accuracy = accuracy_score(y_true_mapped, y_pred_nn)
    logger.info(f"    Neural Network Accuracy: {nn_accuracy:.2%}")
    
    # Final prioritization accuracy
    final_accuracy = accuracy_score(y_true_mapped, y_pred_final)
    logger.info(f"    Final Prioritization Accuracy: {final_accuracy:.2%}")
    
    # Confusion matrix for final prioritization
    cm = confusion_matrix(y_true_mapped, y_pred_final)
    logger.info(f"\n  Confusion Matrix (Final Prioritization):")
    logger.info(f"    {cm}")
    
    # Classification report
    logger.info(f"\n  Classification Report (Final Prioritization):")
    
    # Determine target names based on mapped classes (Low=0, Medium=1, High/Critical=2)
    target_names = ['Low', 'Medium', 'High']
    labels = [0, 1, 2]
    
    report = classification_report(
        y_true_mapped, 
        y_pred_final,
        target_names=target_names,
        labels=labels,
        zero_division=0
    )
    logger.info(f"\n{report}")
    
    # Export full queue
    logger.info(f"\n  Exporting results...")
    queue_manager.save_to_csv(output_dir / 'priority_queue_full.csv')
    
    # Export top 100 critical
    top_100_df = df_queue.head(100)
    top_100_df.to_csv(output_dir / 'top_100_critical.csv', index=False)
    
    # Export by risk level
    for level in ['Critical', 'High', 'Medium', 'Low']:
        level_df = df_queue[df_queue['risk_level'] == level]
        if len(level_df) > 0:
            level_df.to_csv(output_dir / f'{level.lower()}_risk_vulnerabilities.csv', index=False)
            logger.info(f"    ✓ Saved {level} risk ({len(level_df):,} items)")
    
    # Save statistics with evaluation metrics
    stats['evaluation_metrics'] = {
        'rf_accuracy': float(rf_accuracy),
        'nn_accuracy': float(nn_accuracy),
        'final_prioritization_accuracy': float(final_accuracy),
        'confusion_matrix': cm.tolist()
    }
    queue_manager.save_statistics(output_dir / 'summary_statistics.json')
    
    # Generate comprehensive report
    queue_manager.generate_report(output_dir / 'risk_report.txt')
    
    # Print final summary
    logger.info("\n" + "="*70)
    logger.info("STAGE 4 COMPLETE - RISK PRIORITIZATION")
    logger.info("="*70)
    
    logger.info(f"\nModel Performance:")
    logger.info(f"  Final Prioritization Accuracy: {final_accuracy:.1%}")
    
    logger.info(f"\nTop 10 Highest-Risk Vulnerabilities:")
    for i, vuln in enumerate(queue_manager.get_top_n(10), 1):
        logger.info(f"  {i}. {vuln.vulnerability_id}: {vuln.risk_level.value} ({vuln.final_risk_score:.1f}/100)")
        logger.info(f"     Primary Factors: {', '.join(vuln.primary_factors[:3])}")
    
    logger.info("\n✓ Ready for Stage 5: Dashboard visualization")
    logger.info("="*70)


if __name__ == "__main__":
    main()