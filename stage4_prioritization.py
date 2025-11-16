"""
GlitchForge Stage 4: Master Script
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

Complete Stage 4 risk prioritization: scoring, queue management, reporting, evaluation
"""

# Silence TensorFlow/Keras warnings
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import logging
logging.getLogger('tensorflow').setLevel(logging.ERROR)
logging.getLogger('absl').setLevel(logging.ERROR)

import pandas as pd
import numpy as np
import pickle
from pathlib import Path

from src.utils.config import Config
from src.utils.logger import get_logger
from src.prioritization.engine import RiskPrioritizationEngine
from src.prioritization.manager import PriorityQueueManager

try:
    from tensorflow import keras
except ImportError:
    print("Warning: TensorFlow not installed. NN model loading will fail.")
    keras = None

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

logger = get_logger(__name__)


def load_models():
    """Load trained RF and NN models."""
    with open(Config.RF_MODEL_PATH, 'rb') as f:
        rf_model = pickle.load(f)

    if not keras:
        raise RuntimeError("TensorFlow/Keras not available. Cannot load NN model.")

    nn_model = keras.models.load_model(Config.NN_MODEL_PATH)
    return rf_model, nn_model


def load_data():
    """Load and combine training and test datasets."""
    X_train = pd.read_csv(Config.X_TRAIN_PATH)
    X_test = pd.read_csv(Config.X_TEST_PATH)
    y_train = pd.read_csv(Config.Y_TRAIN_PATH).values.ravel()
    y_test = pd.read_csv(Config.Y_TEST_PATH).values.ravel()

    X_full = pd.concat([X_train, X_test], axis=0, ignore_index=True)
    y_full = np.concatenate([y_train, y_test])

    # Load feature names
    with open(Config.PROCESSED_DATA_DIR / 'feature_names.txt', 'r') as f:
        feature_names = [line.strip() for line in f.readlines()]

    return X_full, y_full, feature_names


def load_shap_importance():
    """Load SHAP feature importance from Stage 3."""
    try:
        shap_df = pd.read_csv(Config.TABLES_DIR / 'shap_importance.csv')
        return dict(zip(shap_df['feature'], shap_df['importance']))
    except FileNotFoundError:
        logger.warning("SHAP importance not found, continuing without it")
        return {}


def get_predictions(models, X_full):
    """Generate predictions from both RF and NN models."""
    rf_model, nn_model = models

    # Random Forest
    rf_predictions = rf_model.predict(X_full)
    rf_probabilities = rf_model.predict_proba(X_full)
    rf_confidences = rf_probabilities.max(axis=1)

    # Neural Network
    nn_probabilities = nn_model.predict(X_full, verbose=0)
    nn_predictions = np.argmax(nn_probabilities, axis=1)
    nn_confidences = nn_probabilities.max(axis=1)

    return rf_predictions, rf_confidences, nn_predictions, nn_confidences


def calculate_risk_scores(X_full, y_full, rf_predictions, rf_confidences,
                         nn_predictions, nn_confidences, feature_names, feature_importance):
    """Process all vulnerabilities and calculate risk scores."""
    engine = RiskPrioritizationEngine()
    queue_manager = PriorityQueueManager()

    batch_size = 1000
    total_batches = (len(X_full) + batch_size - 1) // batch_size

    for batch_idx in range(total_batches):
        start_idx = batch_idx * batch_size
        end_idx = min((batch_idx + 1) * batch_size, len(X_full))

        if batch_idx % 5 == 0:  # Log every 5th batch
            logger.info(f"  Processing batch {batch_idx + 1}/{total_batches}")

        for idx in range(start_idx, end_idx):
            vuln_features = X_full.iloc[idx]

            # Extract features with safe defaults
            cvss_base = float(vuln_features.get('cvss_base_score', 0.0))
            cvss_exploitability = float(vuln_features.get('exploitability_score', 0.0))
            cvss_impact = float(vuln_features.get('impact_score', 0.0))
            has_exploit = bool(vuln_features.get('has_exploit', 0))
            age_days = int(vuln_features.get('age_days', 365))
            products_count = int(vuln_features.get('product_count', 0))

            # Get feature importance
            vuln_importance = {feat: feature_importance.get(feat, 0.0) for feat in feature_names}

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

            risk_score.ground_truth_label = int(y_full[idx])
            queue_manager.add_vulnerability(risk_score)

    return queue_manager


def log_statistics(stats, total_vulns):
    """Log priority queue statistics."""
    logger.info(f"\n  Priority Queue Statistics:")
    logger.info(f"    Total: {stats['total_vulnerabilities']:,} | Avg Score: {stats['average_score']:.2f}/100")
    logger.info(f"    Median: {stats['median_score']:.2f} | Agreement: {stats['model_agreement_rate']:.1%}")

    logger.info(f"\n  Risk Distribution:")
    for level, count in stats['by_risk_level'].items():
        pct = (count / total_vulns) * 100
        logger.info(f"    {level}: {count:,} ({pct:.1f}%)")


def evaluate_performance(queue_manager):
    """Calculate and return evaluation metrics."""
    df_queue = queue_manager.export_to_dataframe()

    risk_level_map = {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0, 'Informational': 0}
    df_queue['predicted_risk_numeric'] = df_queue['risk_level'].map(risk_level_map)
    df_queue['ground_truth_risk'] = [risk.ground_truth_label for risk in queue_manager.queue]

    y_true = df_queue['ground_truth_risk'].values
    y_pred_rf = df_queue['rf_prediction'].values
    y_pred_nn = df_queue['nn_prediction'].values
    y_pred_final = df_queue['predicted_risk_numeric'].values

    # Map 4-class to 3-class if needed
    y_true_mapped = y_true.copy()
    if y_true.max() > 2:
        y_true_mapped[y_true == 3] = 2

    # Calculate metrics
    rf_acc = accuracy_score(y_true_mapped, y_pred_rf)
    nn_acc = accuracy_score(y_true_mapped, y_pred_nn)
    final_acc = accuracy_score(y_true_mapped, y_pred_final)
    cm = confusion_matrix(y_true_mapped, y_pred_final)

    logger.info(f"\n  Evaluation Metrics:")
    logger.info(f"    RF: {rf_acc:.2%} | NN: {nn_acc:.2%} | Final: {final_acc:.2%}")

    report = classification_report(
        y_true_mapped, y_pred_final,
        target_names=['Low', 'Medium', 'High'],
        labels=[0, 1, 2],
        zero_division=0
    )
    logger.info(f"\n{report}")

    return df_queue, final_acc, rf_acc, nn_acc, cm


def export_results(queue_manager, df_queue, output_dir, final_acc, rf_acc, nn_acc, cm):
    """Export all results and reports."""
    queue_manager.save_to_csv(output_dir / 'priority_queue_full.csv')
    df_queue.head(100).to_csv(output_dir / 'top_100_critical.csv', index=False)

    for level in ['Critical', 'High', 'Medium', 'Low']:
        level_df = df_queue[df_queue['risk_level'] == level]
        if len(level_df) > 0:
            level_df.to_csv(output_dir / f'{level.lower()}_risk_vulnerabilities.csv', index=False)

    # Save statistics with metrics
    stats = queue_manager.statistics
    stats['evaluation_metrics'] = {
        'rf_accuracy': float(rf_acc),
        'nn_accuracy': float(nn_acc),
        'final_prioritization_accuracy': float(final_acc),
        'confusion_matrix': cm.tolist()
    }
    queue_manager.save_statistics(output_dir / 'summary_statistics.json')
    queue_manager.generate_report(output_dir / 'risk_report.txt')

    logger.info(f"  ✓ Exported all results to {output_dir}")


def main():
    """Main execution: Load Stage 2/3 outputs and generate risk prioritization."""
    logger.info("="*70)
    logger.info("GLITCHFORGE STAGE 4: RISK PRIORITIZATION")
    logger.info("="*70)

    Config.create_directories()
    output_dir = Config.OUTPUTS_DIR / "risk_prioritization"
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Step 1: Load models and data
        logger.info("\n[Step 1/5] Loading models and data...")
        models = load_models()
        X_full, y_full, feature_names = load_data()
        logger.info(f"  ✓ Loaded {len(X_full):,} samples with {len(feature_names)} features")

        # Step 2: Load SHAP importance
        logger.info("\n[Step 2/5] Loading XAI data...")
        feature_importance = load_shap_importance()
        logger.info(f"  ✓ Loaded importance for {len(feature_importance)} features")

        # Step 3: Get predictions
        logger.info("\n[Step 3/5] Generating predictions...")
        rf_pred, rf_conf, nn_pred, nn_conf = get_predictions(models, X_full)
        agreement = np.mean(rf_pred == nn_pred)
        logger.info(f"  ✓ Predictions complete | Model agreement: {agreement:.1%}")

        # Step 4: Calculate risk scores
        logger.info("\n[Step 4/5] Calculating risk scores...")
        queue_manager = calculate_risk_scores(
            X_full, y_full, rf_pred, rf_conf, nn_pred, nn_conf,
            feature_names, feature_importance
        )
        queue_manager.sort_by_risk()
        queue_manager.calculate_statistics()
        logger.info(f"  ✓ Processed {len(X_full):,} vulnerabilities")

        log_statistics(queue_manager.statistics, len(X_full))

        # Step 5: Evaluate and export
        logger.info("\n[Step 5/5] Evaluating and exporting...")
        df_queue, final_acc, rf_acc, nn_acc, cm = evaluate_performance(queue_manager)
        export_results(queue_manager, df_queue, output_dir, final_acc, rf_acc, nn_acc, cm)

        # Final summary
        logger.info("\n" + "="*70)
        logger.info(f"STAGE 4 COMPLETE | Final Accuracy: {final_acc:.1%}")
        logger.info("="*70)

        logger.info(f"\nTop 10 Highest-Risk Vulnerabilities:")
        for i, vuln in enumerate(queue_manager.get_top_n(10), 1):
            logger.info(f"  {i}. {vuln.vulnerability_id}: {vuln.risk_level.value} ({vuln.final_risk_score:.1f}/100)")

        logger.info("\n✓ Ready for Stage 5: Dashboard visualization")
        logger.info("="*70)

    except FileNotFoundError as e:
        logger.error(f"✗ Missing required file: {e}")
        logger.error("Please ensure Stage 2 and Stage 3 have been completed.")
    except Exception as e:
        logger.error(f"✗ Unexpected error: {e}")
        raise


if __name__ == "__main__":
    main()
