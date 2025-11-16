"""
GlitchForge Stage 2: ML Model Development Pipeline
Student: U2687294 - Bilal Almshmesh
Supervisor: Dr. Halima Kure

Orchestrates data collection, feature engineering, and model training
"""

import logging
import pandas as pd
from pathlib import Path
import os
import warnings

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
warnings.simplefilter(action='ignore', category=FutureWarning)

from src.ml.nvd_collector import NVDCollector
from src.ml.feature_engineering import FeatureEngineer
from src.ml.model_trainer import MLModelTrainer
from src.utils.config import Config

def collect_nvd_data():
    """Collect NVD vulnerability data"""
    try:
        collector = NVDCollector(api_key=Config.NVD_API_KEY)
        print("✅ NVD API Key detected")
    except (ImportError, AttributeError):
        collector = NVDCollector()
        print("⚠️ No API key - using public rate limit")

    df = collector.collect_cves(
        start_date="2018-01-01",
        end_date="2024-12-31",
        target_count=15000
    )

    data_file = Config.DATA_DIR / 'nvd_data_15k.csv'
    collector.save_to_csv(df, data_file)
    print(f"📊 Collected {len(df)} CVEs")
    return df

def main():
    """Main Stage 2 pipeline"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('stage2_training.log'),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)

    print("="*70)
    print(" "*15 + "GLITCHFORGE - STAGE 2")
    print(" "*10 + "ML Model Development Pipeline")
    print("="*70)

    Config.create_directories()

    # Step 1: Data Collection
    print("\n" + "="*70)
    print("STEP 1: Collecting NVD Data")
    print("="*70)

    nvd_data_file = Config.DATA_DIR / 'nvd_data_15k.csv'

    if nvd_data_file.exists():
        response = input(f"\nFound existing data. Use it? (y/n): ").lower()
        df_raw = pd.read_csv(nvd_data_file) if response == 'y' else collect_nvd_data()
    else:
        df_raw = collect_nvd_data()

    logger.info(f"Raw data shape: {df_raw.shape}")

    # Step 2: Feature Engineering
    print("\n" + "="*70)
    print("STEP 2: Feature Engineering")
    print("="*70)

    engineer = FeatureEngineer()
    df_engineered = engineer.engineer_features(df_raw)

    engineered_file = Config.DATA_DIR / 'features_engineered.csv'
    df_engineered.to_csv(engineered_file, index=False)
    logger.info(f"Features saved to {engineered_file}")

    X, y = engineer.select_features(df_engineered)
    logger.info(f"Dataset ready: Features {X.shape}, Labels {y.shape}")

    # Step 3: Model Training
    print("\n" + "="*70)
    print("STEP 3: Model Training")
    print("="*70)

    trainer = MLModelTrainer()
    X_train, X_val, X_test, y_train, y_val, y_test = trainer.prepare_data(X, y)

    X_train_scaled, X_val_scaled = engineer.normalize_features(X_train, X_val)
    X_test_scaled = pd.DataFrame(
        engineer.scaler.transform(X_test),
        columns=X_test.columns,
        index=X_test.index
    )

    # Step 3A: Random Forest
    print("\n" + "-"*70)
    print("Training Random Forest Classifier")
    print("-"*70)

    rf_metrics = trainer.train_random_forest(
        X_train_scaled, y_train, X_val_scaled, y_val,
        hyperparameter_tune=False
    )
    trainer.save_metrics(rf_metrics, 'rf_training_metrics.json')

    # Step 3B: Neural Network
    print("\n" + "-"*70)
    print("Training Neural Network Classifier")
    print("-"*70)

    nn_metrics = trainer.train_neural_network(
        X_train_scaled, y_train, X_val_scaled, y_val,
        epochs=100, batch_size=32
    )
    trainer.save_metrics(nn_metrics, 'nn_training_metrics.json')

    # Step 4: Test Set Evaluation
    print("\n" + "="*70)
    print("STEP 4: Test Set Evaluation")
    print("="*70)

    test_metrics = trainer.evaluate_on_test(X_test_scaled, y_test)
    trainer.save_metrics(test_metrics, 'test_metrics.json')

    # Step 5: Results Summary
    print("\n" + "="*70)
    print("STAGE 2 COMPLETE - MODEL COMPARISON")
    print("="*70)

    rf_test = test_metrics.get('random_forest', {})
    nn_test = test_metrics.get('neural_network', {})
    rf_acc = rf_test.get('accuracy', 0)
    nn_acc = nn_test.get('accuracy', 0)
    target = 0.90

    print(f"\nRandom Forest: {rf_acc:.4f}")
    print(f"Neural Network: {nn_acc:.4f}")

    if rf_acc > nn_acc:
        print(f"🏆 Random Forest performed better (+{(rf_acc - nn_acc)*100:.2f}%)")
    elif nn_acc > rf_acc:
        print(f"🏆 Neural Network performed better (+{(nn_acc - rf_acc)*100:.2f}%)")
    else:
        print("👍 Both models performed equally")

    print(f"\nTarget: {target*100:.1f}% accuracy")
    print(f"RF: {'✅ ACHIEVED' if rf_acc >= target else '❌ NOT MET'} ({rf_acc*100:.2f}%)")
    print(f"NN: {'✅ ACHIEVED' if nn_acc >= target else '❌ NOT MET'} ({nn_acc*100:.2f}%)")

    if rf_acc >= target or nn_acc >= target:
        print("\n🎉 Stage 2 Target Achieved!")
    else:
        print("\n⚠️ Target not met. Review feature engineering.")

    print("\n" + "="*70)
    print("READY FOR STAGE 3: XAI Integration")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
