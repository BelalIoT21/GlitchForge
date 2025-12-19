"""
GlitchForge Stage 2: Master Script - ML Model Development Pipeline
Student: U2687294 - Bilal Almshmesh
Supervisor: Dr. Halima Kure

RUNS THE COMPLETE STAGE 2 ML PIPELINE (DATA PREP, TRAINING, EVALUATION)
"""

import logging
import pandas as pd
from pathlib import Path
import sys
import os
import warnings
from datetime import datetime
import json

# --- Environment Setup & Warning Suppression ---
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

warnings.simplefilter(action='ignore', category=FutureWarning)

# Add backend directory to path so we can import app modules
backend_dir = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

from app.core.ml.nvd_collector import NVDCollector
from app.core.ml.feature_engineering import FeatureEngineer
from app.core.ml.model_trainer import MLModelTrainer

def setup_directories():
    """Create all required directories using config paths"""
    from app.config import DATA_DIR, OUTPUTS_DIR, MODELS_DIR, BASE_DIR
    directories = {
        'data': DATA_DIR,
        'logs': BASE_DIR / 'logs',
        'outputs': OUTPUTS_DIR,
        'models': MODELS_DIR
    }

    for name, path in directories.items():
        path.mkdir(exist_ok=True)
        print(f"✓ {name}/ directory ready")

    return directories

def setup_logging(logs_dir):
    """Setup logging configuration with UTF-8 encoding"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = logs_dir / f'stage2_training_{timestamp}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),  # UTF-8 encoding
            logging.StreamHandler()
        ]
    )
    
    return log_file

def save_metrics_to_outputs(metrics, filepath):
    """Save metrics directly to outputs folder with UTF-8 encoding"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)

def collect_nvd_data(data_dir):
    """Collect NVD data"""
    try:
        from app.config import NVD_API_KEY
        collector = NVDCollector(api_key=NVD_API_KEY)
        print("✅ NVD API Key detected (Rate limit: 100 req/min)")
    except ImportError:
        collector = NVDCollector()
        print("⚠️  No API key found. Using public rate limit (10 req/min).")
    except Exception:
        collector = NVDCollector()
        print("⚠️  Error setting up API key. Using public rate limit (10 req/min).")
    
    df = collector.collect_cves(
        start_date="2018-01-01",
        end_date="2024-12-31",
        target_count=15000,
        keywords=None
    )
    
    data_file = data_dir / 'nvd_data_15k.csv'
    collector.save_to_csv(df, data_file)
    
    print(f"📊 Collected {len(df)} CVEs.")
    print(f"📁 Saved to: {data_file}")
    print("\nVulnerability type distribution:")
    print(df['vuln_type'].value_counts())
    
    return df


def main():
    """Main Stage 2 pipeline"""
    print("="*70)
    print(" "*15 + "GLITCHFORGE - STAGE 2")
    print(" "*10 + "ML Model Development Pipeline")
    print(" "*20 + "FINAL VERSION")
    print("="*70)
    
    # Setup directories and logging
    directories = setup_directories()
    data_dir = directories['data']
    logs_dir = directories['logs']
    outputs_dir = directories['outputs']
    models_dir = directories['models']
    
    log_file = setup_logging(logs_dir)
    logger = logging.getLogger(__name__)
    
    # ========================================
    # STEP 1: Data Collection
    # ========================================
    print("\n" + "="*70)
    print("STEP 1: Collecting NVD Data")
    print("="*70)
    
    nvd_data_file = data_dir / 'nvd_data_15k.csv'
    
    if nvd_data_file.exists():
        print(f"\n📂 Found existing data file: {nvd_data_file}")
        response = input("Use existing data? (y/n): ").lower()
        if response == 'y':
            df_raw = pd.read_csv(nvd_data_file)
            print(f"✅ Loaded {len(df_raw)} existing CVEs")
            logger.info(f"Loaded existing data: {len(df_raw)} CVEs")
        else:
            df_raw = collect_nvd_data(data_dir)
            logger.info(f"Collected new data: {len(df_raw)} CVEs")
    else:
        df_raw = collect_nvd_data(data_dir)
        logger.info(f"Collected new data: {len(df_raw)} CVEs")
    
    logger.info(f"Raw data shape: {df_raw.shape}")
    
    # ========================================
    # STEP 2: Feature Engineering
    # ========================================
    print("\n" + "="*70)
    print("STEP 2: Feature Engineering")
    print("="*70)
    
    engineer = FeatureEngineer()
    df_engineered = engineer.engineer_features(df_raw)
    
    engineered_file = data_dir / 'features_engineered.csv'
    df_engineered.to_csv(engineered_file, index=False)
    print(f"💾 Engineered features saved to: {engineered_file}")
    logger.info(f"Engineered features saved to {engineered_file}")
    
    X, y = engineer.select_features(df_engineered)
    
    logger.info(f"Final Dataset Ready (Features: {X.shape}, Labels: {y.shape})")
    print(f"✅ Feature engineering complete")
    print(f"   Features: {X.shape}")
    print(f"   Labels: {y.shape}")
    
    # ========================================
    # STEP 3: Model Training
    # ========================================
    print("\n" + "="*70)
    print("STEP 3: Model Training")
    print("="*70)
    
    trainer = MLModelTrainer()
    X_train, X_val, X_test, y_train, y_val, y_test = trainer.prepare_data(X, y)
    
    print(f"📊 Data split:")
    print(f"   Training: {X_train.shape[0]} samples")
    print(f"   Validation: {X_val.shape[0]} samples")
    print(f"   Test: {X_test.shape[0]} samples")
    
    # Normalize features
    X_train_scaled, X_val_scaled = engineer.normalize_features(X_train, X_val)
    X_test_scaled = pd.DataFrame(
        engineer.scaler.transform(X_test),
        columns=X_test.columns,
        index=X_test.index
    )
    
    # ========================================
    # STEP 3A: Random Forest
    # ========================================
    print("\n" + "-"*70)
    print("Training Random Forest Classifier")
    print("-"*70)
    
    rf_metrics = trainer.train_random_forest(
        X_train_scaled, y_train, X_val_scaled, y_val,
        hyperparameter_tune=False
    )
    
    # Save directly to outputs/
    rf_metrics_file = outputs_dir / 'rf_training_metrics.json'
    save_metrics_to_outputs(rf_metrics, rf_metrics_file)
    print(f"💾 Random Forest metrics saved to: {rf_metrics_file}")
    logger.info(f"Random Forest metrics saved to {rf_metrics_file}")
    
    # ========================================
    # STEP 3B: Neural Network
    # ========================================
    print("\n" + "-"*70)
    print("Training Neural Network Classifier")
    print("-"*70)
    
    nn_metrics = trainer.train_neural_network(
        X_train_scaled, y_train, X_val_scaled, y_val,
        epochs=100, batch_size=32
    )
    
    # Save directly to outputs/
    nn_metrics_file = outputs_dir / 'nn_training_metrics.json'
    save_metrics_to_outputs(nn_metrics, nn_metrics_file)
    print(f"💾 Neural Network metrics saved to: {nn_metrics_file}")
    logger.info(f"Neural Network metrics saved to {nn_metrics_file}")
    
    # ========================================
    # STEP 4: Test Set Evaluation
    # ========================================
    print("\n" + "="*70)
    print("STEP 4: Test Set Evaluation")
    print("="*70)
    
    test_metrics = trainer.evaluate_on_test(X_test_scaled, y_test)
    
    # Save directly to outputs/
    test_metrics_file = outputs_dir / 'test_metrics.json'
    save_metrics_to_outputs(test_metrics, test_metrics_file)
    print(f"💾 Test metrics saved to: {test_metrics_file}")
    logger.info(f"Test metrics saved to {test_metrics_file}")
    
    # ========================================
    # STEP 5: Generate Summary Report
    # ========================================
    print("\n" + "="*70)
    print("STEP 5: Generating Summary Report")
    print("="*70)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_file = outputs_dir / f'stage2_summary_{timestamp}.txt'
    
    # FIXED: Added encoding='utf-8' to support emojis
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("GLITCHFORGE STAGE 2 - ML TRAINING SUMMARY\n")
        f.write("="*70 + "\n\n")
        
        f.write(f"Training Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Student: Bilal Almshmesh (U2687294)\n")
        f.write(f"Supervisor: Dr. Halima Kure\n\n")
        
        f.write("="*70 + "\n")
        f.write("DATASET INFORMATION\n")
        f.write("="*70 + "\n")
        f.write(f"Total Samples: {len(df_raw)}\n")
        f.write(f"Features: {X.shape[1]}\n")
        f.write(f"Training Set: {X_train.shape[0]} samples\n")
        f.write(f"Validation Set: {X_val.shape[0]} samples\n")
        f.write(f"Test Set: {X_test.shape[0]} samples\n\n")
        
        f.write("="*70 + "\n")
        f.write("MODEL PERFORMANCE - TEST SET\n")
        f.write("="*70 + "\n\n")
        
        rf_test = test_metrics.get('random_forest', {})
        nn_test = test_metrics.get('neural_network', {})
        
        f.write("RANDOM FOREST:\n")
        f.write(f"  Accuracy: {rf_test.get('accuracy', 0):.4f}\n")
        f.write(f"  Precision: {rf_test.get('precision', 0):.4f}\n")
        f.write(f"  Recall: {rf_test.get('recall', 0):.4f}\n")
        f.write(f"  F1-Score: {rf_test.get('f1_score', 0):.4f}\n\n")
        
        f.write("NEURAL NETWORK:\n")
        f.write(f"  Accuracy: {nn_test.get('accuracy', 0):.4f}\n")
        f.write(f"  Precision: {nn_test.get('precision', 0):.4f}\n")
        f.write(f"  Recall: {nn_test.get('recall', 0):.4f}\n")
        f.write(f"  F1-Score: {nn_test.get('f1_score', 0):.4f}\n\n")
        
        f.write("="*70 + "\n")
        f.write("MODEL COMPARISON\n")
        f.write("="*70 + "\n")
        
        rf_acc = rf_test.get('accuracy', 0)
        nn_acc = nn_test.get('accuracy', 0)
        
        if rf_acc > nn_acc:
            f.write(f"🏆 Random Forest performed better (+{(rf_acc - nn_acc)*100:.2f}%)\n")
        elif nn_acc > rf_acc:
            f.write(f"🏆 Neural Network performed better (+{(nn_acc - rf_acc)*100:.2f}%)\n")
        else:
            f.write("Both models performed equally.\n")
        
        f.write("\n")
        f.write("="*70 + "\n")
        f.write("TARGET ACHIEVEMENT (90% Accuracy)\n")
        f.write("="*70 + "\n")
        
        target = 0.90
        f.write(f"Random Forest: {'✅ ACHIEVED' if rf_acc >= target else '❌ NOT MET'} ({rf_acc*100:.2f}%)\n")
        f.write(f"Neural Network: {'✅ ACHIEVED' if nn_acc >= target else '❌ NOT MET'} ({nn_acc*100:.2f}%)\n\n")
        
        if rf_acc >= target or nn_acc >= target:
            f.write("🎉 Stage 2 Target Achieved!\n")
        else:
            f.write("⚠️ Target not met. Review feature engineering or hyperparameters.\n")
        
        f.write("\n")
        f.write("="*70 + "\n")
        f.write("OUTPUT FILES\n")
        f.write("="*70 + "\n")
        f.write(f"Logs: {log_file}\n")
        f.write(f"Data: {data_dir}/\n")
        f.write(f"  - nvd_data_15k.csv\n")
        f.write(f"  - features_engineered.csv\n")
        f.write(f"Models: {models_dir}/\n")
        f.write(f"  - random_forest.pkl\n")
        f.write(f"  - neural_network.h5\n")
        f.write(f"  - scaler.pkl\n")
        f.write(f"Outputs: {outputs_dir}/\n")
        f.write(f"  - rf_training_metrics.json\n")
        f.write(f"  - nn_training_metrics.json\n")
        f.write(f"  - test_metrics.json\n")
        f.write(f"  - stage2_summary_{timestamp}.txt\n")
    
    print(f"📄 Summary report saved to: {summary_file}")
    logger.info(f"Summary report saved to {summary_file}")
    
    # ========================================
    # STEP 6: Final Summary (Console Output)
    # ========================================
    print("\n" + "="*70)
    print("STAGE 2 COMPLETE - MODEL COMPARISON")
    print("="*70)
    
    rf_test = test_metrics.get('random_forest', {})
    nn_test = test_metrics.get('neural_network', {})
    rf_acc = rf_test.get('accuracy', 0)
    nn_acc = nn_test.get('accuracy', 0)
    target = 0.90
    
    print("\n--- FINAL TEST ACCURACY ---")
    print(f"Random Forest: {rf_acc:.4f} ({rf_acc*100:.2f}%)")
    print(f"Neural Network: {nn_acc:.4f} ({nn_acc*100:.2f}%)")
    
    print("\n--- COMPARISON ---")
    if rf_acc > nn_acc:
        print(f"🏆 Random Forest performed better (+{(rf_acc - nn_acc)*100:.2f}%)")
    elif nn_acc > rf_acc:
        print(f"🏆 Neural Network performed better (+{(nn_acc - rf_acc)*100:.2f}%)")
    else:
        print("👍 Both models performed equally.")
        
    print("\n--- TARGET ACHIEVEMENT ---")
    print(f"Target: {target*100:.1f}% accuracy")
    print(f"RF: {'✅ ACHIEVED' if rf_acc >= target else '❌ NOT MET'} ({rf_acc*100:.2f}%)")
    print(f"NN: {'✅ ACHIEVED' if nn_acc >= target else '❌ NOT MET'} ({nn_acc*100:.2f}%)")
    
    if rf_acc >= target or nn_acc >= target:
        print("\n🎉 Stage 2 Target Achieved!")
    else:
        print("\n⚠️ Target not met. Review feature engineering or hyperparameters.")
    
    # Final file locations
    print("\n" + "="*70)
    print("OUTPUT FILES LOCATION")
    print("="*70)
    print(f"\n📁 All outputs saved to:")
    print(f"   Logs:    {logs_dir}/")
    print(f"   Data:    {data_dir}/")
    print(f"   Models:  {models_dir}/")
    print(f"   Results: {outputs_dir}/")
    print(f"\n✅ Files successfully saved:")
    print(f"   {rf_metrics_file}")
    print(f"   {nn_metrics_file}")
    print(f"   {test_metrics_file}")
    print(f"   {summary_file}")
    
    print("\n" + "="*70)
    print("READY FOR STAGE 3: XAI Integration (SHAP + LIME)")
    print("="*70 + "\n")
    
    logger.info("Stage 2 pipeline completed successfully")
    logger.info("="*70)

if __name__ == "__main__":
    main()