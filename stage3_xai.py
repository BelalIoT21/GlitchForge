"""
GlitchForge Stage 3: Master Script
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

RUNS THE COMPLETE STAGE 3 ANALYSIS (SHAP, LIME, VIZ, QUALITY)
This is the only script you need to run for Stage 3.
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
import pandas as pd
import numpy as np
import pickle
import shap
from tensorflow import keras

# -----------------------------------------------------------------
# 1. IMPORTS
# -----------------------------------------------------------------

# Import project utils
from src.utils.config import Config
from src.utils.logger import setup_logger

# Import all XAI components
from src.xai.shap_explainer import SHAPExplainer
from src.xai.lime_explainer import LIMEExplainer
from src.xai.quality_metrics import ExplanationQualityMetrics
from src.xai.visualization import ExplanationVisualizer

# Setup logging
logger = setup_logger(__name__)
logger.propagate = False # Stop duplicate logging


# TITLE HEADER
logger.info("\n" + "="*70)
logger.info("🤖 GLITCHFORGE PROJECT: STAGE 3 XAI ANALYSIS")
logger.info("="*70)

# -----------------------------------------------------------------
# 2. FILE VERIFICATION & DATA LOADING
# -----------------------------------------------------------------

def verify_stage2_files():
    """
    Verify all Stage 2 files exist before starting
    """
    logger.info("="*70)
    logger.info("STAGE 3 (Step 1/7): Verifying Stage 2 Files")
    logger.info("="*70)
    
    required_files = {
        'Random Forest Model': Config.RF_MODEL_PATH,
        'Neural Network Model': Config.NN_MODEL_PATH,
        'X_train': Config.X_TRAIN_PATH,
        'X_test': Config.X_TEST_PATH,
        'y_train': Config.Y_TRAIN_PATH,
        'y_test': Config.Y_TEST_PATH,
        'Feature Names': Config.PROCESSED_DATA_DIR / 'feature_names.txt'
    }
    
    missing_files = []
    
    for name, path in required_files.items():
        if path.exists():
            logger.info(f"✓ {name}: {path}")
        else:
            logger.error(f"✗ {name}: NOT FOUND at {path}")
            missing_files.append(name)
    
    if missing_files:
        logger.error(f"\n❌ Missing files: {', '.join(missing_files)}")
        logger.error("Please ensure you have completed Stage 2 and all paths in config.py are correct.")
        return False
    
    logger.info("\n✓ All Stage 2 files found!")
    return True


def load_stage2_data():
    """
    Load all Stage 2 data and models
    """
    logger.info("\n" + "="*70)
    logger.info("STAGE 3 (Step 2/7): Loading Stage 2 Data")
    logger.info("="*70)
    
    # Load models
    logger.info("\n1. Loading models...")
    
    with open(Config.RF_MODEL_PATH, 'rb') as f:
        rf_model = pickle.load(f)
    logger.info(f"✓ Random Forest: {Config.RF_MODEL_PATH}")
    
    try:
        nn_model = keras.models.load_model(Config.NN_MODEL_PATH)
        logger.info(f"✓ Neural Network: {Config.NN_MODEL_PATH}")
    except Exception as e:
        logger.warning(f"⚠ Could not load Neural Network: {e}")
        nn_model = None
    
    # Load data
    logger.info("\n2. Loading datasets...")
    
    X_train_df = pd.read_csv(Config.X_TRAIN_PATH)
    X_test_df = pd.read_csv(Config.X_TEST_PATH)
    y_train = pd.read_csv(Config.Y_TRAIN_PATH).values.ravel()
    y_test = pd.read_csv(Config.Y_TEST_PATH).values.ravel()
    
    logger.info(f"✓ X_train: {X_train_df.shape}")
    logger.info(f"✓ X_test: {X_test_df.shape}")
    logger.info(f"✓ y_train: {y_train.shape}")
    logger.info(f"✓ y_test: {y_test.shape}")
    
    # Load feature names
    logger.info("\n3. Loading feature names...")
    
    feature_names_path = Config.PROCESSED_DATA_DIR / 'feature_names.txt'
    with open(feature_names_path, 'r') as f:
        feature_names = [line.strip() for line in f if line.strip()]
    
    logger.info(f"✓ Loaded {len(feature_names)} features")
    
    # Verify dimensions match
    assert X_train_df.shape[1] == len(feature_names), "Feature count mismatch!"
    assert X_test_df.shape[1] == len(feature_names), "Feature count mismatch!"
    
    logger.info("\n✓ All data loaded successfully!")
    
    return {
        'rf_model': rf_model,
        'nn_model': nn_model,
        'X_train': X_train_df.values,
        'X_test': X_test_df.values,
        'y_train': y_train,
        'y_test': y_test,
        'feature_names': feature_names,
        'X_test_df': X_test_df # Keep dataframe for SHAP summary plot
    }

# -----------------------------------------------------------------
# 3. SHAP ANALYSIS
# -----------------------------------------------------------------

def run_shap_analysis(data_dict):
    """
    Run SHAP on Random Forest and Neural Network models
    """
    logger.info("\n" + "="*70)
    logger.info("STAGE 3 (Step 3/7): Running SHAP Analysis")
    logger.info("="*70)

    X_train = data_dict['X_train']
    X_test = data_dict['X_test']

    # --- Run SHAP on Random Forest ---
    logger.info("\n--- SHAP Analysis: Random Forest ---")
    rf_model = data_dict['rf_model']

    shap_explainer_rf = SHAPExplainer(
        model=rf_model,
        feature_names=data_dict['feature_names'],
        model_type='random_forest'
    )

    shap_explainer_rf.create_explainer(X_train)

    # Get base value
    base_value_rf = shap_explainer_rf.explainer.expected_value
    if isinstance(base_value_rf, (list, np.ndarray)):
        base_value_rf = base_value_rf[1] # Positive class

    logger.info(f"Calculating SHAP values for {X_test.shape[0]} samples...")
    shap_values_rf, predictions_rf, comp_time_rf = shap_explainer_rf.explain_batch(X_test)

    importance_df_rf = shap_explainer_rf.get_feature_importance(shap_values_rf)
    fidelity_rf = shap_explainer_rf.measure_fidelity(shap_values_rf, X_test)

    # Save results
    shap_explainer_rf.save_explanations(shap_values_rf, Config.EXPLANATIONS_DIR / 'shap' / 'shap_values_rf.npy')
    importance_df_rf.to_csv(Config.TABLES_DIR / 'shap_importance_rf.csv', index=False)

    rf_results = {
        'explainer': shap_explainer_rf, # Save explainer
        'shap_values': shap_values_rf,
        'base_value': base_value_rf,
        'predictions': predictions_rf,
        'importance_df': importance_df_rf,
        'fidelity': fidelity_rf,
        'computation_time': comp_time_rf
    }
    logger.info("✓ SHAP Random Forest complete!")

    # --- Run SHAP on Neural Network ---
    logger.info("\n--- SHAP Analysis: Neural Network ---")
    nn_results = None
    if data_dict['nn_model']:
        nn_results = _extracted_from_run_shap_analysis_54(data_dict)
    else:
        logger.warning("⚠ Neural Network model not loaded, skipping SHAP-NN.")

    return rf_results, nn_results


# TODO Rename this here and in `run_shap_analysis`
def _extracted_from_run_shap_analysis_54(data_dict):
    nn_model = data_dict['nn_model']

    shap_explainer_nn = SHAPExplainer(
        model=nn_model,
        feature_names=data_dict['feature_names'],
        model_type='neural_network'
    )

    shap_explainer_nn.create_explainer(data_dict['X_train'], method='kernel')

    # Get base value
    base_value_nn = shap_explainer_nn.explainer.expected_value
    if isinstance(base_value_nn, (list, np.ndarray)):
        # Use index 1 if it exists, otherwise 0 (most robust handling of NN logit output)
        base_value_nn = base_value_nn[1] if len(base_value_nn) > 1 else base_value_nn[0] 

    # Use a subset for NN KernelSHAP (it's very slow)
    subset_size = min(50, len(data_dict['X_test']))
    X_test_subset = data_dict['X_test'][:subset_size]
    logger.info(f"Calculating SHAP values for {subset_size} samples (NN is slow)...")

    shap_values_nn, predictions_nn, comp_time_nn = shap_explainer_nn.explain_batch(
        X_test_subset, nsamples=100
    )

    # --- FIX: Ensure the positive class array is pulled correctly for importance calc ---
    if isinstance(shap_values_nn, list) and len(shap_values_nn) > 1:
        shap_values_for_importance = shap_values_nn[1]
    elif isinstance(shap_values_nn, list) and len(shap_values_nn) == 1:
        shap_values_for_importance = shap_values_nn[0]
    else:
         shap_values_for_importance = shap_values_nn

    importance_df_nn = shap_explainer_nn.get_feature_importance(shap_values_for_importance)
    fidelity_nn = shap_explainer_nn.measure_fidelity(shap_values_for_importance, X_test_subset)

    # Save results
    shap_explainer_nn.save_explanations(shap_values_nn, Config.EXPLANATIONS_DIR / 'shap' / 'shap_values_nn.npy')
    importance_df_nn.to_csv(Config.TABLES_DIR / 'shap_importance_nn.csv', index=False)

    result = {
        'explainer': shap_explainer_nn,
        'shap_values': shap_values_nn,  # NOTE: This is the LIST/3D array, used by visualization later
        'base_value': base_value_nn,
        'predictions': predictions_nn,
        'importance_df': importance_df_nn,
        'fidelity': fidelity_nn,
        'computation_time': comp_time_nn,
        'X_test_subset': X_test_subset,
    }
    logger.info("✓ SHAP Neural Network complete!")
    return result

# -----------------------------------------------------------------
# 4. LIME ANALYSIS
# -----------------------------------------------------------------

def run_lime_analysis(data_dict):
    """
    Run LIME on Random Forest and Neural Network models
    """
    logger.info("\n" + "="*70)
    logger.info("STAGE 3 (Step 4/7): Running LIME Analysis")
    logger.info("="*70)
    
    X_train = data_dict['X_train']
    X_test = data_dict['X_test']
    
    # Use a subset for LIME (faster than KernelSHAP, but still slow)
    subset_size = min(100, len(X_test))
    X_test_subset = X_test[:subset_size]
    logger.info(f"Using a subset of {subset_size} samples for LIME analysis.")

    # --- Run LIME on Random Forest ---
    logger.info("\n--- LIME Analysis: Random Forest ---")
    rf_model = data_dict['rf_model']
    
    lime_explainer_rf = LIMEExplainer(
        model=rf_model,
        feature_names=data_dict['feature_names']
    )
    
    lime_explainer_rf.create_explainer(X_train)
    
    explanations_rf, comp_time_rf = lime_explainer_rf.explain_batch(
        X_test_subset, num_features=10, num_samples=1000
    )
    
    importance_df_rf = lime_explainer_rf.get_feature_importance(explanations_rf)
    fidelity_rf = lime_explainer_rf.measure_fidelity(explanations_rf, X_test_subset)
    
    # Save results
    lime_explainer_rf.save_explanations(explanations_rf, Config.EXPLANATIONS_DIR / 'lime' / 'lime_explanations_rf.pkl')
    importance_df_rf.to_csv(Config.TABLES_DIR / 'lime_importance_rf.csv', index=False)
    
    rf_results = {
        'explainer': lime_explainer_rf, # Save explainer
        'explanations': explanations_rf,
        'importance_df': importance_df_rf,
        'fidelity': fidelity_rf,
        'computation_time': comp_time_rf,
        'X_test_subset': X_test_subset
    }
    logger.info("✓ LIME Random Forest complete!")

    # --- Run LIME on Neural Network ---
    logger.info("\n--- LIME Analysis: Neural Network ---")
    nn_results = None
    if data_dict['nn_model']:
        nn_model = data_dict['nn_model']
        
        lime_explainer_nn = LIMEExplainer(
            model=nn_model,
            feature_names=data_dict['feature_names']
        )
        
        lime_explainer_nn.create_explainer(X_train)
        
        explanations_nn, comp_time_nn = lime_explainer_nn.explain_batch(
            X_test_subset, num_features=10, num_samples=1000
        )
        
        importance_df_nn = lime_explainer_nn.get_feature_importance(explanations_nn)
        fidelity_nn = lime_explainer_nn.measure_fidelity(explanations_nn, X_test_subset)
        
        # Save results
        lime_explainer_nn.save_explanations(explanations_nn, Config.EXPLANATIONS_DIR / 'lime' / 'lime_explanations_nn.pkl')
        importance_df_nn.to_csv(Config.TABLES_DIR / 'lime_importance_nn.csv', index=False)
        
        nn_results = {
            'explainer': lime_explainer_nn, # Save explainer
            'explanations': explanations_nn,
            'importance_df': importance_df_nn,
            'fidelity': fidelity_nn,
            'computation_time': comp_time_nn,
            'X_test_subset': X_test_subset
        }
        logger.info("✓ LIME Neural Network complete!")
    else:
        logger.warning("⚠ Neural Network model not loaded, skipping LIME-NN.")

    return rf_results, nn_results

# -----------------------------------------------------------------
# 5. VISUALIZATION
# -----------------------------------------------------------------

def run_visualization(data_dict, all_results):
    """
    Generate all plots for SHAP and LIME
    """
    logger.info("\n" + "="*70)
    logger.info("STAGE 3 (Step 5/7): Generating Visualizations")
    logger.info("="*70)
    
    visualizer = ExplanationVisualizer(data_dict['feature_names'])
    plots_dir = Config.PLOTS_DIR
    plots_dir.mkdir(parents=True, exist_ok=True)
    
    # --- SHAP-RF Plots ---
    if 'rf_shap' in all_results:
        logger.info("\nGenerating SHAP-RF plots...")
        res = all_results['rf_shap']
        visualizer.plot_shap_summary(
            res['shap_values'], data_dict['X_test_df'], 
            title="SHAP Summary (Random Forest)",
            save_path=plots_dir / "shap_summary_rf.png"
        )
        visualizer.plot_shap_bar(
            res['shap_values'], title="SHAP Feature Importance (Random Forest)",
            save_path=plots_dir / "shap_bar_rf.png"
        )
        visualizer.plot_shap_waterfall(
            res['shap_values'][0], data_dict['X_test'][0], res['base_value'],
            title="SHAP Waterfall (Random Forest, Sample 0)",
            save_path=plots_dir / "shap_waterfall_rf_sample0.png"
        )
    
    # --- SHAP-NN Plots ---
    if 'nn_shap' in all_results:
        logger.info("\nGenerating SHAP-NN plots...")
        res = all_results['nn_shap']
        visualizer.plot_shap_summary(
            res['shap_values'], res['X_test_subset'], 
            title="SHAP Summary (Neural Network, 50 samples)",
            save_path=plots_dir / "shap_summary_nn.png"
        )
        visualizer.plot_shap_bar(
            res['shap_values'], title="SHAP Feature Importance (Neural Network)",
            save_path=plots_dir / "shap_bar_nn.png"
        )
    
    # --- LIME-RF Plots ---
    if 'rf_lime' in all_results:
        logger.info("\nGenerating LIME-RF plots...")
        res = all_results['rf_lime']
        if res['explanations']:
            explainer_rf = res['explainer']
            exp_dict_rf = explainer_rf.get_explanation_as_dict(res['explanations'][0])
            visualizer.plot_lime_explanation(
                exp_dict_rf, # Pass the dict, not the Explanation object
                title="LIME Explanation (Random Forest, Sample 0)",
                save_path=plots_dir / "lime_bar_rf_sample0.png"
            )

    # --- LIME-NN Plots ---
    if 'nn_lime' in all_results:
        logger.info("\nGenerating LIME-NN plots...")
        res = all_results['nn_lime']
        if res['explanations']:
            explainer_nn = res['explainer']
            exp_dict_nn = explainer_nn.get_explanation_as_dict(res['explanations'][0])
            visualizer.plot_lime_explanation(
                exp_dict_nn, # Pass the dict, not the Explanation object
                title="LIME Explanation (Neural Network, Sample 0)",
                save_path=plots_dir / "lime_bar_nn_sample0.png"
            )

    # --- Comparison Plots ---
    logger.info("\nGenerating comparison plots...")
    if 'rf_shap' in all_results and 'rf_lime' in all_results:
        visualizer.plot_shap_vs_lime_importance(
            all_results['rf_shap']['importance_df'],
            all_results['rf_lime']['importance_df'],
            title="SHAP vs LIME Importance (Random Forest)",
            save_path=plots_dir / "comparison_bar_rf.png"
        )
    
    if 'nn_shap' in all_results and 'nn_lime' in all_results:
        visualizer.plot_shap_vs_lime_importance(
            all_results['nn_shap']['importance_df'],
            all_results['nn_lime']['importance_df'],
            title="SHAP vs LIME Importance (Neural Network)",
            save_path=plots_dir / "comparison_bar_nn.png"
        )
    
    logger.info(f"\n✓ All visualizations saved to: {plots_dir}")

# -----------------------------------------------------------------
# 6. QUALITY ANALYSIS
# -----------------------------------------------------------------

def run_quality_analysis(data_dict, all_results):
    """
    Run fidelity and consistency metrics on all explanations
    """
    logger.info("\n" + "="*70)
    logger.info("STAGE 3 (Step 6/7): Running Quality Analysis")
    logger.info("="*70)
    
    metrics = ExplanationQualityMetrics(data_dict['feature_names'])
    master_report = []

    # --- SHAP-RF Quality ---
    if 'rf_shap' in all_results:
        logger.info("\nAnalyzing SHAP-RF quality...")
        res = all_results['rf_shap']
        fidelity = metrics.measure_fidelity_shap(
            res['shap_values'], res['predictions'], res['base_value']
        )
        
        # Handle SHAP value format for consistency
        shap_vals_rf_cons = res['shap_values']
        if isinstance(shap_vals_rf_cons, list): shap_vals_rf_cons = shap_vals_rf_cons[1]
        elif shap_vals_rf_cons.ndim == 3: shap_vals_rf_cons = shap_vals_rf_cons[:,:,1]

        consistency = metrics.measure_consistency(shap_vals_rf_cons, data_dict['X_test'])
        master_report.append({'method': 'SHAP-RF', 'metric': 'fidelity_mae', 'value': fidelity['mean_absolute_error']})
        master_report.append({'method': 'SHAP-RF', 'metric': 'consistency_mean_sim', 'value': consistency['mean_explanation_similarity']})

    # --- SHAP-NN Quality ---
    if 'nn_shap' in all_results:
        logger.info("\nAnalyzing SHAP-NN quality...")
        res = all_results['nn_shap']
        fidelity = metrics.measure_fidelity_shap(
            res['shap_values'], res['predictions'], res['base_value']
        )
        
        # Handle SHAP value format for consistency
        shap_vals_nn_cons = res['shap_values']
        if isinstance(shap_vals_nn_cons, list): shap_vals_nn_cons = shap_vals_nn_cons[1]
        elif shap_vals_nn_cons.ndim == 3:
            shap_vals_nn_cons = shap_vals_nn_cons[:,:,0] if shap_vals_nn_cons.shape[2] == 1 else shap_vals_nn_cons[:,:,1]

        consistency = metrics.measure_consistency(shap_vals_nn_cons, res['X_test_subset'])
        master_report.append({'method': 'SHAP-NN', 'metric': 'fidelity_mae', 'value': fidelity['mean_absolute_error']})
        master_report.append({'method': 'SHAP-NN', 'metric': 'consistency_mean_sim', 'value': consistency['mean_explanation_similarity']})

    # --- LIME-RF Quality ---
    if 'rf_lime' in all_results:
        logger.info("\nAnalyzing LIME-RF quality...")
        res = all_results['rf_lime']
        
        # 1. Convert explanations from objects to dicts
        lime_explainer_rf = res['explainer']
        lime_exps_as_dicts = [lime_explainer_rf.get_explanation_as_dict(exp) for exp in res['explanations']]
        
        # 2. Pass the dicts and the *wrapped* predict_fn
        fidelity = metrics.measure_fidelity_lime(
            lime_exps_as_dicts, res['X_test_subset'], lime_explainer_rf.predict_fn
        )

        # Convert LIME explanations to a plain np.array for consistency check
        lime_values_rf = np.array([exp['weights'] for exp in lime_exps_as_dicts]) # Use dicts
        consistency = metrics.measure_consistency(lime_values_rf, res['X_test_subset'])
        
        master_report.append({'method': 'LIME-RF', 'metric': 'fidelity_r2', 'value': fidelity.get('mean_r2_score', 0)})
        master_report.append({'method': 'LIME-RF', 'metric': 'consistency_mean_sim', 'value': consistency.get('mean_explanation_similarity', 0)})
        
    # --- LIME-NN Quality ---
    if 'nn_lime' in all_results:
        logger.info("\nAnalyzing LIME-NN quality...")
        res = all_results['nn_lime']
        
        # 1. Convert explanations from objects to dicts
        lime_explainer_nn = res['explainer']
        lime_exps_as_dicts_nn = [lime_explainer_nn.get_explanation_as_dict(exp) for exp in res['explanations']]
            
        # 2. Pass the dicts and the *wrapped* predict_fn
        fidelity = metrics.measure_fidelity_lime(
            lime_exps_as_dicts_nn, res['X_test_subset'], lime_explainer_nn.predict_fn
        )
        
        lime_values_nn = np.array([exp['weights'] for exp in lime_exps_as_dicts_nn]) # Use dicts
        consistency = metrics.measure_consistency(lime_values_nn, res['X_test_subset'])
        
        master_report.append({'method': 'LIME-NN', 'metric': 'fidelity_r2', 'value': fidelity.get('mean_r2_score', 0)})
        master_report.append({'method': 'LIME-NN', 'metric': 'consistency_mean_sim', 'value': consistency.get('mean_explanation_similarity', 0)})

    # Save final report
    report_df = pd.DataFrame(master_report)
    report_path = Config.TABLES_DIR / "master_quality_report.csv"
    report_df.to_csv(report_path, index=False)
    
    logger.info(f"\n✓ Quality analysis complete! Report saved to {report_path}")
    return report_df

# -----------------------------------------------------------------
# 7. FINAL SUMMARY
# -----------------------------------------------------------------

def generate_summary_report(all_results, quality_report):
    """
    Generate a final summary report for the console
    """
    logger.info("\n" + "="*70)
    logger.info("STAGE 3 (Step 7/7): Final Summary Report")
    logger.info("="*70)
    
    # --- SHAP Summary ---
    logger.info("\n--- SHAP ANALYSIS ---")
    if 'rf_shap' in all_results:
        res = all_results['rf_shap']
        logger.info("\nRandom Forest (SHAP):")
        logger.info(f"  Fidelity (MAE): {res['fidelity']:.8f}")
        logger.info(f"  Time/sample: {res['computation_time']/len(res['predictions']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")
    
    if 'nn_shap' in all_results:
        res = all_results['nn_shap']
        logger.info("\nNeural Network (SHAP):")
        logger.info(f"  Fidelity (MAE): {res['fidelity']:.6f}")
        if len(res['predictions']) > 0:
            logger.info(f"  Time/sample: {res['computation_time']/len(res['predictions']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")

    # --- LIME Summary ---
    logger.info("\n--- LIME ANALYSIS ---")
    if 'rf_lime' in all_results:
        res = all_results['rf_lime']
        logger.info("\nRandom Forest (LIME):")
        logger.info(f"  Fidelity (Mean R²): {res['fidelity'].get('mean_r2_score', 0):.4f}")
        if len(res['explanations']) > 0:
            logger.info(f"  Time/sample: {res['computation_time']/len(res['explanations']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")
    
    if 'nn_lime' in all_results:
        res = all_results['nn_lime']
        logger.info("\nNeural Network (LIME):")
        logger.info(f"  Fidelity (Mean R²): {res['fidelity'].get('mean_r2_score', 0):.4f}")
        if len(res['explanations']) > 0:
            logger.info(f"  Time/sample: {res['computation_time']/len(res['explanations']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")

    # --- Quality Summary ---
    logger.info("\n--- QUALITY METRICS ---")
    if not quality_report.empty:
        logger.info(f"\n{quality_report.to_string(index=False)}")
    else:
        logger.info("\nNo quality metrics were generated.")
    
    logger.info("\n" + "="*70)
    logger.info("✓✓✓ GLITCHFORGE STAGE 3 COMPLETE ✓✓✓")
    logger.info("="*70)
    logger.info(f"\nAll reports saved to: {Config.TABLES_DIR}")
    logger.info(f"All plots saved to: {Config.PLOTS_DIR}")
    logger.info(f"All explanation data saved to: {Config.EXPLANATIONS_DIR}")


# -----------------------------------------------------------------
# MAIN EXECUTION
# -----------------------------------------------------------------

def main():
    """
    Main execution function
    """
    all_results = {}
    
    # Step 1: Verify files
    if not verify_stage2_files():
        logger.error("\n❌ Cannot proceed without Stage 2 files!")
        return
    
    # Step 2: Load data
    data_dict = load_stage2_data()
    
    # Step 3: Run SHAP
    rf_shap_results, nn_shap_results = run_shap_analysis(data_dict)
    if rf_shap_results: all_results['rf_shap'] = rf_shap_results
    if nn_shap_results: all_results['nn_shap'] = nn_shap_results
    
    # Step 4: Run LIME
    rf_lime_results, nn_lime_results = run_lime_analysis(data_dict)
    if rf_lime_results: all_results['rf_lime'] = rf_lime_results
    if nn_lime_results: all_results['nn_lime'] = nn_lime_results
    
    # Step 5: Run Visualization
    run_visualization(data_dict, all_results)
    
    # Step 6: Run Quality Analysis
    quality_report = run_quality_analysis(data_dict, all_results)
    
    # Step 7: Generate summary
    generate_summary_report(all_results, quality_report)


if __name__ == "__main__":
    main()