"""
GlitchForge Stage 3: Master Script
Student: U2687294 - Belal Almshmesh
Supervisor: Dr. Halima Kure

Runs complete Stage 3 XAI analysis (SHAP, LIME, Visualization, Quality Metrics)
"""

import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import logging
logging.getLogger('tensorflow').setLevel(logging.ERROR)
logging.getLogger('absl').setLevel(logging.ERROR)

import pandas as pd
import numpy as np
import pickle
from tensorflow import keras

from src.utils.config import Config
from src.utils.logger import setup_logger
from src.xai.shap_explainer import SHAPExplainer
from src.xai.lime_explainer import LIMEExplainer
from src.xai.quality_metrics import ExplanationQualityMetrics
from src.xai.visualization import ExplanationVisualizer

logger = setup_logger(__name__)
logger.propagate = False

logger.info("\n" + "="*70)
logger.info("🤖 GLITCHFORGE PROJECT: STAGE 3 XAI ANALYSIS")
logger.info("="*70)


def verify_stage2_files():
    """Verify all Stage 2 files exist before starting"""
    logger.info("\nSTAGE 3 (Step 1/7): Verifying Stage 2 Files")

    required_files = {
        'Random Forest Model': Config.RF_MODEL_PATH,
        'Neural Network Model': Config.NN_MODEL_PATH,
        'X_train': Config.X_TRAIN_PATH,
        'X_test': Config.X_TEST_PATH,
        'y_train': Config.Y_TRAIN_PATH,
        'y_test': Config.Y_TEST_PATH,
        'Feature Names': Config.PROCESSED_DATA_DIR / 'feature_names.txt'
    }

    missing_files = [name for name, path in required_files.items() if not path.exists()]

    if missing_files:
        logger.error(f"\n❌ Missing files: {', '.join(missing_files)}")
        logger.error("Please ensure you have completed Stage 2 and all paths in config.py are correct.")
        return False

    logger.info("✓ All Stage 2 files found!")
    return True


def load_stage2_data():
    """Load all Stage 2 data and models"""
    logger.info("\nSTAGE 3 (Step 2/7): Loading Stage 2 Data")

    # Load models
    with open(Config.RF_MODEL_PATH, 'rb') as f:
        rf_model = pickle.load(f)

    try:
        nn_model = keras.models.load_model(Config.NN_MODEL_PATH)
        logger.info("✓ Models loaded")
    except Exception as e:
        logger.warning(f"⚠ Could not load Neural Network: {e}")
        nn_model = None

    # Load datasets
    X_train_df = pd.read_csv(Config.X_TRAIN_PATH)
    X_test_df = pd.read_csv(Config.X_TEST_PATH)
    y_train = pd.read_csv(Config.Y_TRAIN_PATH).values.ravel()
    y_test = pd.read_csv(Config.Y_TEST_PATH).values.ravel()

    # Load feature names
    feature_names_path = Config.PROCESSED_DATA_DIR / 'feature_names.txt'
    with open(feature_names_path, 'r') as f:
        feature_names = [line.strip() for line in f if line.strip()]

    logger.info(f"✓ Data loaded: X_train {X_train_df.shape}, X_test {X_test_df.shape}, {len(feature_names)} features")

    assert X_train_df.shape[1] == len(feature_names), "Feature count mismatch!"
    assert X_test_df.shape[1] == len(feature_names), "Feature count mismatch!"

    return {
        'rf_model': rf_model,
        'nn_model': nn_model,
        'X_train': X_train_df.values,
        'X_test': X_test_df.values,
        'y_train': y_train,
        'y_test': y_test,
        'feature_names': feature_names,
        'X_test_df': X_test_df
    }


def run_random_forest_shap(rf_model, X_train, X_test, feature_names):
    """Run SHAP analysis on Random Forest model"""
    logger.info("\n--- SHAP Analysis: Random Forest ---")

    shap_explainer = SHAPExplainer(model=rf_model, feature_names=feature_names, model_type='random_forest')
    shap_explainer.create_explainer(X_train)

    base_value = shap_explainer.explainer.expected_value
    if isinstance(base_value, (list, np.ndarray)):
        base_value = base_value[1]

    logger.info(f"Calculating SHAP values for {X_test.shape[0]} samples...")
    shap_values, predictions, comp_time = shap_explainer.explain_batch(X_test)

    importance_df = shap_explainer.get_feature_importance(shap_values)
    fidelity = shap_explainer.measure_fidelity(shap_values, X_test)

    shap_explainer.save_explanations(shap_values, Config.EXPLANATIONS_DIR / 'shap' / 'shap_values_rf.npy')
    importance_df.to_csv(Config.TABLES_DIR / 'shap_importance_rf.csv', index=False)

    logger.info("✓ SHAP Random Forest complete!")

    return {
        'explainer': shap_explainer,
        'shap_values': shap_values,
        'base_value': base_value,
        'predictions': predictions,
        'importance_df': importance_df,
        'fidelity': fidelity,
        'computation_time': comp_time
    }


def run_neural_network_shap(nn_model, X_train, X_test, feature_names):
    """Run SHAP analysis on Neural Network model"""
    logger.info("\n--- SHAP Analysis: Neural Network ---")

    shap_explainer = SHAPExplainer(model=nn_model, feature_names=feature_names, model_type='neural_network')
    shap_explainer.create_explainer(X_train, method='kernel')

    base_value = shap_explainer.explainer.expected_value
    if isinstance(base_value, (list, np.ndarray)):
        base_value = base_value[1] if len(base_value) > 1 else base_value[0]

    # Use subset for NN KernelSHAP (slow)
    subset_size = min(50, len(X_test))
    X_test_subset = X_test[:subset_size]
    logger.info(f"Calculating SHAP values for {subset_size} samples (NN is slow)...")

    shap_values, predictions, comp_time = shap_explainer.explain_batch(X_test_subset, nsamples=100)

    # Extract positive class for importance calculation
    if isinstance(shap_values, list) and len(shap_values) > 1:
        shap_values_for_importance = shap_values[1]
    elif isinstance(shap_values, list) and len(shap_values) == 1:
        shap_values_for_importance = shap_values[0]
    else:
        shap_values_for_importance = shap_values

    importance_df = shap_explainer.get_feature_importance(shap_values_for_importance)
    fidelity = shap_explainer.measure_fidelity(shap_values_for_importance, X_test_subset)

    shap_explainer.save_explanations(shap_values, Config.EXPLANATIONS_DIR / 'shap' / 'shap_values_nn.npy')
    importance_df.to_csv(Config.TABLES_DIR / 'shap_importance_nn.csv', index=False)

    logger.info("✓ SHAP Neural Network complete!")

    return {
        'explainer': shap_explainer,
        'shap_values': shap_values,
        'base_value': base_value,
        'predictions': predictions,
        'importance_df': importance_df,
        'fidelity': fidelity,
        'computation_time': comp_time,
        'X_test_subset': X_test_subset
    }


def run_shap_analysis(data_dict):
    """Run SHAP on Random Forest and Neural Network models"""
    logger.info("\nSTAGE 3 (Step 3/7): Running SHAP Analysis")

    rf_results = run_random_forest_shap(
        data_dict['rf_model'], data_dict['X_train'], data_dict['X_test'], data_dict['feature_names']
    )

    nn_results = None
    if data_dict['nn_model']:
        nn_results = run_neural_network_shap(
            data_dict['nn_model'], data_dict['X_train'], data_dict['X_test'], data_dict['feature_names']
        )
    else:
        logger.warning("⚠ Neural Network model not loaded, skipping SHAP-NN.")

    return rf_results, nn_results


def run_model_lime_analysis(model, X_train, X_test_subset, feature_names, model_name):
    """Run LIME analysis on a single model"""
    logger.info(f"\n--- LIME Analysis: {model_name} ---")

    lime_explainer = LIMEExplainer(model=model, feature_names=feature_names)
    lime_explainer.create_explainer(X_train)

    explanations, comp_time = lime_explainer.explain_batch(X_test_subset, num_features=10, num_samples=1000)
    importance_df = lime_explainer.get_feature_importance(explanations)
    fidelity = lime_explainer.measure_fidelity(explanations, X_test_subset)

    # Save results
    model_suffix = 'rf' if 'Forest' in model_name else 'nn'
    lime_explainer.save_explanations(explanations, Config.EXPLANATIONS_DIR / 'lime' / f'lime_explanations_{model_suffix}.pkl')
    importance_df.to_csv(Config.TABLES_DIR / f'lime_importance_{model_suffix}.csv', index=False)

    logger.info(f"✓ LIME {model_name} complete!")

    return {
        'explainer': lime_explainer,
        'explanations': explanations,
        'importance_df': importance_df,
        'fidelity': fidelity,
        'computation_time': comp_time,
        'X_test_subset': X_test_subset
    }


def run_lime_analysis(data_dict):
    """Run LIME on Random Forest and Neural Network models"""
    logger.info("\nSTAGE 3 (Step 4/7): Running LIME Analysis")

    subset_size = min(100, len(data_dict['X_test']))
    X_test_subset = data_dict['X_test'][:subset_size]
    logger.info(f"Using subset of {subset_size} samples for LIME analysis")

    rf_results = run_model_lime_analysis(
        data_dict['rf_model'], data_dict['X_train'], X_test_subset,
        data_dict['feature_names'], 'Random Forest'
    )

    nn_results = None
    if data_dict['nn_model']:
        nn_results = run_model_lime_analysis(
            data_dict['nn_model'], data_dict['X_train'], X_test_subset,
            data_dict['feature_names'], 'Neural Network'
        )
    else:
        logger.warning("⚠ Neural Network model not loaded, skipping LIME-NN.")

    return rf_results, nn_results


def run_visualization(data_dict, all_results):
    """Generate all plots for SHAP and LIME"""
    logger.info("\nSTAGE 3 (Step 5/7): Generating Visualizations")

    visualizer = ExplanationVisualizer(data_dict['feature_names'])
    plots_dir = Config.PLOTS_DIR
    plots_dir.mkdir(parents=True, exist_ok=True)

    # SHAP-RF plots
    if 'rf_shap' in all_results:
        logger.info("Generating SHAP-RF plots...")
        res = all_results['rf_shap']
        visualizer.plot_shap_summary(res['shap_values'], data_dict['X_test_df'],
            title="SHAP Summary (Random Forest)", save_path=plots_dir / "shap_summary_rf.png")
        visualizer.plot_shap_bar(res['shap_values'], title="SHAP Feature Importance (Random Forest)",
            save_path=plots_dir / "shap_bar_rf.png")
        visualizer.plot_shap_waterfall(res['shap_values'][0], data_dict['X_test'][0], res['base_value'],
            title="SHAP Waterfall (Random Forest, Sample 0)", save_path=plots_dir / "shap_waterfall_rf_sample0.png")

    # SHAP-NN plots
    if 'nn_shap' in all_results:
        logger.info("Generating SHAP-NN plots...")
        res = all_results['nn_shap']
        visualizer.plot_shap_summary(res['shap_values'], res['X_test_subset'],
            title="SHAP Summary (Neural Network, 50 samples)", save_path=plots_dir / "shap_summary_nn.png")
        visualizer.plot_shap_bar(res['shap_values'], title="SHAP Feature Importance (Neural Network)",
            save_path=plots_dir / "shap_bar_nn.png")

    # LIME-RF plots
    if 'rf_lime' in all_results:
        logger.info("Generating LIME-RF plots...")
        res = all_results['rf_lime']
        if res['explanations']:
            exp_dict = res['explainer'].get_explanation_as_dict(res['explanations'][0])
            visualizer.plot_lime_explanation(exp_dict, title="LIME Explanation (Random Forest, Sample 0)",
                save_path=plots_dir / "lime_bar_rf_sample0.png")

    # LIME-NN plots
    if 'nn_lime' in all_results:
        logger.info("Generating LIME-NN plots...")
        res = all_results['nn_lime']
        if res['explanations']:
            exp_dict = res['explainer'].get_explanation_as_dict(res['explanations'][0])
            visualizer.plot_lime_explanation(exp_dict, title="LIME Explanation (Neural Network, Sample 0)",
                save_path=plots_dir / "lime_bar_nn_sample0.png")

    # Comparison plots
    if 'rf_shap' in all_results and 'rf_lime' in all_results:
        logger.info("Generating comparison plots...")
        visualizer.plot_shap_vs_lime_importance(all_results['rf_shap']['importance_df'],
            all_results['rf_lime']['importance_df'], title="SHAP vs LIME Importance (Random Forest)",
            save_path=plots_dir / "comparison_bar_rf.png")

    if 'nn_shap' in all_results and 'nn_lime' in all_results:
        visualizer.plot_shap_vs_lime_importance(all_results['nn_shap']['importance_df'],
            all_results['nn_lime']['importance_df'], title="SHAP vs LIME Importance (Neural Network)",
            save_path=plots_dir / "comparison_bar_nn.png")

    logger.info(f"✓ All visualizations saved to: {plots_dir}")


def run_quality_analysis(data_dict, all_results):
    """Run fidelity and consistency metrics on all explanations"""
    logger.info("\nSTAGE 3 (Step 6/7): Running Quality Analysis")

    metrics = ExplanationQualityMetrics(data_dict['feature_names'])
    master_report = []

    # SHAP-RF quality
    if 'rf_shap' in all_results:
        res = all_results['rf_shap']
        fidelity = metrics.measure_fidelity_shap(res['shap_values'], res['predictions'], res['base_value'])

        shap_vals = res['shap_values']
        if isinstance(shap_vals, list):
            shap_vals = shap_vals[1]
        elif shap_vals.ndim == 3:
            shap_vals = shap_vals[:, :, 1]

        consistency = metrics.measure_consistency(shap_vals, data_dict['X_test'])
        master_report.append({'method': 'SHAP-RF', 'metric': 'fidelity_mae', 'value': fidelity['mean_absolute_error']})
        master_report.append({'method': 'SHAP-RF', 'metric': 'consistency_mean_sim', 'value': consistency['mean_explanation_similarity']})

    # SHAP-NN quality
    if 'nn_shap' in all_results:
        res = all_results['nn_shap']
        fidelity = metrics.measure_fidelity_shap(res['shap_values'], res['predictions'], res['base_value'])

        shap_vals = res['shap_values']
        if isinstance(shap_vals, list):
            shap_vals = shap_vals[1]
        elif shap_vals.ndim == 3:
            shap_vals = shap_vals[:, :, 0] if shap_vals.shape[2] == 1 else shap_vals[:, :, 1]

        consistency = metrics.measure_consistency(shap_vals, res['X_test_subset'])
        master_report.append({'method': 'SHAP-NN', 'metric': 'fidelity_mae', 'value': fidelity['mean_absolute_error']})
        master_report.append({'method': 'SHAP-NN', 'metric': 'consistency_mean_sim', 'value': consistency['mean_explanation_similarity']})

    # LIME-RF quality
    if 'rf_lime' in all_results:
        res = all_results['rf_lime']
        lime_exps_as_dicts = [res['explainer'].get_explanation_as_dict(exp) for exp in res['explanations']]
        fidelity = metrics.measure_fidelity_lime(lime_exps_as_dicts, res['X_test_subset'], res['explainer'].predict_fn)
        lime_values = np.array([exp['weights'] for exp in lime_exps_as_dicts])
        consistency = metrics.measure_consistency(lime_values, res['X_test_subset'])
        master_report.append({'method': 'LIME-RF', 'metric': 'fidelity_r2', 'value': fidelity.get('mean_r2_score', 0)})
        master_report.append({'method': 'LIME-RF', 'metric': 'consistency_mean_sim', 'value': consistency.get('mean_explanation_similarity', 0)})

    # LIME-NN quality
    if 'nn_lime' in all_results:
        res = all_results['nn_lime']
        lime_exps_as_dicts = [res['explainer'].get_explanation_as_dict(exp) for exp in res['explanations']]
        fidelity = metrics.measure_fidelity_lime(lime_exps_as_dicts, res['X_test_subset'], res['explainer'].predict_fn)
        lime_values = np.array([exp['weights'] for exp in lime_exps_as_dicts])
        consistency = metrics.measure_consistency(lime_values, res['X_test_subset'])
        master_report.append({'method': 'LIME-NN', 'metric': 'fidelity_r2', 'value': fidelity.get('mean_r2_score', 0)})
        master_report.append({'method': 'LIME-NN', 'metric': 'consistency_mean_sim', 'value': consistency.get('mean_explanation_similarity', 0)})

    # Save report
    report_df = pd.DataFrame(master_report)
    report_path = Config.TABLES_DIR / "master_quality_report.csv"
    report_df.to_csv(report_path, index=False)
    logger.info(f"✓ Quality analysis complete! Report saved to {report_path}")

    return report_df


def generate_summary_report(all_results, quality_report):
    """Generate final summary report for the console"""
    logger.info("\nSTAGE 3 (Step 7/7): Final Summary Report")

    logger.info("\n--- SHAP ANALYSIS ---")
    if 'rf_shap' in all_results:
        res = all_results['rf_shap']
        logger.info(f"\nRandom Forest (SHAP):")
        logger.info(f"  Fidelity (MAE): {res['fidelity']:.8f}")
        logger.info(f"  Time/sample: {res['computation_time']/len(res['predictions']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")

    if 'nn_shap' in all_results:
        res = all_results['nn_shap']
        logger.info(f"\nNeural Network (SHAP):")
        logger.info(f"  Fidelity (MAE): {res['fidelity']:.6f}")
        if len(res['predictions']) > 0:
            logger.info(f"  Time/sample: {res['computation_time']/len(res['predictions']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")

    logger.info("\n--- LIME ANALYSIS ---")
    if 'rf_lime' in all_results:
        res = all_results['rf_lime']
        logger.info(f"\nRandom Forest (LIME):")
        logger.info(f"  Fidelity (Mean R²): {res['fidelity'].get('mean_r2_score', 0):.4f}")
        if len(res['explanations']) > 0:
            logger.info(f"  Time/sample: {res['computation_time']/len(res['explanations']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")

    if 'nn_lime' in all_results:
        res = all_results['nn_lime']
        logger.info(f"\nNeural Network (LIME):")
        logger.info(f"  Fidelity (Mean R²): {res['fidelity'].get('mean_r2_score', 0):.4f}")
        if len(res['explanations']) > 0:
            logger.info(f"  Time/sample: {res['computation_time']/len(res['explanations']):.4f}s")
        if not res['importance_df'].empty:
            logger.info(f"  Top feature: {res['importance_df'].iloc[0]['feature']}")

    logger.info("\n--- QUALITY METRICS ---")
    if not quality_report.empty:
        logger.info(f"\n{quality_report.to_string(index=False)}")

    logger.info("\n" + "="*70)
    logger.info("✓✓✓ GLITCHFORGE STAGE 3 COMPLETE ✓✓✓")
    logger.info("="*70)
    logger.info(f"\nAll reports saved to: {Config.TABLES_DIR}")
    logger.info(f"All plots saved to: {Config.PLOTS_DIR}")
    logger.info(f"All explanation data saved to: {Config.EXPLANATIONS_DIR}")


def main():
    """Main execution function"""
    all_results = {}

    if not verify_stage2_files():
        logger.error("\n❌ Cannot proceed without Stage 2 files!")
        return

    data_dict = load_stage2_data()

    rf_shap_results, nn_shap_results = run_shap_analysis(data_dict)
    if rf_shap_results:
        all_results['rf_shap'] = rf_shap_results
    if nn_shap_results:
        all_results['nn_shap'] = nn_shap_results

    rf_lime_results, nn_lime_results = run_lime_analysis(data_dict)
    if rf_lime_results:
        all_results['rf_lime'] = rf_lime_results
    if nn_lime_results:
        all_results['nn_lime'] = nn_lime_results

    run_visualization(data_dict, all_results)
    quality_report = run_quality_analysis(data_dict, all_results)
    generate_summary_report(all_results, quality_report)


if __name__ == "__main__":
    main()
