"""
Utility helper functions for GlitchForge
Student: U2687294 - Bilal

Common helper functions used across all stages
"""

import pickle
import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Any, Dict, List, Union, Tuple
import logging

logger = logging.getLogger(__name__)


# ============================================
# MODEL LOADING AND SAVING
# ============================================

def load_model(model_path: Union[str, Path]) -> Any:
    """
    Load a saved model from disk
    
    Args:
        model_path: Path to model file (.pkl for sklearn, .h5 for keras)
    
    Returns:
        Loaded model object
    
    Raises:
        FileNotFoundError: If model file doesn't exist
        ValueError: If file format not supported
    """
    model_path = Path(model_path)
    
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    
    logger.info(f"Loading model from {model_path}")
    
    # Sklearn models (.pkl)
    if model_path.suffix == '.pkl':
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        logger.info(f"✓ Loaded pickle model: {type(model).__name__}")
        return model
    
    # Keras/TensorFlow models (.h5)
    elif model_path.suffix == '.h5':
        from tensorflow import keras
        model = keras.models.load_model(model_path)
        logger.info(f"✓ Loaded Keras model")
        return model
    
    else:
        raise ValueError(f"Unsupported model format: {model_path.suffix}")


def save_model(model: Any, model_path: Union[str, Path]) -> None:
    """
    Save a model to disk
    
    Args:
        model: Model object to save
        model_path: Path where to save the model
    """
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Saving model to {model_path}")
    
    # Sklearn models
    if hasattr(model, 'fit') and hasattr(model, 'predict'):
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        logger.info(f"✓ Saved sklearn model: {type(model).__name__}")
    
    # Keras models
    elif hasattr(model, 'save'):
        model.save(model_path)
        logger.info(f"✓ Saved Keras model")
    
    else:
        # Fallback to pickle
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        logger.info(f"✓ Saved model using pickle")


# ============================================
# DATA LOADING AND SAVING
# ============================================

def load_data(data_path: Union[str, Path], 
              file_type: str = 'auto') -> Union[pd.DataFrame, np.ndarray]:
    """
    Load data from various file formats
    
    Args:
        data_path: Path to data file
        file_type: 'auto', 'csv', 'npy', 'json', 'pkl'
    
    Returns:
        Loaded data (DataFrame or ndarray)
    """
    data_path = Path(data_path)
    
    if not data_path.exists():
        raise FileNotFoundError(f"Data file not found: {data_path}")
    
    # Auto-detect file type
    if file_type == 'auto':
        file_type = data_path.suffix[1:]  # Remove the dot
    
    logger.info(f"Loading {file_type} data from {data_path}")
    
    if file_type == 'csv':
        data = pd.read_csv(data_path)
        logger.info(f"✓ Loaded CSV: {data.shape}")
        return data
    
    elif file_type == 'npy':
        data = np.load(data_path)
        logger.info(f"✓ Loaded numpy array: {data.shape}")
        return data
    
    elif file_type == 'json':
        with open(data_path, 'r') as f:
            data = json.load(f)
        logger.info(f"✓ Loaded JSON")
        return data
    
    elif file_type == 'pkl' or file_type == 'pickle':
        with open(data_path, 'rb') as f:
            data = pickle.load(f)
        logger.info(f"✓ Loaded pickle data")
        return data
    
    else:
        raise ValueError(f"Unsupported file type: {file_type}")


def save_data(data: Union[pd.DataFrame, np.ndarray, Dict, List],
              data_path: Union[str, Path],
              file_type: str = 'auto') -> None:
    """
    Save data to various file formats
    
    Args:
        data: Data to save
        data_path: Path where to save
        file_type: 'auto', 'csv', 'npy', 'json', 'pkl'
    """
    data_path = Path(data_path)
    data_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Auto-detect file type from extension
    if file_type == 'auto':
        file_type = data_path.suffix[1:]
    
    logger.info(f"Saving data to {data_path} as {file_type}")
    
    if file_type == 'csv':
        if isinstance(data, pd.DataFrame):
            data.to_csv(data_path, index=False)
        elif isinstance(data, np.ndarray):
            pd.DataFrame(data).to_csv(data_path, index=False)
        else:
            raise ValueError("CSV format requires DataFrame or ndarray")
        logger.info(f"✓ Saved CSV")
    
    elif file_type == 'npy':
        np.save(data_path, data)
        logger.info(f"✓ Saved numpy array")
    
    elif file_type == 'json':
        with open(data_path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"✓ Saved JSON")
    
    elif file_type == 'pkl' or file_type == 'pickle':
        with open(data_path, 'wb') as f:
            pickle.dump(data, f)
        logger.info(f"✓ Saved pickle data")
    
    else:
        raise ValueError(f"Unsupported file type: {file_type}")


# ============================================
# RESULTS SAVING
# ============================================

def save_results(results: Dict[str, Any],
                 output_dir: Union[str, Path],
                 prefix: str = "results") -> None:
    """
    Save results dictionary to multiple formats
    
    Args:
        results: Dictionary of results to save
        output_dir: Directory where to save results
        prefix: Prefix for output files
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Saving results to {output_dir}")
    
    # Save as JSON (human-readable)
    json_path = output_dir / f"{prefix}.json"
    with open(json_path, 'w') as f:
        # Convert numpy types to native Python types for JSON
        json_results = convert_to_json_serializable(results)
        json.dump(json_results, f, indent=2)
    logger.info(f"✓ Saved JSON: {json_path}")
    
    # Save as pickle (preserves numpy arrays)
    pkl_path = output_dir / f"{prefix}.pkl"
    with open(pkl_path, 'wb') as f:
        pickle.dump(results, f)
    logger.info(f"✓ Saved pickle: {pkl_path}")
    
    # If results contain DataFrames, save as CSV
    for key, value in results.items():
        if isinstance(value, pd.DataFrame):
            csv_path = output_dir / f"{prefix}_{key}.csv"
            value.to_csv(csv_path, index=False)
            logger.info(f"✓ Saved CSV: {csv_path}")


def convert_to_json_serializable(obj: Any) -> Any:
    """
    Convert numpy types to Python native types for JSON serialization
    
    Args:
        obj: Object to convert
    
    Returns:
        JSON-serializable object
    """
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, pd.DataFrame):
        return obj.to_dict('records')
    elif isinstance(obj, dict):
        return {key: convert_to_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_json_serializable(item) for item in obj]
    else:
        return obj


# ============================================
# FEATURE NAMES HANDLING
# ============================================

def load_feature_names(file_path: Union[str, Path]) -> List[str]:
    """
    Load feature names from a text file
    
    Args:
        file_path: Path to feature names file (one name per line)
    
    Returns:
        List of feature names
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"Feature names file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        feature_names = [line.strip() for line in f if line.strip()]
    
    logger.info(f"✓ Loaded {len(feature_names)} feature names from {file_path}")
    return feature_names


def save_feature_names(feature_names: List[str],
                       file_path: Union[str, Path]) -> None:
    """
    Save feature names to a text file
    
    Args:
        feature_names: List of feature names
        file_path: Path where to save
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w') as f:
        for name in feature_names:
            f.write(f"{name}\n")
    
    logger.info(f"✓ Saved {len(feature_names)} feature names to {file_path}")


# ============================================
# DATA SPLITTING
# ============================================

def split_data(X: Union[pd.DataFrame, np.ndarray],
               y: Union[pd.Series, np.ndarray],
               test_size: float = 0.2,
               val_size: float = 0.15,
               random_state: int = 42) -> Tuple:
    """
    Split data into train, validation, and test sets
    
    Args:
        X: Features
        y: Labels
        test_size: Proportion of test set (0.0 to 1.0)
        val_size: Proportion of validation set from remaining data
        random_state: Random seed for reproducibility
    
    Returns:
        X_train, X_val, X_test, y_train, y_val, y_test
    """
    from sklearn.model_selection import train_test_split
    
    # First split: separate test set
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    # Second split: separate validation set from remaining data
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=val_size, random_state=random_state, stratify=y_temp
    )
    
    logger.info(f"Data split:")
    logger.info(f"  Train: {X_train.shape[0]} samples ({X_train.shape[0]/len(X)*100:.1f}%)")
    logger.info(f"  Val:   {X_val.shape[0]} samples ({X_val.shape[0]/len(X)*100:.1f}%)")
    logger.info(f"  Test:  {X_test.shape[0]} samples ({X_test.shape[0]/len(X)*100:.1f}%)")
    
    return X_train, X_val, X_test, y_train, y_val, y_test


# ============================================
# METRICS FORMATTING
# ============================================

def format_metrics(metrics: Dict[str, float], precision: int = 4) -> Dict[str, str]:
    """
    Format metrics dictionary with consistent precision
    
    Args:
        metrics: Dictionary of metric name -> value
        precision: Number of decimal places
    
    Returns:
        Formatted metrics dictionary
    """
    formatted = {}
    for key, value in metrics.items():
        if isinstance(value, float):
            formatted[key] = f"{value:.{precision}f}"
        else:
            formatted[key] = str(value)
    
    return formatted


def print_metrics(metrics: Dict[str, float], title: str = "Metrics") -> None:
    """
    Pretty print metrics
    
    Args:
        metrics: Dictionary of metrics
        title: Title to print
    """
    print("\n" + "="*60)
    print(f"{title}")
    print("="*60)
    
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"  {key:30s}: {value:.4f}")
        else:
            print(f"  {key:30s}: {value}")
    
    print("="*60 + "\n")


# ============================================
# FILE SYSTEM UTILITIES
# ============================================

def ensure_dir(directory: Union[str, Path]) -> Path:
    """
    Ensure directory exists, create if it doesn't
    
    Args:
        directory: Directory path
    
    Returns:
        Path object of the directory
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def list_files(directory: Union[str, Path],
               pattern: str = "*",
               recursive: bool = False) -> List[Path]:
    """
    List files in directory matching pattern
    
    Args:
        directory: Directory to search
        pattern: File pattern (e.g., "*.csv", "*.pkl")
        recursive: Search subdirectories
    
    Returns:
        List of file paths
    """
    directory = Path(directory)
    
    if not directory.exists():
        logger.warning(f"Directory does not exist: {directory}")
        return []
    
    if recursive:
        files = list(directory.rglob(pattern))
    else:
        files = list(directory.glob(pattern))
    
    logger.info(f"Found {len(files)} files matching '{pattern}' in {directory}")
    return files


# ============================================
# TIMING UTILITIES
# ============================================

import time
from contextlib import contextmanager

@contextmanager
def timer(name: str = "Operation"):
    """
    Context manager for timing code blocks
    
    Usage:
        with timer("Model training"):
            model.fit(X_train, y_train)
    """
    start_time = time.time()
    logger.info(f"{name} started...")
    
    try:
        yield
    finally:
        elapsed = time.time() - start_time
        logger.info(f"✓ {name} completed in {elapsed:.2f} seconds")


# ============================================
# ARRAY UTILITIES
# ============================================

def normalize_array(arr: np.ndarray, method: str = 'minmax') -> np.ndarray:
    """
    Normalize numpy array
    
    Args:
        arr: Array to normalize
        method: 'minmax' or 'zscore'
    
    Returns:
        Normalized array
    """
    if method == 'minmax':
        arr_min = arr.min()
        arr_max = arr.max()
        if arr_max - arr_min == 0:
            return arr
        return (arr - arr_min) / (arr_max - arr_min)
    
    elif method == 'zscore':
        mean = arr.mean()
        std = arr.std()
        if std == 0:
            return arr
        return (arr - mean) / std
    
    else:
        raise ValueError(f"Unknown normalization method: {method}")


def safe_divide(numerator: Union[float, np.ndarray],
                denominator: Union[float, np.ndarray],
                default: float = 0.0) -> Union[float, np.ndarray]:
    """
    Safe division that handles divide-by-zero
    
    Args:
        numerator: Numerator
        denominator: Denominator
        default: Value to return when denominator is zero
    
    Returns:
        Result of division or default value
    """
    with np.errstate(divide='ignore', invalid='ignore'):
        result = np.true_divide(numerator, denominator)
        if isinstance(result, np.ndarray):
            result[~np.isfinite(result)] = default
        elif not np.isfinite(result):
            result = default
    
    return result


# ============================================
# EXAMPLE USAGE
# ============================================

if __name__ == "__main__":
    """
    Example usage of helper functions
    """
    from app.config import Config
    from app.utils.logger import setup_logger
    
    # Setup logger
    logger = setup_logger(__name__)
    
    print("="*60)
    print("GlitchForge Helper Functions - Examples")
    print("="*60)
    
    # Example 1: Create and ensure directories
    print("\n1. Creating directories...")
    ensure_dir(Config.MODELS_DIR)
    ensure_dir(Config.PLOTS_DIR / "test")
    print("✓ Directories created")
    
    # Example 2: Save and load data
    print("\n2. Testing data save/load...")
    test_data = pd.DataFrame({
        'feature_1': [1, 2, 3],
        'feature_2': [4, 5, 6]
    })
    
    test_path = Config.DATA_DIR / "test_data.csv"
    save_data(test_data, test_path)
    loaded_data = load_data(test_path)
    print(f"✓ Data saved and loaded: {loaded_data.shape}")
    
    # Example 3: Format and print metrics
    print("\n3. Testing metrics formatting...")
    test_metrics = {
        'accuracy': 0.9167,
        'precision': 0.9234,
        'recall': 0.8956,
        'f1_score': 0.9093
    }
    print_metrics(test_metrics, "Test Metrics")
    
    # Example 4: Timer context manager
    print("\n4. Testing timer...")
    with timer("Sleep test"):
        time.sleep(0.5)
    
    # Example 5: List files
    print("\n5. Listing files...")
    files = list_files(Config.DATA_DIR, "*.csv")
    print(f"Found {len(files)} CSV files")
    
    print("\n" + "="*60)
    print("All helper functions working! ✓")
    print("="*60)