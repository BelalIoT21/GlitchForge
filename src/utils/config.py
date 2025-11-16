"""
Configuration settings for GlitchForge
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class Config:
    """Centralized configuration for all GlitchForge stages"""

    PROJECT_ROOT = Path(__file__).parent.parent.parent

    # Directory structure
    DATA_DIR = PROJECT_ROOT / "data"
    MODELS_DIR = PROJECT_ROOT / "models"
    OUTPUTS_DIR = PROJECT_ROOT / "outputs"
    RAW_DATA_DIR = DATA_DIR / "raw"
    PROCESSED_DATA_DIR = DATA_DIR / "processed"
    PLOTS_DIR = OUTPUTS_DIR / "plots"
    TABLES_DIR = OUTPUTS_DIR / "tables"
    EXPLANATIONS_DIR = OUTPUTS_DIR / "explanations"

    # Model and data file paths
    RF_MODEL_PATH = MODELS_DIR / "random_forest_model.pkl"
    NN_MODEL_PATH = MODELS_DIR / "neural_network_model.h5"
    X_TRAIN_PATH = PROCESSED_DATA_DIR / "X_train.csv"
    X_TEST_PATH = PROCESSED_DATA_DIR / "X_test.csv"
    Y_TRAIN_PATH = PROCESSED_DATA_DIR / "y_train.csv"
    Y_TEST_PATH = PROCESSED_DATA_DIR / "y_test.csv"

    # NVD API configuration
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT = 0.6
    NVD_CWE_FILTERS = ['CWE-89', 'CWE-79', 'CWE-352']
    NVD_START_YEAR = 2023
    NVD_END_YEAR = 2024

    # Scanner configuration (Stage 1)
    DVWA_BASE_URL = os.getenv("DVWA_URL", "http://192.168.1.127/DVWA")
    DVWA_USERNAME = "admin"
    DVWA_PASSWORD = "password"
    DVWA_SECURITY_LEVELS = ['low', 'medium', 'high']
    SCANNER_TIMEOUT = 10
    SCANNER_MAX_RETRIES = 3
    SCANNER_USER_AGENT = 'GlitchForge/1.0'

    # SQL injection test payloads
    SQL_PAYLOADS = {
        'error_based': ["'", "1' OR '1'='1", "1' OR '1'='1' --", "1' OR '1'='1' #", "' OR 1=1 --", "admin' --", "admin' #"],
        'union_based': ["1' UNION SELECT null, version() #", "1' UNION SELECT null, user() #", "1' UNION SELECT null, database() #"],
        'boolean_blind': ["1' AND '1'='1", "1' AND '1'='2"],
        'time_based': ["1' AND SLEEP(5) #", "1'; WAITFOR DELAY '00:00:05' --"]
    }

    # XSS test payloads
    XSS_PAYLOADS = {
        'basic': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg/onload=alert(1)>'],
        'encoded': ['<ScRiPt>alert(1)</ScRiPt>', '&lt;script&gt;alert(1)&lt;/script&gt;'],
        'event_handlers': ['" onload="alert(1)', "' onmouseover='alert(1)", '" autofocus onfocus="alert(1)']
    }

    # ML model configuration (Stage 2)
    RANDOM_STATE = 42
    TEST_SIZE = 0.2
    VALIDATION_SIZE = 0.15
    CV_FOLDS = 5
    RF_N_ESTIMATORS = 200
    RF_MAX_DEPTH = 6

    # XAI configuration (Stage 3)
    SHAP_BACKGROUND_SAMPLES = 100
    SHAP_MAX_DISPLAY = 10
    LIME_NUM_SAMPLES = 1000
    LIME_NUM_FEATURES = 10

    # Risk prioritization weights (Stage 4)
    RISK_WEIGHTS = {
        'cvss': 0.35,
        'exploitability': 0.25,
        'impact': 0.20,
        'ml_prediction': 0.15,
        'temporal': 0.05
    }

    RISK_THRESHOLDS = {
        'critical': 85,
        'high': 70,
        'medium': 50,
        'low': 0
    }

    RISK_ADJUSTMENTS = {
        'exploit_multiplier': 1.3,
        'product_threshold': 10,
        'product_multiplier': 1.15
    }

    # Logging configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = PROJECT_ROOT / "glitchforge.log"

    @classmethod
    def create_directories(cls):
        """Create all necessary directories"""
        for directory in [
            cls.DATA_DIR, cls.RAW_DATA_DIR, cls.PROCESSED_DATA_DIR,
            cls.MODELS_DIR, cls.OUTPUTS_DIR, cls.PLOTS_DIR,
            cls.TABLES_DIR, cls.EXPLANATIONS_DIR,
            cls.PLOTS_DIR / "shap", cls.PLOTS_DIR / "lime", cls.PLOTS_DIR / "comparisons"
        ]:
            directory.mkdir(parents=True, exist_ok=True)