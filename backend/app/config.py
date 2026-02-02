"""
GlitchForge Configuration
Single source of truth for all project settings.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Project paths - backend directory is one level up from this file
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
RAW_DATA_DIR = DATA_DIR / 'raw'
PROCESSED_DATA_DIR = DATA_DIR / 'processed'
MODELS_DIR = BASE_DIR / 'models'
OUTPUTS_DIR = BASE_DIR / 'outputs'

# Output subdirectories
PLOTS_DIR = OUTPUTS_DIR / 'plots'
TABLES_DIR = OUTPUTS_DIR / 'tables'
EXPLANATIONS_DIR = OUTPUTS_DIR / 'explanations'

# Model paths
RF_MODEL_PATH = MODELS_DIR / 'random_forest.pkl'
NN_MODEL_PATH = MODELS_DIR / 'neural_network.h5'

# Data paths
X_TRAIN_PATH = PROCESSED_DATA_DIR / 'X_train.csv'
X_TEST_PATH = PROCESSED_DATA_DIR / 'X_test.csv'
Y_TRAIN_PATH = PROCESSED_DATA_DIR / 'y_train.csv'
Y_TEST_PATH = PROCESSED_DATA_DIR / 'y_test.csv'

# Create directories if they don't exist
for directory in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# NVD API Key
NVD_API_KEY = os.getenv('NVD_API_KEY')

# DVWA Configuration
DVWA_CONFIG = {
    'base_url': 'http://192.168.1.127/DVWA',
    'username': 'admin',
    'password': 'password',
    'security_levels': ['low', 'medium', 'high']
}

# Scanner Configuration - Rebuilt for Speed and Accuracy
# New scanner design:
# - Error-based SQL detection only (fast and reliable)
# - Reflected XSS only (no DOM/stored - too slow)
# - Simple CSRF token checking
# - Smart parameter filtering (skips tracking params)
# - Maximum 10 parameters per URL
SCANNER_CONFIG = {
    'timeout': 15,
    'max_retries': 3,
    'user_agent': 'GlitchForge/2.0'
}

# Note: Payloads are now defined inside each scanner class for better encapsulation
# SQL Scanner: 4 error-based payloads (', 1', 1' OR '1'='1, 1' --)
# XSS Scanner: 4 reflected payloads with unique markers
# CSRF Scanner: Checks for tokens, SameSite cookies, and CSRF headers

# ML Configuration
ML_CONFIG = {
    'test_size': 0.2,
    'random_state': 42,
    'cv_folds': 5,
    'xgboost_params': {
        'n_estimators': 200,
        'max_depth': 6,
        'learning_rate': 0.1,
        'random_state': 42
    }
}

# SHAP Configuration
SHAP_CONFIG = {
    'background_samples': 100,
    'max_display_features': 10
}

# NVD API Configuration
NVD_CONFIG = {
    'base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    'rate_limit_delay': 0.6,  # 0.6 seconds with API key (instead of 6)
    'cwe_filters': ['CWE-89', 'CWE-79', 'CWE-352'],  # SQL, XSS, CSRF
    'start_year': 2023,
    'end_year': 2024,
    'api_key': os.getenv('NVD_API_KEY')
}

# Flask settings
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False") == "True"
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = BASE_DIR / "glitchforge.log"

# CORS origins for React frontend
CORS_ORIGINS = ["http://localhost:3000", "http://localhost:3001"]

# XAI settings
SHAP_BACKGROUND_SAMPLES = 100
LIME_NUM_SAMPLES = 1000
LIME_NUM_FEATURES = 10

# Model settings
RANDOM_STATE = 42
TEST_SIZE = 0.2
VALIDATION_SIZE = 0.15

# Scanner target URLs
DVWA_URL = os.getenv("DVWA_URL", "http://localhost/dvwa")
WEBGOAT_URL = os.getenv("WEBGOAT_URL", "http://localhost:8080/WebGoat")


class Config:
    """Configuration class for project settings (used by stage scripts)"""

    PROJECT_ROOT = BASE_DIR

    DATA_DIR = DATA_DIR
    MODELS_DIR = MODELS_DIR
    OUTPUTS_DIR = OUTPUTS_DIR
    RAW_DATA_DIR = RAW_DATA_DIR
    PROCESSED_DATA_DIR = PROCESSED_DATA_DIR
    PLOTS_DIR = PLOTS_DIR
    TABLES_DIR = TABLES_DIR
    EXPLANATIONS_DIR = EXPLANATIONS_DIR

    RF_MODEL_PATH = RF_MODEL_PATH
    NN_MODEL_PATH = NN_MODEL_PATH

    X_TRAIN_PATH = X_TRAIN_PATH
    X_TEST_PATH = X_TEST_PATH
    Y_TRAIN_PATH = Y_TRAIN_PATH
    Y_TEST_PATH = Y_TEST_PATH

    NVD_API_KEY = NVD_API_KEY
    NVD_BASE_URL = NVD_CONFIG['base_url']
    DVWA_URL = DVWA_URL
    WEBGOAT_URL = WEBGOAT_URL

    RANDOM_STATE = RANDOM_STATE
    TEST_SIZE = TEST_SIZE
    VALIDATION_SIZE = VALIDATION_SIZE

    SHAP_BACKGROUND_SAMPLES = SHAP_BACKGROUND_SAMPLES
    LIME_NUM_SAMPLES = LIME_NUM_SAMPLES
    LIME_NUM_FEATURES = LIME_NUM_FEATURES

    FLASK_DEBUG = FLASK_DEBUG
    FLASK_PORT = FLASK_PORT
    SECRET_KEY = SECRET_KEY

    LOG_LEVEL = LOG_LEVEL
    LOG_FILE = LOG_FILE

    @classmethod
    def create_directories(cls):
        """Create all necessary directories"""
        directories = [
            cls.DATA_DIR,
            cls.RAW_DATA_DIR,
            cls.PROCESSED_DATA_DIR,
            cls.MODELS_DIR,
            cls.OUTPUTS_DIR,
            cls.PLOTS_DIR,
            cls.TABLES_DIR,
            cls.EXPLANATIONS_DIR,
            cls.PLOTS_DIR / "shap",
            cls.PLOTS_DIR / "lime",
            cls.PLOTS_DIR / "comparisons"
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

        print("All directories created successfully")
