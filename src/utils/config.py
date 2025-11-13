"""
Configuration settings for GlitchForge
"""

import os
from pathlib import Path

class Config:
    """Configuration class for project settings"""
    
    # Project root
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    
    # Directories
    DATA_DIR = PROJECT_ROOT / "data"
    MODELS_DIR = PROJECT_ROOT / "models"
    OUTPUTS_DIR = PROJECT_ROOT / "outputs"
    
    # Data subdirectories
    RAW_DATA_DIR = DATA_DIR / "raw"
    PROCESSED_DATA_DIR = DATA_DIR / "processed"
    
    # Output subdirectories
    PLOTS_DIR = OUTPUTS_DIR / "plots"
    TABLES_DIR = OUTPUTS_DIR / "tables"
    EXPLANATIONS_DIR = OUTPUTS_DIR / "explanations"
    
    # Model paths
    RF_MODEL_PATH = MODELS_DIR / "random_forest_model.pkl"
    NN_MODEL_PATH = MODELS_DIR / "neural_network_model.h5"
    
    # Data paths
    X_TRAIN_PATH = PROCESSED_DATA_DIR / "X_train.csv"
    X_TEST_PATH = PROCESSED_DATA_DIR / "X_test.csv"
    Y_TRAIN_PATH = PROCESSED_DATA_DIR / "y_train.csv"
    Y_TEST_PATH = PROCESSED_DATA_DIR / "y_test.csv"
    
    # NVD API settings
    NVD_API_KEY = os.getenv("NVD_API_KEY", None)
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Scanner settings (Stage 1)
    DVWA_URL = os.getenv("DVWA_URL", "http://localhost/dvwa")
    WEBGOAT_URL = os.getenv("WEBGOAT_URL", "http://localhost:8080/WebGoat")
    
    # Model settings (Stage 2)
    RANDOM_STATE = 42
    TEST_SIZE = 0.2
    VALIDATION_SIZE = 0.15
    
    # XAI settings (Stage 3)
    SHAP_BACKGROUND_SAMPLES = 100
    LIME_NUM_SAMPLES = 1000
    LIME_NUM_FEATURES = 10
    
    # Dashboard settings (Stage 4)
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False") == "True"
    FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = PROJECT_ROOT / "glitchforge.log"
    
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
        
        print("✓ All directories created successfully")