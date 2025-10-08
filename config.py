"""
GlitchForge Configuration
"""
import os
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
RAW_DATA_DIR = DATA_DIR / 'raw'
PROCESSED_DATA_DIR = DATA_DIR / 'processed'
MODELS_DIR = DATA_DIR / 'models'

# Create directories if they don't exist
for directory in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# DVWA Configuration
DVWA_CONFIG = {
    'base_url': 'http://192.168.1.127/DVWA',
    'username': 'admin',
    'password': 'password',
    'security_levels': ['low', 'medium', 'high']
}

# Scanner Configuration
SCANNER_CONFIG = {
    'timeout': 10,
    'max_retries': 3,
    'user_agent': 'GlitchForge/1.0'
}

# SQL Injection Payloads
SQL_PAYLOADS = {
    'error_based': [
        "'",
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "1' OR '1'='1' #",
        "' OR 1=1 --",
        "admin' --",
        "admin' #",
    ],
    'union_based': [
        "1' UNION SELECT null, version() #",
        "1' UNION SELECT null, user() #",
        "1' UNION SELECT null, database() #",
    ],
    'boolean_blind': [
        "1' AND '1'='1",
        "1' AND '1'='2",
    ],
    'time_based': [
        "1' AND SLEEP(5) #",
        "1'; WAITFOR DELAY '00:00:05' --",
    ]
}

# XSS Payloads
XSS_PAYLOADS = {
    'basic': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
    ],
    'encoded': [
        '<ScRiPt>alert(1)</ScRiPt>',
        '&lt;script&gt;alert(1)&lt;/script&gt;',
    ],
    'event_handlers': [
        '" onload="alert(1)',
        "' onmouseover='alert(1)",
        '" autofocus onfocus="alert(1)',
    ]
}

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
    'api_key': 'd34953fb-9354-4924-a975-09db76588fce'  # Your NVD API key
}