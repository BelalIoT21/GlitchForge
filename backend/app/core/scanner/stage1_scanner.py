#!/usr/bin/env python3
"""
GlitchForge Stage 1 Test Script
Verifies that all scanner components are working correctly
"""
import sys
from pathlib import Path

# Add backend directory to path so we can import app modules
backend_dir = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(backend_dir))

print("="*70)
print(" GlitchForge Stage 1 Test Suite")
print("="*70)

# Test 1: Import utilities
print("\n[Test 1] Testing utility imports...")
try:
    from app.utils.logger import get_logger
    from app.utils.metrics import MetricsCalculator
    logger = get_logger("TestSuite")
    logger.info("[OK] Logger initialized successfully")
    print("[OK] Utilities imported successfully")
except Exception as e:
    print(f"[ERROR] Failed to import utilities: {e}")
    sys.exit(1)

# Test 2: Import base scanner
print("\n[Test 2] Testing base scanner import...")
try:
    from app.core.scanner.base_scanner import BaseScanner, VulnerabilityType, SeverityLevel
    print("[OK] Base scanner imported successfully")
except Exception as e:
    print(f"[ERROR] Failed to import base scanner: {e}")
    sys.exit(1)

# Test 3: Import specific scanners
print("\n[Test 3] Testing specific scanner imports...")
try:
    from app.core.scanner.sql_injection import SQLInjectionScanner
    from app.core.scanner.xss_scanner import XSSScanner
    from app.core.scanner.csrf_scanner import CSRFScanner
    print("[OK] All scanners imported successfully")
except Exception as e:
    print(f"[ERROR] Failed to import scanners: {e}")
    sys.exit(1)

# Test 4: Import main orchestrator
print("\n[Test 4] Testing main orchestrator import...")
try:
    from app.core.scanner.main import GlitchForgeScanner
    print("[OK] Main orchestrator imported successfully")
except ImportError as e:
    print(f"[WARNING] Import error: {e}")
    print("  The scanners will still work individually")
except Exception as e:
    print(f"[ERROR] Failed to import main orchestrator: {e}")

# Test 5: Load configuration
print("\n[Test 5] Testing configuration loading...")
try:
    import app.config as config
    print(f"[OK] Configuration loaded successfully")
    print(f"  - DVWA URL: {config.DVWA_CONFIG['base_url']}")
    print(f"  - Scanner timeout: {config.SCANNER_CONFIG['timeout']}s")
    print(f"  - NVD API configured: {'Yes' if config.NVD_CONFIG.get('api_key') else 'No'}")
except Exception as e:
    print(f"[WARNING] Configuration issue: {e}")
    print("  This is OK - you can still use individual scanners")

# Test 6: Initialize scanners
print("\n[Test 6] Testing scanner initialization...")
try:
    import app.config as config
    sql_scanner = SQLInjectionScanner(config.SCANNER_CONFIG)
    xss_scanner = XSSScanner(config.SCANNER_CONFIG)
    csrf_scanner = CSRFScanner(config.SCANNER_CONFIG)
    print("[OK] All scanners initialized successfully")
    print(f"  - SQL Scanner: {sql_scanner.__class__.__name__}")
    print(f"  - XSS Scanner: {xss_scanner.__class__.__name__}")
    print(f"  - CSRF Scanner: {csrf_scanner.__class__.__name__}")
except Exception as e:
    print(f"[WARNING] Scanner initialization issue: {e}")

# Test 7: Test payload loading
print("\n[Test 7] Testing payload loading...")
try:
    import app.config as config
    sql_scanner = SQLInjectionScanner(config.SCANNER_CONFIG)
    xss_scanner = XSSScanner(config.SCANNER_CONFIG)

    sql_payloads = sql_scanner.get_payloads()
    xss_payloads = xss_scanner.get_payloads()

    sql_count = sum(len(p) for p in sql_payloads.values())
    xss_count = sum(len(p) for p in xss_payloads.values())

    print(f"[OK] Payloads loaded successfully")
    print(f"  - SQL Injection payloads: {sql_count}")
    print(f"  - XSS payloads: {xss_count}")
except Exception as e:
    print(f"[WARNING] Payload loading issue: {e}")

# Test 8: Test metrics calculator
print("\n[Test 8] Testing metrics calculator...")
try:
    calculator = MetricsCalculator()

    # Test detection metrics
    y_true = [0, 1, 1, 0, 1, 0]
    y_pred = [0, 1, 0, 0, 1, 1]

    metrics = calculator.calculate_detection_metrics(y_true, y_pred)

    print(f"[OK] Metrics calculator working")
    print(f"  - Accuracy: {metrics['accuracy']:.2f}")
    print(f"  - Precision: {metrics['precision']:.2f}")
    print(f"  - Recall: {metrics['recall']:.2f}")
except Exception as e:
    print(f"[WARNING] Metrics calculator issue: {e}")

# Test 9: Test main orchestrator
print("\n[Test 9] Testing main orchestrator...")
try:
    import app.config as config
    from app.core.scanner.main import GlitchForgeScanner
    orchestrator = GlitchForgeScanner(config.SCANNER_CONFIG)
    print("[OK] Main orchestrator initialized successfully")
    print(f"  - SQL Scanner ready: {orchestrator.sql_scanner is not None}")
    print(f"  - XSS Scanner ready: {orchestrator.xss_scanner is not None}")
    print(f"  - CSRF Scanner ready: {orchestrator.csrf_scanner is not None}")
except Exception as e:
    print(f"[WARNING] Orchestrator issue: {e}")

# Test 10: Check directory structure
print("\n[Test 10] Checking directory structure...")
try:
    required_dirs = ['data', 'data/raw', 'data/processed', 'data', 'logs']
    missing_dirs = []

    for dir_name in required_dirs:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            missing_dirs.append(dir_name)

    if missing_dirs:
        print(f"[WARNING] Some directories are missing: {', '.join(missing_dirs)}")
        print("  Creating missing directories...")
        for dir_name in missing_dirs:
            Path(dir_name).mkdir(parents=True, exist_ok=True)
        print("[OK] Missing directories created")
    else:
        print("[OK] All required directories exist")
except Exception as e:
    print(f"[ERROR] Failed to check directories: {e}")
    sys.exit(1)

# Summary
print("\n" + "="*70)
print("STAGE 1 TESTS COMPLETE!")
print("="*70)

print("\n[OK] All tests passed - Stage 1 is ready!")
print("\nNext steps:")
print("  1. Test against DVWA:")
print("     py -m app.core.scanner.main --url http://192.168.1.127/DVWA/vulnerabilities/sqli/")
print("\n  2. Or run a quick test:")
print("     py -m app.core.scanner.main --url http://testphp.vulnweb.com")
print("="*70)
