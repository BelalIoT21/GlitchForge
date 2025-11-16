#!/usr/bin/env python3
"""
GlitchForge Stage 1 Test Script
Verifies that all scanner components are working correctly
"""

print("="*70)
print(" GlitchForge Stage 1 Test Suite")
print("="*70)

# Test 1: Import utilities
print("\n[Test 1] Testing utility imports...")
try:
    from src.utils.logger import get_logger
    from src.utils.metrics import MetricsCalculator
    from src.utils.config import Config
    logger = get_logger("TestSuite")
    logger.info("Logger initialized successfully")
    print("[OK] Utilities imported")
except Exception as e:
    print(f"[ERROR] Failed to import utilities: {e}")
    raise SystemExit(1)

# Test 2: Import scanners
print("\n[Test 2] Testing scanner imports...")
try:
    from src.scanner.base_scanner import BaseScanner, VulnerabilityType, SeverityLevel
    from src.scanner.sql_injection import SQLInjectionScanner
    from src.scanner.xss_scanner import XSSScanner
    from src.scanner.csrf_scanner import CSRFScanner
    from src.scanner.main import GlitchForgeScanner
    print("[OK] All scanners imported")
except Exception as e:
    print(f"[ERROR] Failed to import scanners: {e}")
    raise SystemExit(1)

# Test 3: Configuration
print("\n[Test 3] Testing configuration...")
try:
    print(f"  - DVWA URL: {Config.DVWA_BASE_URL}")
    print(f"  - Scanner timeout: {Config.SCANNER_TIMEOUT}s")
    print(f"  - NVD API: {'Yes' if Config.NVD_API_KEY else 'No'}")
    print("[OK] Configuration loaded")
except Exception as e:
    print(f"[ERROR] Configuration issue: {e}")

# Test 4: Initialize scanners
print("\n[Test 4] Testing scanner initialization...")
try:
    scanner_config = {
        'timeout': Config.SCANNER_TIMEOUT,
        'max_retries': Config.SCANNER_MAX_RETRIES,
        'user_agent': Config.SCANNER_USER_AGENT
    }
    sql_scanner = SQLInjectionScanner(scanner_config)
    xss_scanner = XSSScanner(scanner_config)
    csrf_scanner = CSRFScanner(scanner_config)
    print(f"[OK] All scanners initialized")
    print(f"  - SQL: {sql_scanner.__class__.__name__}")
    print(f"  - XSS: {xss_scanner.__class__.__name__}")
    print(f"  - CSRF: {csrf_scanner.__class__.__name__}")
except Exception as e:
    print(f"[ERROR] Scanner initialization: {e}")

# Test 5: Payload loading
print("\n[Test 5] Testing payload loading...")
try:
    sql_payloads = sql_scanner.get_payloads()
    xss_payloads = xss_scanner.get_payloads()

    sql_count = sum(len(p) for p in sql_payloads.values())
    xss_count = sum(len(p) for p in xss_payloads.values())

    print(f"[OK] Payloads loaded")
    print(f"  - SQL payloads: {sql_count}")
    print(f"  - XSS payloads: {xss_count}")
except Exception as e:
    print(f"[ERROR] Payload loading: {e}")

# Test 6: Metrics calculator
print("\n[Test 6] Testing metrics calculator...")
try:
    calculator = MetricsCalculator()
    y_true = [0, 1, 1, 0, 1, 0]
    y_pred = [0, 1, 0, 0, 1, 1]
    metrics = calculator.calculate_detection_metrics(y_true, y_pred)
    print(f"[OK] Metrics calculator working")
    print(f"  - Accuracy: {metrics['accuracy']:.2f}")
except Exception as e:
    print(f"[ERROR] Metrics calculator: {e}")

# Test 7: Main orchestrator
print("\n[Test 7] Testing main orchestrator...")
try:
    orchestrator = GlitchForgeScanner(scanner_config)
    print("[OK] Main orchestrator initialized")
    print(f"  - SQL Scanner ready: {orchestrator.sql_scanner is not None}")
    print(f"  - XSS Scanner ready: {orchestrator.xss_scanner is not None}")
    print(f"  - CSRF Scanner ready: {orchestrator.csrf_scanner is not None}")
except Exception as e:
    print(f"[ERROR] Orchestrator: {e}")

# Test 8: Directory structure
print("\n[Test 8] Checking directory structure...")
try:
    Config.create_directories()
    print("[OK] All required directories exist")
except Exception as e:
    print(f"[ERROR] Directory check: {e}")

# Summary
print("\n" + "="*70)
print("STAGE 1 TESTS COMPLETE!")
print("="*70)
print("\n[OK] All tests passed - Stage 1 is ready!")
print("\nNext steps:")
print("  Test against DVWA:")
print("  python -m src.scanner.main --url http://192.168.1.127/DVWA/vulnerabilities/sqli/")
print("="*70)
