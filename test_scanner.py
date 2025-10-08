#!/usr/bin/env python3
"""
Test script for GlitchForge scanner
"""

from scanners import VulnerabilityScanner
from report_generator import ReportGenerator

def test_basic_scan():
    """Test basic scanning functionality"""
    
    print("\n" + "="*60)
    print("  GlitchForge - Test Suite")
    print("="*60)
    
    # Initialize scanner
    scanner = VulnerabilityScanner("http://192.168.1.127/DVWA")
    
    # Test login
    print("\n[TEST 1] Testing login...")
    if scanner.login_dvwa():
        print("✓ Login test passed")
    else:
        print("✗ Login test failed")
        return
    
    # Test security level
    print("\n[TEST 2] Testing security level setting...")
    if scanner.set_security_level('low'):
        print("✓ Security level test passed")
    else:
        print("✗ Security level test failed")
    
    # Test SQL injection scan
    print("\n[TEST 3] Testing SQL injection scanner...")
    sql_result = scanner.scan_sql_injection('vulnerabilities/sqli/', 'id')
    if sql_result:
        print(f"✓ SQL injection scan completed")
        print(f"  Vulnerable: {sql_result['vulnerable']}")
        print(f"  Confidence: {sql_result['confidence']}")
    else:
        print("✗ SQL injection scan failed")
    
    # Test XSS scan
    print("\n[TEST 4] Testing XSS scanner...")
    xss_result = scanner.scan_xss('vulnerabilities/xss_r/', 'name')
    if xss_result:
        print(f"✓ XSS scan completed")
        print(f"  Vulnerable: {xss_result['vulnerable']}")
        print(f"  Confidence: {xss_result['confidence']}")
    else:
        print("✗ XSS scan failed")
    
    # Test CSRF scan
    print("\n[TEST 5] Testing CSRF scanner...")
    csrf_result = scanner.scan_csrf('vulnerabilities/csrf/')
    if csrf_result:
        print(f"✓ CSRF scan completed")
        print(f"  Vulnerable: {csrf_result['vulnerable']}")
        print(f"  Forms analyzed: {csrf_result['forms_analyzed']}")
    else:
        print("✗ CSRF scan failed")
    
    # Test report generation
    print("\n[TEST 6] Testing report generation...")
    summary = scanner.get_summary()
    ReportGenerator.generate_console_report(scanner.scan_results, summary)
    print("✓ Report generation test passed")
    
    print("\n" + "="*60)
    print("  All Tests Complete!")
    print("="*60 + "\n")

if __name__ == "__main__":
    test_basic_scan()