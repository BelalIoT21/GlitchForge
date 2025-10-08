#!/usr/bin/env python3
"""
GlitchForge - Main Application
Complete vulnerability scanning with ML prioritization
"""

import argparse
from scanners import VulnerabilityScanner
from report_generator import ReportGenerator
from config import DVWA_CONFIG

def main():
    parser = argparse.ArgumentParser(
        description='GlitchForge - Explainable AI Vulnerability Scanner'
    )
    
    parser.add_argument(
        '--target',
        default=DVWA_CONFIG['base_url'],
        help='Target URL (default: DVWA)'
    )
    
    parser.add_argument(
        '--security-level',
        choices=['low', 'medium', 'high'],
        default='low',
        help='DVWA security level (default: low)'
    )
    
    parser.add_argument(
        '--scan-type',
        choices=['all', 'sql', 'xss', 'csrf'],
        default='all',
        help='Type of scan to perform (default: all)'
    )
    
    parser.add_argument(
        '--output',
        choices=['console', 'json', 'csv', 'all'],
        default='console',
        help='Output format (default: console)'
    )
    
    args = parser.parse_args()
    
    # Initialize scanner
    print("\n" + "="*60)
    print("  GlitchForge - Explainable AI Vulnerability Scanner")
    print("  Version 1.0.0")
    print("="*60)
    
    scanner = VulnerabilityScanner(args.target)
    
    # Login to DVWA
    print(f"\n[*] Connecting to {args.target}...")
    if not scanner.login_dvwa():
        print("✗ Failed to login. Exiting.")
        return
    
    # Set security level
    if not scanner.set_security_level(args.security_level):
        print("✗ Failed to set security level. Continuing anyway...")
    
    # Perform scans
    print(f"\n[*] Starting {args.scan_type} scan...")
    
    if args.scan_type == 'all':
        results = scanner.scan_all()
    elif args.scan_type == 'sql':
        scanner.scan_sql_injection('vulnerabilities/sqli/', 'id')
        scanner.scan_sql_injection('vulnerabilities/sqli_blind/', 'id')
        results = scanner.scan_results
    elif args.scan_type == 'xss':
        scanner.scan_xss('vulnerabilities/xss_r/', 'name')
        scanner.scan_xss('vulnerabilities/xss_s/', 'txtName')
        results = scanner.scan_results
    elif args.scan_type == 'csrf':
        scanner.scan_csrf('vulnerabilities/csrf/')
        results = scanner.scan_results
    
    # Get summary
    summary = scanner.get_summary()
    
    # Generate reports
    if args.output in ['console', 'all']:
        ReportGenerator.generate_console_report(results, summary)
    
    if args.output in ['json', 'all']:
        ReportGenerator.generate_json_report(results, summary)
    
    if args.output in ['csv', 'all']:
        ReportGenerator.generate_csv_report(results)
    
    print("\n" + "="*60)
    print("  Scan Complete!")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()