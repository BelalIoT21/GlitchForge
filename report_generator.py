"""
Report Generator for GlitchForge
Generates detailed vulnerability reports
"""

from typing import Dict, List
from datetime import datetime
import json

class ReportGenerator:
    """Generate vulnerability scan reports"""
    
    @staticmethod
    def generate_console_report(scan_results: List[Dict], summary: Dict):
        """Generate detailed console report"""
        
        print("\n" + "="*60)
        print("  SCAN RESULTS SUMMARY")
        print("="*60)
        
        print(f"\nTotal Scans: {summary['total_scans']}")
        print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
        print(f"  • High Confidence: {summary['high_confidence']}")
        print(f"  • Medium Confidence: {summary['medium_confidence']}")
        print(f"  • Low Confidence: {summary['low_confidence']}")
        
        print(f"\nBy Type:")
        print(f"  • SQL Injection: {summary['by_type']['sql_injection']}")
        print(f"  • XSS: {summary['by_type']['xss']}")
        print(f"  • CSRF: {summary['by_type']['csrf']}")
        
        # Detailed results
        print("\n" + "="*60)
        print("  DETAILED RESULTS")
        print("="*60)
        
        for idx, result in enumerate(scan_results, 1):
            ReportGenerator._print_vulnerability_detail(idx, result)
    
    @staticmethod
    def _print_vulnerability_detail(idx: int, result: Dict):
        """Print detailed information for a single vulnerability"""
        
        status_symbol = "⚠️ VULNERABLE" if result['vulnerable'] else "✓ SECURE"
        
        print(f"\n[{idx}] {result['vulnerability_type']}")
        print(f"    Endpoint: {result['endpoint']}")
        print(f"    Status: {status_symbol}")
        print(f"    Confidence: {result['confidence'].upper()}")
        
        if result['vulnerable']:
            print(f"    CWE ID: {result['cwe_id']}")
            
            if result['scan_type'] == 'sql_injection':
                print(f"    Successful Payloads: {len(result['successful_payloads'])}")
                for payload in result['successful_payloads'][:3]:  # Show first 3
                    print(f"      • [{payload['type']}] {payload['payload'][:50]}...")
            
            elif result['scan_type'] == 'xss':
                print(f"    XSS Type: {result.get('xss_type', 'unknown')}")
                print(f"    Successful Payloads: {len(result['successful_payloads'])}")
                for payload in result['successful_payloads'][:3]:
                    print(f"      • [{payload['type']}] {payload['payload'][:50]}...")
            
            elif result['scan_type'] == 'csrf':
                print(f"    Forms Analyzed: {result['forms_analyzed']}")
                print(f"    Vulnerable Forms: {len(result['vulnerable_forms'])}")
                for form in result['vulnerable_forms']:
                    print(f"      • Action: {form['action']}")
                    print(f"        Method: {form['method']}")
                    print(f"        Issues: {', '.join(form['issues'])}")
    
    @staticmethod
    def generate_json_report(scan_results: List[Dict], summary: Dict, filename: str = None):
        """Generate JSON report"""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"glitchforge_scan_{timestamp}.json"
        
        report = {
            'scan_metadata': {
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'scanner_name': 'GlitchForge'
            },
            'summary': summary,
            'results': scan_results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✓ JSON report saved to: {filename}")
        
        return filename
    
    @staticmethod
    def generate_csv_report(scan_results: List[Dict], filename: str = None):
        """Generate CSV report for ML processing"""
        import csv
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"glitchforge_scan_{timestamp}.csv"
        
        headers = [
            'endpoint', 'vulnerability_type', 'cwe_id', 'vulnerable',
            'confidence', 'scan_type', 'successful_payloads_count'
        ]
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for result in scan_results:
                row = {
                    'endpoint': result['endpoint'],
                    'vulnerability_type': result['vulnerability_type'],
                    'cwe_id': result['cwe_id'],
                    'vulnerable': result['vulnerable'],
                    'confidence': result['confidence'],
                    'scan_type': result['scan_type'],
                    'successful_payloads_count': len(result.get('successful_payloads', []))
                }
                writer.writerow(row)
        
        print(f"✓ CSV report saved to: {filename}")
        
        return filename