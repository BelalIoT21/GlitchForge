"""
GlitchForge Main Scanner
Orchestrates all vulnerability scanners (SQL Injection, XSS, CSRF)
"""
import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from .sql_injection import SQLInjectionScanner
from .xss_scanner import XSSScanner
from .csrf_scanner import CSRFScanner
from ..utils.logger import get_logger


class GlitchForgeScanner:
    """
    Main scanner orchestrator for GlitchForge
    Coordinates all vulnerability scanners
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize GlitchForge scanner
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = get_logger("GlitchForge")
        
        # Initialize individual scanners
        self.sql_scanner = SQLInjectionScanner(config)
        self.xss_scanner = XSSScanner(config)
        self.csrf_scanner = CSRFScanner(config)
        
        self.all_results = []
        self.scan_summary = {
            'target_url': None,
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'total_vulnerabilities': 0,
            'by_type': {
                'sql_injection': 0,
                'xss': 0,
                'csrf': 0
            },
            'by_severity': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
    
    def scan_all(
        self,
        url: str,
        scan_types: List[str] = None,
        parameters: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Run all vulnerability scanners on target URL
        
        Args:
            url: Target URL to scan
            scan_types: List of scan types to run (default: all)
            parameters: Parameters to test (auto-discover if None)
            
        Returns:
            List of all vulnerability results
        """
        self.scan_summary['target_url'] = url
        self.scan_summary['start_time'] = datetime.now()
        
        self.logger.info("="*70)
        self.logger.info(f"Starting GlitchForge Scan on: {url}")
        self.logger.info("="*70)
        
        # Default to all scan types
        if scan_types is None:
            scan_types = ['sql', 'xss', 'csrf']
        
        # Run SQL Injection scan
        if 'sql' in scan_types or 'sqli' in scan_types:
            self.logger.info("\n[1/3] Running SQL Injection Scanner...")
            self.logger.info("-" * 70)
            
            try:
                sql_results = self.sql_scanner.scan(url, parameters=parameters)
                self.all_results.extend(sql_results)
                self.scan_summary['by_type']['sql_injection'] = len(sql_results)
                
                self.logger.info(f"SQL Injection scan complete: {len(sql_results)} vulnerabilities found")
            except Exception as e:
                self.logger.error(f"✗ SQL Injection scan failed: {str(e)}")
        
        # Run XSS scan
        if 'xss' in scan_types:
            self.logger.info("\n[2/3] Running XSS Scanner...")
            self.logger.info("-" * 70)
            
            try:
                xss_results = self.xss_scanner.scan(url, parameters=parameters)
                self.all_results.extend(xss_results)
                self.scan_summary['by_type']['xss'] = len(xss_results)
                
                self.logger.info(f"XSS scan complete: {len(xss_results)} vulnerabilities found")
            except Exception as e:
                self.logger.error(f"✗ XSS scan failed: {str(e)}")
        
        # Run CSRF scan
        if 'csrf' in scan_types:
            self.logger.info("\n[3/3] Running CSRF Scanner...")
            self.logger.info("-" * 70)
            
            try:
                csrf_results = self.csrf_scanner.scan(url)
                self.all_results.extend(csrf_results)
                self.scan_summary['by_type']['csrf'] = len(csrf_results)
                
                self.logger.info(f"CSRF scan complete: {len(csrf_results)} vulnerabilities found")
            except Exception as e:
                self.logger.error(f"✗ CSRF scan failed: {str(e)}")
        
        # Calculate summary statistics
        self.scan_summary['end_time'] = datetime.now()
        self.scan_summary['duration'] = (
            self.scan_summary['end_time'] - self.scan_summary['start_time']
        ).total_seconds()
        self.scan_summary['total_vulnerabilities'] = len(self.all_results)
        
        # Count by severity
        for result in self.all_results:
            severity = result.severity.value.lower()
            self.scan_summary['by_severity'][severity] += 1
        
        # Print summary
        self._print_summary()
        
        return [result.to_dict() for result in self.all_results]
    
    def _print_summary(self):
        """Print scan summary to console"""
        self.logger.info("\n" + "="*70)
        self.logger.info("SCAN SUMMARY")
        self.logger.info("="*70)
        
        summary = self.scan_summary
        
        self.logger.info(f"Target URL: {summary['target_url']}")
        self.logger.info(f"Scan Duration: {summary['duration']:.2f} seconds")
        self.logger.info(f"Total Vulnerabilities: {summary['total_vulnerabilities']}")
        
        self.logger.info("\nVulnerabilities by Type:")
        self.logger.info(f"  - SQL Injection: {summary['by_type']['sql_injection']}")
        self.logger.info(f"  - XSS: {summary['by_type']['xss']}")
        self.logger.info(f"  - CSRF: {summary['by_type']['csrf']}")
        
        self.logger.info("\nVulnerabilities by Severity:")
        self.logger.info(f"  - Critical: {summary['by_severity']['critical']}")
        self.logger.info(f"  - High: {summary['by_severity']['high']}")
        self.logger.info(f"  - Medium: {summary['by_severity']['medium']}")
        self.logger.info(f"  - Low: {summary['by_severity']['low']}")
        self.logger.info(f"  - Info: {summary['by_severity']['info']}")
        
        self.logger.info("="*70)
    
    def export_results(
        self,
        output_file: str = None,
        format: str = 'json'
    ) -> str:
        """
        Export scan results to file
        
        Args:
            output_file: Output file path (auto-generated if None)
            format: Output format ('json', 'html', 'csv')
            
        Returns:
            Path to output file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"glitchforge_scan_{timestamp}.{format}"
        
        output_path = Path(output_file)
        
        if format == 'json':
            data = {
                'summary': {
                    'target_url': self.scan_summary['target_url'],
                    'start_time': self.scan_summary['start_time'].isoformat(),
                    'end_time': self.scan_summary['end_time'].isoformat(),
                    'duration': self.scan_summary['duration'],
                    'total_vulnerabilities': self.scan_summary['total_vulnerabilities'],
                    'by_type': self.scan_summary['by_type'],
                    'by_severity': self.scan_summary['by_severity']
                },
                'vulnerabilities': [result.to_dict() for result in self.all_results]
            }
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        elif format == 'html':
            html_content = self._generate_html_report()
            with open(output_path, 'w') as f:
                f.write(html_content)
        
        elif format == 'csv':
            import csv
            
            if self.all_results:
                with open(output_path, 'w', newline='') as f:
                    fieldnames = list(self.all_results[0].to_dict().keys())
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for result in self.all_results:
                        writer.writerow(result.to_dict())
        
        self.logger.info(f"\nResults exported to: {output_path}")
        return str(output_path)
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>GlitchForge Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .vulnerability {{ background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #e74c3c; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ border-left-color: #8B0000; }}
        .high {{ border-left-color: #e74c3c; }}
        .medium {{ border-left-color: #f39c12; }}
        .low {{ border-left-color: #3498db; }}
        .info {{ border-left-color: #95a5a6; }}
        h1, h2, h3 {{ margin: 0 0 10px 0; }}
        .severity {{ display: inline-block; padding: 5px 10px; color: white; border-radius: 3px; font-weight: bold; }}
        .severity.critical {{ background-color: #8B0000; }}
        .severity.high {{ background-color: #e74c3c; }}
        .severity.medium {{ background-color: #f39c12; }}
        .severity.low {{ background-color: #3498db; }}
        .severity.info {{ background-color: #95a5a6; }}
        code {{ background-color: #ecf0f1; padding: 2px 5px; border-radius: 3px; }}
        pre {{ background-color: #ecf0f1; padding: 10px; border-radius: 3px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>GlitchForge Vulnerability Scan Report</h1>
        <p>Target: {self.scan_summary['target_url']}</p>
        <p>Scan Date: {self.scan_summary['start_time'].strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p><strong>Duration:</strong> {self.scan_summary['duration']:.2f} seconds</p>
        <p><strong>Total Vulnerabilities:</strong> {self.scan_summary['total_vulnerabilities']}</p>
        
        <h3>By Type:</h3>
        <ul>
            <li>SQL Injection: {self.scan_summary['by_type']['sql_injection']}</li>
            <li>XSS: {self.scan_summary['by_type']['xss']}</li>
            <li>CSRF: {self.scan_summary['by_type']['csrf']}</li>
        </ul>
        
        <h3>By Severity:</h3>
        <ul>
            <li><span class="severity critical">Critical</span> {self.scan_summary['by_severity']['critical']}</li>
            <li><span class="severity high">High</span> {self.scan_summary['by_severity']['high']}</li>
            <li><span class="severity medium">Medium</span> {self.scan_summary['by_severity']['medium']}</li>
            <li><span class="severity low">Low</span> {self.scan_summary['by_severity']['low']}</li>
            <li><span class="severity info">Info</span> {self.scan_summary['by_severity']['info']}</li>
        </ul>
    </div>
    
    <h2>🐛 Vulnerabilities Found</h2>
"""
        
        for i, vuln in enumerate(self.all_results, 1):
            severity_class = vuln.severity.value.lower()
            html += f"""
    <div class="vulnerability {severity_class}">
        <h3>[{i}] {vuln.vuln_type.value}</h3>
        <p><span class="severity {severity_class}">{vuln.severity.value}</span> 
           <strong>Confidence:</strong> {vuln.confidence:.0%} 
           <strong>CWE:</strong> {vuln.cwe_id}</p>
        
        <p><strong>URL:</strong> <code>{vuln.url}</code></p>
        <p><strong>Parameter:</strong> <code>{vuln.parameter}</code></p>
        <p><strong>Payload:</strong> <code>{vuln.payload[:100]}{'...' if len(vuln.payload) > 100 else ''}</code></p>
        
        <h4>Description:</h4>
        <p>{vuln.description}</p>
        
        <h4>Evidence:</h4>
        <pre>{vuln.evidence[:200]}{'...' if len(vuln.evidence) > 200 else ''}</pre>
        
        <h4>Remediation:</h4>
        <pre>{vuln.remediation}</pre>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html


def main():
    """Command-line interface for GlitchForge"""
    parser = argparse.ArgumentParser(
        description='GlitchForge - Explainable AI Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.scanner.main --url http://target.com
  python -m src.scanner.main --url http://target.com --types sql xss
  python -m src.scanner.main --url http://target.com --output report.json
  python -m src.scanner.main --url http://192.168.1.127/DVWA --security low
        """
    )
    
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--types', nargs='+', choices=['sql', 'xss', 'csrf', 'all'],
                       default=['all'], help='Vulnerability types to scan for')
    parser.add_argument('--parameters', nargs='+', help='Specific parameters to test')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'html', 'csv'], default='json',
                       help='Output format')
    parser.add_argument('--security', choices=['low', 'medium', 'high'],
                       help='DVWA security level (for DVWA testing)')
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        from config import SCANNER_CONFIG
    except ImportError:
        print("Error: config.py not found. Please create configuration file.")
        sys.exit(1)
    
    # Initialize scanner
    scanner = GlitchForgeScanner(SCANNER_CONFIG)
    
    # Determine scan types
    scan_types = args.types
    if 'all' in scan_types:
        scan_types = ['sql', 'xss', 'csrf']
    
    # Run scan
    try:
        results = scanner.scan_all(
            url=args.url,
            scan_types=scan_types,
            parameters=args.parameters
        )
        
        # Export results
        if args.output or len(results) > 0:
            output_file = scanner.export_results(
                output_file=args.output,
                format=args.format
            )
            print(f"\nResults saved to: {output_file}")
        
        # Exit code based on results
        sys.exit(0 if len(results) == 0 else 1)
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()