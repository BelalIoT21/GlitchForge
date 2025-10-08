"""
NVD Data Collector - Debug version to see what's actually available
"""

import requests
import time
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pathlib import Path
from tqdm import tqdm
from collections import Counter

class NVDDataCollectorSimple:
    """Collector that fetches vulnerabilities from NVD API 2.0"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        
        if api_key is None:
            try:
                import sys
                sys.path.insert(0, str(Path(__file__).parent.parent))
                from config import NVD_CONFIG
                api_key = NVD_CONFIG.get('api_key')
            except:
                pass
        
        self.api_key = api_key
        self.rate_limit_delay = 0.6 if api_key else 6
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GlitchForge/1.0',
            'Accept': 'application/json'
        })
        
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            print(f"[✓] Using NVD API key (rate limit: {self.rate_limit_delay}s)")
    
    def analyze_available_cwes(self, sample_size: int = 1000) -> Dict:
        """Analyze what CWEs are actually in the database"""
        
        print(f"\n[*] Analyzing {sample_size} recent CVEs to see available CWEs...")
        
        all_cwes = Counter()
        vulnerabilities_with_cvss = []
        start_index = 0
        results_per_page = 100
        
        with tqdm(total=sample_size, desc="  Analyzing", unit="CVE") as pbar:
            while len(vulnerabilities_with_cvss) < sample_size:
                try:
                    params = {
                        'resultsPerPage': results_per_page,
                        'startIndex': start_index
                    }
                    
                    response = self.session.get(self.base_url, params=params, timeout=30)
                    
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    
                    if 'vulnerabilities' not in data:
                        break
                    
                    for vuln_data in data['vulnerabilities']:
                        vuln = self._extract_vulnerability_info(vuln_data)
                        
                        if vuln:
                            vulnerabilities_with_cvss.append(vuln)
                            
                            for cwe in vuln.get('cwe_ids', []):
                                all_cwes[cwe] += 1
                            
                            pbar.update(1)
                    
                    start_index += results_per_page
                    time.sleep(self.rate_limit_delay)
                    
                except Exception as e:
                    print(f"\n✗ Error: {e}")
                    break
        
        print(f"\n✓ Analyzed {len(vulnerabilities_with_cvss)} CVEs")
        print(f"\n" + "="*60)
        print("  Top 20 Most Common CWEs in Recent CVEs")
        print("="*60)
        
        for cwe, count in all_cwes.most_common(20):
            percentage = (count / len(vulnerabilities_with_cvss)) * 100
            print(f"  {cwe:<15} {count:>4} ({percentage:>5.1f}%)")
        
        return {
            'vulnerabilities': vulnerabilities_with_cvss,
            'cwe_distribution': all_cwes
        }
    
    def fetch_any_vulnerabilities(self, count: int = 900) -> List[Dict]:
        """Fetch ANY vulnerabilities with CVSS scores (no CWE filter)"""
        
        print(f"\n[*] Fetching {count} recent vulnerabilities with CVSS scores...")
        
        vulnerabilities = []
        start_index = 0
        results_per_page = 100
        
        with tqdm(total=count, desc="  Fetching", unit="vuln") as pbar:
            while len(vulnerabilities) < count:
                try:
                    params = {
                        'resultsPerPage': results_per_page,
                        'startIndex': start_index
                    }
                    
                    response = self.session.get(self.base_url, params=params, timeout=30)
                    
                    if response.status_code != 200:
                        break
                    
                    data = response.json()
                    
                    if start_index == 0:
                        print(f"\n    ✓ Connected to NVD")
                    
                    if 'vulnerabilities' not in data:
                        break
                    
                    for vuln_data in data['vulnerabilities']:
                        if len(vulnerabilities) >= count:
                            break
                        
                        vuln = self._extract_vulnerability_info(vuln_data)
                        
                        if vuln:
                            vulnerabilities.append(vuln)
                            pbar.update(1)
                    
                    start_index += results_per_page
                    time.sleep(self.rate_limit_delay)
                    
                except Exception as e:
                    print(f"\n✗ Error: {e}")
                    break
        
        print(f"\n✓ Collected {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities
    
    def fetch_by_cwe(self, cwe_ids: List[str], max_per_cwe: int = 300) -> List[Dict]:
        """Fetch vulnerabilities for specific CWE types"""
        
        print(f"\n⚠️  Specific CWE filtering is not finding results.")
        print(f"    This is likely because:")
        print(f"    1. Recent CVEs don't have CWE classifications yet")
        print(f"    2. Those specific CWEs are rare")
        print(f"\n    Recommendation: Use fetch_any_vulnerabilities() instead")
        
        return []
    
    def _extract_vulnerability_info(self, vuln_data: Dict) -> Optional[Dict]:
        """Extract vulnerability information"""
        
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            # Get CVSS v3
            metrics = cve.get('metrics', {})
            cvss_v3 = None
            
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']
            
            if not cvss_v3:
                return None
            
            # Get CWE
            weaknesses = cve.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        value = desc.get('value', '')
                        if value.startswith('CWE-'):
                            cwe_ids.append(value)
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Dates
            published = cve.get('published', '')
            modified = cve.get('lastModified', '')
            
            # Days since disclosure
            try:
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                days_since_disclosure = (datetime.now(timezone.utc) - pub_date).days
            except:
                days_since_disclosure = 0
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cwe_ids': cwe_ids,
                'published_date': published,
                'modified_date': modified,
                'days_since_disclosure': days_since_disclosure,
                'cvss_v3': {
                    'base_score': cvss_v3.get('baseScore', 0),
                    'base_severity': cvss_v3.get('baseSeverity', 'UNKNOWN'),
                    'attack_vector': cvss_v3.get('attackVector', 'UNKNOWN'),
                    'attack_complexity': cvss_v3.get('attackComplexity', 'UNKNOWN'),
                    'privileges_required': cvss_v3.get('privilegesRequired', 'UNKNOWN'),
                    'user_interaction': cvss_v3.get('userInteraction', 'UNKNOWN'),
                    'scope': cvss_v3.get('scope', 'UNKNOWN'),
                    'confidentiality_impact': cvss_v3.get('confidentialityImpact', 'UNKNOWN'),
                    'integrity_impact': cvss_v3.get('integrityImpact', 'UNKNOWN'),
                    'availability_impact': cvss_v3.get('availabilityImpact', 'UNKNOWN')
                }
            }
            
        except:
            return None
    
    def save_to_file(self, vulnerabilities: List[Dict], filename: str = None):
        """Save to file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nvd_vulnerabilities_{timestamp}.json"
        
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from config import RAW_DATA_DIR
        
        filepath = RAW_DATA_DIR / filename
        
        with open(filepath, 'w') as f:
            json.dump(vulnerabilities, f, indent=2)
        
        print(f"\n✓ Data saved to: {filepath}")
        return str(filepath)
    
    def load_from_file(self, filename: str) -> List[Dict]:
        """Load from file"""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from config import RAW_DATA_DIR
        
        filepath = RAW_DATA_DIR / filename
        
        with open(filepath, 'r') as f:
            vulnerabilities = json.load(f)
        
        print(f"✓ Loaded {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from config import NVD_CONFIG
    
    print("\n" + "="*60)
    print("  GlitchForge Real NVD Data Collection")
    print("="*60)
    
    collector = NVDDataCollectorSimple(api_key=NVD_CONFIG.get('api_key'))
    
    # First, analyze what's actually available
    print("\n[Option 1] Analyze CWE distribution first")
    print("[Option 2] Just fetch 900 recent vulnerabilities")
    
    choice = input("\nChoose option (1 or 2): ").strip()
    
    if choice == '1':
        # Analyze first
        result = collector.analyze_available_cwes(sample_size=1000)
        
        print("\n" + "="*60)
        print("  Do you want to fetch these 1000 analyzed CVEs?")
        print("="*60)
        
        if input("\nSave these? (y/n): ").lower() == 'y':
            vulnerabilities = result['vulnerabilities']
            filepath = collector.save_to_file(vulnerabilities, 'nvd_real_data.json')
            print(f"\n✓ Saved {len(vulnerabilities)} vulnerabilities")
    
    else:
        # Just fetch 900
        vulnerabilities = collector.fetch_any_vulnerabilities(900)
        
        if vulnerabilities:
            filepath = collector.save_to_file(vulnerabilities, 'nvd_real_data.json')
            
            # Show statistics
            cwe_dist = Counter()
            for v in vulnerabilities:
                for cwe in v.get('cwe_ids', []):
                    cwe_dist[cwe] += 1
            
            print("\n" + "="*60)
            print("  Statistics")
            print("="*60)
            print(f"\nTotal: {len(vulnerabilities)}")
            print(f"\nTop 10 CWEs:")
            for cwe, count in cwe_dist.most_common(10):
                print(f"  {cwe}: {count}")
    
    print("\n✓ Collection complete!")