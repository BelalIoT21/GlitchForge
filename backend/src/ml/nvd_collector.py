"""
NVD Data Collector - Stage 2
Collects vulnerability data from National Vulnerability Database API v2.0
Target: 15,000 CVE records from 2018-2024
"""

import requests
import time
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
from pathlib import Path
from requests.exceptions import RequestException

class NVDCollector:
    """Collects vulnerability data from NVD API v2.0"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD collector
        """
        self.api_key = api_key
        self.session = requests.Session()
        
        # API v2.0 requires API key in HEADER
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.rate_limit = 0.6  # 100 requests per 60 seconds with key
        else:
            self.rate_limit = 6.0  # 10 requests per 60 seconds without key
            
        self.logger = logging.getLogger(__name__)
        
    def collect_cves(
        self,
        start_date: str,
        end_date: str,
        target_count: int,
        keywords: Optional[List[str]] = None
    ) -> pd.DataFrame:
        """
        Collect CVE records from NVD in 120-day chunks (NVD API v2.0 limitation).
        """
        self.logger.info(f"Starting CVE collection: {start_date} to {end_date}")
        self.logger.info(f"Target: {target_count} records")
        
        all_cves = []
        
        # Convert string dates to datetime
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        
        # Split into 120-day chunks (NVD API v2.0 limitation)
        current_start = start_dt
        # Use 119 days to be safe, ensuring each chunk is <= 120 days inclusive
        chunk_days = 119 
        
        while current_start < end_dt and len(all_cves) < target_count:
            # Calculate chunk end date (max 120 days)
            current_end = min(current_start + timedelta(days=chunk_days), end_dt)
            
            # Format dates for logging and API call
            start_date_str = current_start.strftime("%Y-%m-%d")
            end_date_str = current_end.strftime("%Y-%m-%d")
            
            self.logger.info(f"\nCollecting chunk: {start_date_str} to {end_date_str}")
            
            # Collect CVEs for this date range
            chunk_cves = self._collect_date_range(
                start_date_str,
                end_date_str,
                target_count - len(all_cves),
                keywords
            )
            
            all_cves.extend(chunk_cves)
            self.logger.info(f"Total collected: {len(all_cves)}/{target_count}")
            
            # Move to next chunk
            current_start = current_end + timedelta(days=1)
            
            if len(all_cves) >= target_count:
                break
        
        df = pd.DataFrame(all_cves)
        self.logger.info(f"Collection complete: {len(df)} CVEs collected")
        
        return df
    
    def _collect_date_range(
        self,
        start_date: str,
        end_date: str,
        remaining_count: int,
        keywords: Optional[List[str]] = None
    ) -> List[Dict]:
        """Collect CVEs for a specific date range (max 120 days)"""
        
        cves = []
        results_per_page = 2000  # Max allowed by API
        start_index = 0
        
        while len(cves) < remaining_count:
            # NVD API v2.0 ISO 8601 format (This format is critical for 404 avoidance)
            # Using 'lastMod' dates as in your original code
            params = {
                'lastModStartDate': f"{start_date}T00:00:00.000Z", # Added 'Z' for UTC
                'lastModEndDate': f"{end_date}T23:59:59.999Z",     # Added 'Z' for UTC
                'resultsPerPage': min(results_per_page, remaining_count - len(cves)),
                'startIndex': start_index
            }
            
            if keywords:
                params['keywordSearch'] = ' OR '.join(keywords)
            
            try:
                self.logger.info(f"Fetching batch (start index: {start_index})")
                
                # Use a slightly longer timeout as the API can be slow
                response = self.session.get(self.BASE_URL, params=params, timeout=60) 
                
                # Check for 404, 403, 429, etc.
                response.raise_for_status() 
                
                data = response.json()
                
                vulnerabilities = data.get('vulnerabilities', [])
                total_results = data.get('totalResults', 0)
                
                if not vulnerabilities:
                    self.logger.info("No more results for this date range")
                    break
                
                # Extract features from each CVE
                for vuln in vulnerabilities:
                    cve_data = self._extract_features(vuln)
                    if cve_data:
                        cves.append(cve_data)
                
                self.logger.info(f"Collected {len(cves)} CVEs from this date range (Total: {len(cves)}/{total_results})")
                
                # Check if we've reached the end
                if start_index + params['resultsPerPage'] >= total_results:
                    break
                
                if len(cves) >= remaining_count:
                    break
                
                start_index += params['resultsPerPage']
                
                # Rate limiting
                time.sleep(self.rate_limit)
                
            except RequestException as e:
                self.logger.error(f"API request failed: {e}")
                
                # Check for 429 Too Many Requests
                if response.status_code == 429:
                    self.logger.warning("Rate limit hit (429). Waiting 60 seconds...")
                    time.sleep(60)
                
                # Check for 404 Not Found (might indicate no data for the range or bad params)
                elif response.status_code == 404:
                    self.logger.warning("404 Not Found. Skipping to next index/chunk.")
                    break # Skip this index/chunk if 404 is persistent
                
                time.sleep(10)  # Back off on other errors
                continue
        
        return cves
    
    # --- Feature Extraction Methods (Retained as is, they look correct) ---
    
    def _extract_features(self, vuln: Dict) -> Optional[Dict]:
        """Extract relevant features from CVE JSON"""
        # ... (rest of _extract_features method) ...
        try:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Published and modified dates
            published = cve.get('published', '')
            last_modified = cve.get('lastModified', '')
            
            # Description
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # CVSS metrics
            metrics = cve.get('metrics', {})
            cvss_data = self._extract_cvss_metrics(metrics)
            
            # CWE information
            weaknesses = cve.get('weaknesses', [])
            cwe_ids = self._extract_cwe_ids(weaknesses)
            
            # References (check for exploit availability)
            references = cve.get('references', [])
            has_exploit = self._check_exploit_availability(references)
            
            # CPE (affected products)
            configurations = cve.get('configurations', [])
            affected_products = self._extract_affected_products(configurations)
            
            # Vulnerability type detection
            vuln_type = self._classify_vulnerability_type(description, cwe_ids)
            
            features = {
                'cve_id': cve_id,
                'published_date': published,
                'last_modified_date': last_modified,
                'description': description[:500],  # Truncate for storage
                'vuln_type': vuln_type,
                'cwe_ids': ','.join(cwe_ids) if cwe_ids else None,
                'has_exploit': has_exploit,
                'affected_products_count': len(affected_products),
                **cvss_data  # Unpack CVSS metrics
            }
            
            return features
            
        except Exception as e:
            self.logger.warning(f"Failed to extract features: {e}")
            return None
    
    def _extract_cvss_metrics(self, metrics: Dict) -> Dict:
        """Extract CVSS v3.1 metrics"""
        # ... (rest of _extract_cvss_metrics method) ...
        cvss_data = {
            'cvss_base_score': None,
            'cvss_exploitability_score': None,
            'cvss_impact_score': None,
            'cvss_severity': None,
            'cvss_attack_vector': None,
            'cvss_attack_complexity': None,
            'cvss_privileges_required': None,
            'cvss_user_interaction': None,
            'cvss_scope': None,
            'cvss_confidentiality_impact': None,
            'cvss_integrity_impact': None,
            'cvss_availability_impact': None
        }
        
        # Try CVSS v3.1 first, then v3.0
        cvss_v31 = metrics.get('cvssMetricV31', [])
        cvss_v30 = metrics.get('cvssMetricV30', [])
        
        cvss_list = cvss_v31 if cvss_v31 else cvss_v30
        
        if cvss_list:
            cvss = cvss_list[0].get('cvssData', {})
            
            cvss_data['cvss_base_score'] = cvss.get('baseScore')
            cvss_data['cvss_severity'] = cvss.get('baseSeverity')
            cvss_data['cvss_attack_vector'] = cvss.get('attackVector')
            cvss_data['cvss_attack_complexity'] = cvss.get('attackComplexity')
            cvss_data['cvss_privileges_required'] = cvss.get('privilegesRequired')
            cvss_data['cvss_user_interaction'] = cvss.get('userInteraction')
            cvss_data['cvss_scope'] = cvss.get('scope')
            cvss_data['cvss_confidentiality_impact'] = cvss.get('confidentialityImpact')
            cvss_data['cvss_integrity_impact'] = cvss.get('integrityImpact')
            cvss_data['cvss_availability_impact'] = cvss.get('availabilityImpact')
            
            # Exploitability and Impact scores
            cvss_data['cvss_exploitability_score'] = cvss_list[0].get('exploitabilityScore')
            cvss_data['cvss_impact_score'] = cvss_list[0].get('impactScore')
        
        return cvss_data
    
    def _extract_cwe_ids(self, weaknesses: List[Dict]) -> List[str]:
        """Extract CWE IDs from weakness data"""
        # ... (rest of _extract_cwe_ids method) ...
        cwe_ids = []
        
        for weakness in weaknesses:
            descriptions = weakness.get('description', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    value = desc.get('value', '')
                    if value.startswith('CWE-'):
                        cwe_ids.append(value)
        
        return list(set(cwe_ids))  # Remove duplicates
    
    def _check_exploit_availability(self, references: List[Dict]) -> bool:
        """Check if exploit code is available"""
        # ... (rest of _check_exploit_availability method) ...
        exploit_keywords = [
            'exploit', 'poc', 'proof of concept', 
            'exploit-db', 'metasploit', 'github.com'
        ]
        
        for ref in references:
            url = ref.get('url', '').lower()
            tags = ref.get('tags', [])
            
            # Check tags
            if 'Exploit' in tags or 'Third Party Advisory' in tags:
                return True
            
            # Check URL
            for keyword in exploit_keywords:
                if keyword in url:
                    return True
        
        return False
    
    def _extract_affected_products(self, configurations: List[Dict]) -> List[str]:
        """Extract affected product names"""
        # ... (rest of _extract_affected_products method) ...
        products = set()
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    if cpe_match.get('vulnerable', False):
                        cpe23 = cpe_match.get('criteria', '')
                        if cpe23:
                            # Extract vendor and product from CPE
                            parts = cpe23.split(':')
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                products.add(f"{vendor}:{product}")
        
        return list(products)
    
    def _classify_vulnerability_type(self, description: str, cwe_ids: List[str]) -> str:
        """
        Classify vulnerability into SQL, XSS, or CSRF
        """
        # ... (rest of _classify_vulnerability_type method) ...
        desc_lower = description.lower()
        
        # SQL Injection patterns
        sql_keywords = ['sql injection', 'sql query', 'sqli', 'database query']
        sql_cwes = ['CWE-89', 'CWE-564']
        
        if any(kw in desc_lower for kw in sql_keywords) or any(cwe in cwe_ids for cwe in sql_cwes):
            return 'SQL_INJECTION'
        
        # XSS patterns
        xss_keywords = ['cross-site scripting', 'xss', 'script injection', 'html injection']
        xss_cwes = ['CWE-79', 'CWE-80', 'CWE-83']
        
        if any(kw in desc_lower for kw in xss_keywords) or any(cwe in cwe_ids for cwe in xss_cwes):
            return 'XSS'
        
        # CSRF patterns
        csrf_keywords = ['cross-site request forgery', 'csrf', 'xsrf', 'request forgery']
        csrf_cwes = ['CWE-352']
        
        if any(kw in desc_lower for kw in csrf_keywords) or any(cwe in cwe_ids for cwe in csrf_cwes):
            return 'CSRF'
        
        return 'OTHER'
    
    def save_to_csv(self, df: pd.DataFrame, filename: str):
        """Save DataFrame to CSV"""
        output_path = Path(filename)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        df.to_csv(output_path, index=False)
        self.logger.info(f"Saved {len(df)} records to {output_path}")
    
    def load_from_csv(self, filename: str) -> pd.DataFrame:
        """Load DataFrame from CSV"""
        df = pd.read_csv(filename)
        self.logger.info(f"Loaded {len(df)} records from {filename}")
        return df