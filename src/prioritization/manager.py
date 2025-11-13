# src/prioritization/manager.py

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from src.utils.logger import get_logger
from src.prioritization.data_models import RiskScore, RiskLevel, RemediationPriority

class PriorityQueueManager:
    """
    Manages vulnerability priority queue, including sorting, statistics, and reporting.
    """
    
    def __init__(self):
        """Initialize priority queue manager"""
        self.logger = get_logger(__name__)
        self.queue: List[RiskScore] = []
        self.statistics: Dict = {
            'total_vulnerabilities': 0,
            'by_risk_level': {},
            'by_remediation_priority': {},
            'average_score': 0.0,
            'median_score': 0.0,
            'model_agreement_rate': 0.0,
            'average_confidence': 0.0
        }
    
    def add_vulnerability(self, risk_score: RiskScore):
        """Add vulnerability to queue"""
        self.queue.append(risk_score)
    
    def sort_by_risk(self):
        """Sort queue by final risk score (descending)"""
        self.queue.sort(key=lambda x: x.final_risk_score, reverse=True)
        self.logger.info(f"Queue sorted: {len(self.queue)} vulnerabilities")
    
    def get_top_n(self, n: int) -> List[RiskScore]:
        """Get top N highest-risk vulnerabilities"""
        return self.queue[:n]
    
    def calculate_statistics(self):
        """Calculate queue statistics"""
        if not self.queue:
            return
        
        self.statistics['total_vulnerabilities'] = len(self.queue)
        
        # Calculate distributions
        scores = [v.final_risk_score for v in self.queue]
        agreements = [v.model_agreement for v in self.queue]
        confidences = [(v.rf_confidence + v.nn_confidence) / 2 for v in self.queue]
        
        self.statistics['average_score'] = float(np.mean(scores))
        self.statistics['median_score'] = float(np.median(scores))
        self.statistics['model_agreement_rate'] = float(np.mean(agreements))
        self.statistics['average_confidence'] = float(np.mean(confidences))
        
        self.statistics['by_risk_level'] = {
            level.value: len([v for v in self.queue if v.risk_level == level])
            for level in RiskLevel
        }
        
        self.statistics['by_remediation_priority'] = {
            priority.value: len([v for v in self.queue if v.remediation_priority == priority])
            for priority in RemediationPriority
        }
        
        self.logger.info("Statistics calculated.")
    
    def export_to_dataframe(self) -> pd.DataFrame:
        """Export queue to pandas DataFrame"""
        if not self.queue:
            return pd.DataFrame()
        
        data = [risk.to_dict() for risk in self.queue]
        df = pd.DataFrame(data)
        
        # Add priority rank
        df['priority_rank'] = range(1, len(df) + 1)
        
        return df
    
    def save_to_csv(self, filepath: Path):
        """Save queue to CSV file"""
        df = self.export_to_dataframe()
        df.to_csv(filepath, index=False)
        self.logger.info(f"Queue saved to {filepath}")
    
    def save_statistics(self, filepath: Path):
        """Save statistics to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.statistics, f, indent=2)
        self.logger.info(f"Statistics saved to {filepath}")
    
    def generate_report(self, filepath: Path):
        """Generate human-readable text report"""
        
        if not self.queue or not self.statistics:
             self.logger.warning("Cannot generate report: Queue or statistics are empty.")
             return

        with open(filepath, 'w') as f:
            f.write("="*70 + "\n")
            f.write("GLITCHFORGE RISK PRIORITIZATION REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            f.write("SUMMARY\n")
            f.write("-"*70 + "\n")
            stats = self.statistics
            
            f.write(f"Total Vulnerabilities: {stats['total_vulnerabilities']:,}\n")
            f.write(f"Average Risk Score: {stats['average_score']:.2f}/100\n")
            f.write(f"Median Risk Score: {stats['median_score']:.2f}/100\n")
            f.write(f"Model Agreement Rate: {stats['model_agreement_rate']:.1%}\n")
            f.write(f"Average Confidence: {stats['average_confidence']:.1%}\n")

            f.write("\nRisk Level Distribution:\n")
            for level, count in stats['by_risk_level'].items():
                percentage = (count / stats['total_vulnerabilities']) * 100
                f.write(f"  {level}: {count:,} ({percentage:.1f}%)\n")
            
            f.write("\nRemediation Priority Distribution:\n")
            for priority, count in stats['by_remediation_priority'].items():
                percentage = (count / stats['total_vulnerabilities']) * 100
                f.write(f"  {priority}: {count:,} ({percentage:.1f}%)\n")
            
            # Top 20 vulnerabilities
            f.write("\n\nTOP 20 CRITICAL VULNERABILITIES\n")
            f.write("-"*70 + "\n\n")
            
            for i, vuln in enumerate(self.get_top_n(20), 1):
                f.write(f"Rank #{i}: {vuln.risk_level.value} - Score: {vuln.final_risk_score:.1f}/100\n")
                f.write(f"  ID: {vuln.vulnerability_id}\n")
                f.write(f"  {vuln.explanation_text}\n\n")
        
        self.logger.info(f"Report generated: {filepath}")