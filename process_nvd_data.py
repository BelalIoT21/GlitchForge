#!/usr/bin/env python3
"""
Process NVD data for ML training
"""

from ml.data_collector_simple import NVDDataCollectorSimple
from ml.feature_extractor import FeatureExtractor

print("\n" + "="*60)
print("  Processing NVD Data")
print("="*60)

# Load data
collector = NVDDataCollectorSimple()
vulnerabilities = collector.load_from_file('nvd_real_data.json')

# Extract features
extractor = FeatureExtractor()
df = extractor.extract_features(vulnerabilities)

# Encode features
df_encoded = extractor.encode_categorical_features(df)

# Create target
df_final = extractor.create_target_variable(df_encoded)

# Save
filepath = extractor.save_processed_data(df_final, 'processed_nvd_data.csv')

print(f"\n✓ Ready for training: {len(df_final)} records")