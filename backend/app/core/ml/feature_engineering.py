"""
Feature Engineering - Stage 2
Transforms raw NVD data into ML-ready features
"""

import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, StandardScaler
from typing import Tuple
import logging

class FeatureEngineer:
    """Engineers features from NVD vulnerability data"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.label_encoders = {}
        self.scaler = StandardScaler()
        
    def engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create ML features from raw NVD data
        
        Args:
            df: Raw NVD DataFrame
            
        Returns:
            DataFrame with engineered features
        """
        self.logger.info("Starting feature engineering...")
        
        df = df.copy()
        
        # 1. Temporal features
        df = self._create_temporal_features(df)
        
        # 2. CVSS-based features
        df = self._create_cvss_features(df)
        
        # 3. Exploit availability features
        df = self._create_exploit_features(df)
        
        # 4. Product popularity features (simplified)
        df = self._create_product_features(df)
        
        # 5. Encode categorical features
        df = self._encode_categorical_features(df)
        
        # 6. Create risk labels
        df = self._create_risk_labels(df)
        
        self.logger.info(f"Feature engineering complete. Shape: {df.shape}")
        
        return df
    
    def _create_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create time-based features"""
        self.logger.info("Creating temporal features...")
        
        # Convert dates to datetime
        df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce')
        df['last_modified_date'] = pd.to_datetime(df['last_modified_date'], errors='coerce')
        
        # Calculate age in days
        current_date = datetime.now()
        df['age_days'] = (current_date - df['published_date']).dt.days
        
        # Days since last modification
        df['days_since_modified'] = (current_date - df['last_modified_date']).dt.days
        
        # Modification frequency (difference between published and modified)
        df['modification_span_days'] = (df['last_modified_date'] - df['published_date']).dt.days
        
        # Extract temporal components
        df['publish_year'] = df['published_date'].dt.year
        df['publish_month'] = df['published_date'].dt.month
        df['publish_quarter'] = df['published_date'].dt.quarter
        
        # Fill NaN values
        df['age_days'].fillna(0, inplace=True)
        df['days_since_modified'].fillna(0, inplace=True)
        df['modification_span_days'].fillna(0, inplace=True)
        
        return df
    
    def _create_cvss_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create CVSS-based features"""
        self.logger.info("Creating CVSS features...")
        
        # Fill missing CVSS scores with median
        df['cvss_base_score'].fillna(df['cvss_base_score'].median(), inplace=True)
        df['cvss_exploitability_score'].fillna(df['cvss_exploitability_score'].median(), inplace=True)
        df['cvss_impact_score'].fillna(df['cvss_impact_score'].median(), inplace=True)
        
        # Create binary severity features
        df['is_critical'] = (df['cvss_base_score'] >= 9.0).astype(int)
        df['is_high'] = ((df['cvss_base_score'] >= 7.0) & (df['cvss_base_score'] < 9.0)).astype(int)
        df['is_medium'] = ((df['cvss_base_score'] >= 4.0) & (df['cvss_base_score'] < 7.0)).astype(int)
        df['is_low'] = (df['cvss_base_score'] < 4.0).astype(int)
        
        # Exploitability categories
        df['high_exploitability'] = (df['cvss_exploitability_score'] >= 3.0).astype(int)
        
        # Impact categories
        df['high_impact'] = (df['cvss_impact_score'] >= 5.0).astype(int)
        
        # Attack vector encoding
        attack_vector_map = {'NETWORK': 3, 'ADJACENT_NETWORK': 2, 'LOCAL': 1, 'PHYSICAL': 0}
        df['attack_vector_score'] = df['cvss_attack_vector'].map(attack_vector_map).fillna(0)
        
        # Attack complexity encoding
        complexity_map = {'LOW': 1, 'HIGH': 0}
        df['attack_complexity_score'] = df['cvss_attack_complexity'].map(complexity_map).fillna(0)
        
        # Privileges required encoding
        privileges_map = {'NONE': 2, 'LOW': 1, 'HIGH': 0}
        df['privileges_required_score'] = df['cvss_privileges_required'].map(privileges_map).fillna(0)
        
        # User interaction encoding
        interaction_map = {'NONE': 1, 'REQUIRED': 0}
        df['user_interaction_score'] = df['cvss_user_interaction'].map(interaction_map).fillna(0)
        
        # Impact scores encoding
        impact_map = {'HIGH': 2, 'LOW': 1, 'NONE': 0}
        df['confidentiality_score'] = df['cvss_confidentiality_impact'].map(impact_map).fillna(0)
        df['integrity_score'] = df['cvss_integrity_impact'].map(impact_map).fillna(0)
        df['availability_score'] = df['cvss_availability_impact'].map(impact_map).fillna(0)
        
        # Combined impact score
        df['total_impact_score'] = (
            df['confidentiality_score'] + 
            df['integrity_score'] + 
            df['availability_score']
        )
        
        return df
    
    def _create_exploit_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create exploit availability features"""
        self.logger.info("Creating exploit features...")
        
        # Binary exploit availability
        df['has_exploit'] = df['has_exploit'].fillna(False).astype(int)
        
        # Interaction with CVSS score
        df['exploit_cvss_interaction'] = df['has_exploit'] * df['cvss_base_score']
        
        return df
    
    def _create_product_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create product-related features"""
        self.logger.info("Creating product features...")
        
        # Number of affected products
        df['affected_products_count'].fillna(0, inplace=True)
        
        # Product impact categories
        df['single_product'] = (df['affected_products_count'] == 1).astype(int)
        df['multiple_products'] = (df['affected_products_count'] > 1).astype(int)
        df['widespread'] = (df['affected_products_count'] > 10).astype(int)
        
        return df
    
    def _encode_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical variables"""
        self.logger.info("Encoding categorical features...")
        
        categorical_cols = [
            'cvss_severity', 'cvss_scope'
        ]
        
        for col in categorical_cols:
            if col in df.columns:
                # Fill missing values with 'UNKNOWN'
                df[col].fillna('UNKNOWN', inplace=True)
                
                # Create label encoder if doesn't exist
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    self.label_encoders[col].fit(df[col])
                
                # Transform
                df[f'{col}_encoded'] = self.label_encoders[col].transform(df[col])
        
        return df
    
    def _create_risk_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create risk classification labels based on:
        - CVSS score
        - Exploit availability
        - Age
        """
        self.logger.info("Creating risk labels...")
        
        def calculate_risk(row):
            """Calculate risk level: LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3"""
            score = 0
            
            # CVSS contribution (0-3 points)
            if row['cvss_base_score'] >= 9.0:
                score += 3
            elif row['cvss_base_score'] >= 7.0:
                score += 2
            elif row['cvss_base_score'] >= 4.0:
                score += 1
            
            # Exploit availability (0-2 points)
            if row['has_exploit']:
                score += 2
            
            # Recent vulnerability (0-1 point)
            if row['age_days'] < 180:  # Less than 6 months
                score += 1
            
            # High exploitability (0-1 point)
            if row['cvss_exploitability_score'] >= 3.0:
                score += 1
            
            # Map to risk levels
            if score >= 6:
                return 3  # CRITICAL
            elif score >= 4:
                return 2  # HIGH
            elif score >= 2:
                return 1  # MEDIUM
            else:
                return 0  # LOW
        
        df['risk_level'] = df.apply(calculate_risk, axis=1)
        
        # Create risk labels
        risk_labels = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}
        df['risk_label'] = df['risk_level'].map(risk_labels)
        
        self.logger.info(f"Risk distribution:\n{df['risk_label'].value_counts()}")
        
        return df
    
    def select_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Select final features for ML models
        
        Returns:
            X: Feature matrix
            y: Target variable (risk_level)
        """
        self.logger.info("Selecting features for ML...")
        
        # Feature columns to use
        feature_cols = [
            # CVSS features
            'cvss_base_score',
            'cvss_exploitability_score',
            'cvss_impact_score',
            'is_critical',
            'is_high',
            'is_medium',
            'is_low',
            'high_exploitability',
            'high_impact',
            'attack_vector_score',
            'attack_complexity_score',
            'privileges_required_score',
            'user_interaction_score',
            'confidentiality_score',
            'integrity_score',
            'availability_score',
            'total_impact_score',
            
            # Exploit features
            'has_exploit',
            'exploit_cvss_interaction',
            
            # Temporal features
            'age_days',
            'days_since_modified',
            'modification_span_days',
            'publish_quarter',
            
            # Product features
            'affected_products_count',
            'single_product',
            'multiple_products',
            'widespread',
            
            # Encoded categoricals
            'cvss_severity_encoded',
            'cvss_scope_encoded'
        ]
        
        # Filter to only existing columns
        existing_features = [col for col in feature_cols if col in df.columns]
        
        X = df[existing_features].copy()
        y = df['risk_level'].copy()
        
        # Fill any remaining NaN values
        X.fillna(0, inplace=True)
        
        self.logger.info(f"Selected {len(existing_features)} features")
        self.logger.info(f"Feature matrix shape: {X.shape}")
        self.logger.info(f"Target distribution:\n{y.value_counts()}")
        
        return X, y
    
    def normalize_features(self, X_train: pd.DataFrame, X_test: pd.DataFrame = None) -> Tuple:
        """
        Normalize features using StandardScaler
        
        Args:
            X_train: Training features
            X_test: Optional test features
            
        Returns:
            Normalized X_train and X_test (if provided)
        """
        self.logger.info("Normalizing features...")
        
        # Fit scaler on training data
        X_train_scaled = pd.DataFrame(
            self.scaler.fit_transform(X_train),
            columns=X_train.columns,
            index=X_train.index
        )
        
        if X_test is not None:
            X_test_scaled = pd.DataFrame(
                self.scaler.transform(X_test),
                columns=X_test.columns,
                index=X_test.index
            )
            return X_train_scaled, X_test_scaled
        
        return X_train_scaled


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("Feature Engineering Module - Stage 2")
    print("=" * 60)
    
    # Load sample data
    try:
        df = pd.read_csv('data/nvd_sample.csv')
        print(f"\nLoaded {len(df)} CVEs from sample data")
        
        # Engineer features
        engineer = FeatureEngineer()
        df_engineered = engineer.engineer_features(df)
        
        print(f"\nEngineered features: {df_engineered.shape[1]} columns")
        print(f"\nNew feature columns:")
        new_cols = set(df_engineered.columns) - set(df.columns)
        for col in sorted(new_cols):
            print(f"  - {col}")
        
        # Select features
        X, y = engineer.select_features(df_engineered)
        print(f"\nFinal feature matrix: {X.shape}")
        print(f"Target variable: {y.shape}")
        
        print(f"\nFeature list:")
        for i, col in enumerate(X.columns, 1):
            print(f"  {i:2d}. {col}")
        
    except FileNotFoundError:
        print("\nNo sample data found. Run nvd_collector.py first!")