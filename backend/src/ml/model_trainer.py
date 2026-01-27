"""
ML Model Trainer - Stage 2
Trains Random Forest and Neural Network models for vulnerability risk prediction
Target: >90% accuracy
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from sklearn.utils import class_weight
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import joblib
import logging
from pathlib import Path
from typing import Dict, Tuple
import json

class MLModelTrainer:
    """Trains and evaluates ML models for vulnerability risk prediction"""
    
    def __init__(self, model_dir: str = "models"):
        """
        Initialize trainer
        
        Args:
            model_dir: Directory to save trained models
        """
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        
        self.rf_model = None
        self.nn_model = None
        self.class_weights = None
        
    def prepare_data(
        self,
        X: pd.DataFrame,
        y: pd.Series,
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42
    ) -> Tuple:
        """
        Split data into train/validation/test sets (70/15/15)
        
        Args:
            X: Feature matrix
            y: Target variable
            test_size: Test set proportion
            val_size: Validation set proportion
            random_state: Random seed
            
        Returns:
            X_train, X_val, X_test, y_train, y_val, y_test
        """
        self.logger.info("Splitting data into train/val/test...")
        
        # First split: train+val / test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Second split: train / val
        val_proportion = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_proportion, 
            random_state=random_state, stratify=y_temp
        )
        
        self.logger.info(f"Train set: {len(X_train)} samples")
        self.logger.info(f"Validation set: {len(X_val)} samples")
        self.logger.info(f"Test set: {len(X_test)} samples")
        
        # Calculate class weights for imbalanced data
        self.class_weights = class_weight.compute_class_weight(
            'balanced',
            classes=np.unique(y_train),
            y=y_train
        )
        self.class_weights_dict = dict(enumerate(self.class_weights))
        
        self.logger.info(f"Class weights: {self.class_weights_dict}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def train_random_forest(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_val: pd.DataFrame = None,
        y_val: pd.Series = None,
        hyperparameter_tune: bool = False
    ) -> Dict:
        """
        Train Random Forest classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels
            hyperparameter_tune: Whether to perform grid search
            
        Returns:
            Training metrics dictionary
        """
        self.logger.info("Training Random Forest model...")
        
        if hyperparameter_tune:
            self.logger.info("Performing hyperparameter tuning...")
            
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 20, 30, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4],
                'max_features': ['sqrt', 'log2']
            }
            
            rf = RandomForestClassifier(
                random_state=42,
                class_weight=self.class_weights_dict,
                n_jobs=-1
            )
            
            grid_search = GridSearchCV(
                rf, param_grid, cv=5, scoring='f1_weighted', 
                n_jobs=-1, verbose=1
            )
            
            grid_search.fit(X_train, y_train)
            self.rf_model = grid_search.best_estimator_
            
            self.logger.info(f"Best parameters: {grid_search.best_params_}")
            
        else:
            # Use default optimized parameters
            self.rf_model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                random_state=42,
                class_weight=self.class_weights_dict,
                n_jobs=-1
            )
            
            self.rf_model.fit(X_train, y_train)
        
        # Evaluate
        train_metrics = self._evaluate_model(self.rf_model, X_train, y_train, "Training")
        
        if X_val is not None and y_val is not None:
            val_metrics = self._evaluate_model(self.rf_model, X_val, y_val, "Validation")
            train_metrics['validation_metrics'] = val_metrics
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': X_train.columns,
            'importance': self.rf_model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        self.logger.info("\nTop 10 Important Features:")
        for idx, row in feature_importance.head(10).iterrows():
            self.logger.info(f"  {row['feature']}: {row['importance']:.4f}")
        
        train_metrics['feature_importance'] = feature_importance.to_dict('records')
        
        # Save model
        model_path = self.model_dir / 'random_forest.pkl'
        joblib.dump(self.rf_model, model_path)
        self.logger.info(f"Model saved to {model_path}")
        
        return train_metrics
    
    def train_neural_network(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        X_val: pd.DataFrame,
        y_val: pd.Series,
        epochs: int = 100,
        batch_size: int = 32
    ) -> Dict:
        """
        Train Neural Network classifier using TensorFlow/Keras
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features
            y_val: Validation labels
            epochs: Number of training epochs
            batch_size: Batch size
            
        Returns:
            Training metrics dictionary
        """
        self.logger.info("Training Neural Network model...")
        
        n_features = X_train.shape[1]
        n_classes = len(np.unique(y_train))
        
        # Build model architecture
        self.nn_model = keras.Sequential([
            layers.Input(shape=(n_features,)),
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            layers.Dense(32, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(n_classes, activation='softmax')
        ])
        
        # Compile model
        self.nn_model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # --- FIX FOR UNICODEENCODEERROR ---
        self.logger.info(f"\nModel Architecture:")
        try:
            # Print the summary using the standard print function, which is 
            # often more successful at handling Unicode characters in consoles.
            # Using self.logger.info as print_fn causes the UnicodeEncodeError.
            self.nn_model.summary(print_fn=print)
        except UnicodeEncodeError:
            self.logger.warning("Model summary skipped due to Unicode encoding error in console.")
            self.logger.info(f"Summary unavailable. Total parameters: {self.nn_model.count_params()}")
        except Exception as e:
            self.logger.warning(f"Failed to log model summary: {e}")
        # --- END FIX ---
        
        # Callbacks
        early_stopping = keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=15,
            restore_best_weights=True
        )
        
        reduce_lr = keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=5,
            min_lr=0.00001
        )
        
        # Train model
        history = self.nn_model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            class_weight=self.class_weights_dict,
            callbacks=[early_stopping, reduce_lr],
            verbose=1
        )
        
        # Evaluate
        train_metrics = {
            'history': {
                'loss': [float(x) for x in history.history['loss']],
                'accuracy': [float(x) for x in history.history['accuracy']],
                'val_loss': [float(x) for x in history.history['val_loss']],
                'val_accuracy': [float(x) for x in history.history['val_accuracy']]
            }
        }
        
        # Predictions for metrics
        y_train_pred = np.argmax(self.nn_model.predict(X_train), axis=1)
        y_val_pred = np.argmax(self.nn_model.predict(X_val), axis=1)
        
        train_metrics['training_metrics'] = self._calculate_metrics(y_train, y_train_pred, "Training")
        train_metrics['validation_metrics'] = self._calculate_metrics(y_val, y_val_pred, "Validation")
        
        # Save model
        model_path = self.model_dir / 'neural_network.h5'
        self.nn_model.save(model_path)
        self.logger.info(f"Model saved to {model_path}")
        
        return train_metrics
    
    def _evaluate_model(self, model, X, y, dataset_name: str) -> Dict:
        """Evaluate model and return metrics"""
        self.logger.info(f"\nEvaluating on {dataset_name} set...")
        
        y_pred = model.predict(X)
        
        # If it's a Keras model, predict returns probabilities, so convert to class labels
        if isinstance(model, keras.Model):
            y_pred = np.argmax(y_pred, axis=1)
            
        return self._calculate_metrics(y, y_pred, dataset_name)
    
    def _calculate_metrics(self, y_true, y_pred, dataset_name: str) -> Dict:
        """Calculate classification metrics"""
        
        metrics = {
            'accuracy': float(accuracy_score(y_true, y_pred)),
            'precision_weighted': float(precision_score(y_true, y_pred, average='weighted', zero_division=0)),
            'recall_weighted': float(recall_score(y_true, y_pred, average='weighted', zero_division=0)),
            'f1_weighted': float(f1_score(y_true, y_pred, average='weighted', zero_division=0)),
            'precision_macro': float(precision_score(y_true, y_pred, average='macro', zero_division=0)),
            'recall_macro': float(recall_score(y_true, y_pred, average='macro', zero_division=0)),
            'f1_macro': float(f1_score(y_true, y_pred, average='macro', zero_division=0))
        }
        
        # Per-class metrics
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        metrics['classification_report'] = report
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        
        # --- FIX: Add a blank line log entry for vertical spacing ---
        self.logger.info("") 
        # -----------------------------------------------------------
        
        self.logger.info(f"{dataset_name} Metrics:")
        # Adjusted formatting to use two spaces after the colon for better separation
        self.logger.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
        self.logger.info(f"  F1 (weighted):  {metrics['f1_weighted']:.4f}")
        self.logger.info(f"  F1 (macro):  {metrics['f1_macro']:.4f}")
        
        return metrics
    
    def evaluate_on_test(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict:
        """
        Evaluate both models on test set
        """
        results = {}
        
        if self.rf_model:
            # Add vertical space before Random Forest evaluation
            self.logger.info("")  
            self.logger.info("="*60)
            self.logger.info("Random Forest - Test Set Evaluation")
            self.logger.info("="*60)
            results['random_forest'] = self._evaluate_model(self.rf_model, X_test, y_test, "Test")
            # Add vertical space after Random Forest evaluation
            self.logger.info("") 
        
        if self.nn_model:
            # Add vertical space before Neural Network evaluation
            self.logger.info("")  
            self.logger.info("="*60)
            self.logger.info("Neural Network - Test Set Evaluation")
            self.logger.info("="*60)
            # Keras model prediction
            y_pred = np.argmax(self.nn_model.predict(X_test), axis=1)
            results['neural_network'] = self._calculate_metrics(y_test, y_pred, "Test")
            # Add vertical space after Neural Network evaluation
            self.logger.info("")  
        
        return results
    
    def save_metrics(self, metrics: Dict, filename: str):
        """Save metrics to JSON file"""
        output_path = self.model_dir / filename
        with open(output_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        self.logger.info(f"Metrics saved to {output_path}")