"""
SecureLink Guardian - ML Phishing Classifier
Machine learning model for phishing detection
"""

import logging
from typing import Dict, List
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os
from backend.config import Config

logger = logging.getLogger(__name__)


class PhishingClassifier:
    """ML-based phishing classification"""
    
    def __init__(self, config: Config):
        self.config = config
        self.model = None
        self.vectorizer = None
        self.feature_names = [
            'url_length', 'domain_length', 'subdomain_count',
            'path_depth', 'param_count', 'has_ip', 'has_at_symbol',
            'has_dash', 'digit_count', 'special_char_count',
            'typosquatting_score', 'domain_age', 'ssl_valid'
        ]
        
        # Load model if exists
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained model"""
        model_path = self.config.PHISHING_MODEL_PATH
        
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                logger.info(f"Model loaded from {model_path}")
            except Exception as e:
                logger.warning(f"Model loading failed: {str(e)}")
                self._initialize_default_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize default model"""
        logger.info("Initializing default model")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.vectorizer = TfidfVectorizer(
            max_features=100,
            ngram_range=(1, 2)
        )
    
    def extract_features(self, url: str, analysis_results: Dict) -> np.ndarray:
        """
        Extract features from URL and analysis results
        
        Args:
            url: URL to analyze
            analysis_results: Previous analysis results
            
        Returns:
            Feature vector
        """
        from backend.utils.url_parser import url_parser
        
        parsed = url_parser.parse(url)
        
        features = []
        
        # URL features
        features.append(len(url))  # url_length
        features.append(len(parsed.get('domain', '')))  # domain_length
        features.append(parsed.get('subdomain_count', 0))  # subdomain_count
        features.append(parsed.get('path_depth', 0))  # path_depth
        features.append(parsed.get('param_count', 0))  # param_count
        features.append(1 if parsed.get('is_ip') else 0)  # has_ip
        features.append(1 if '@' in url else 0)  # has_at_symbol
        features.append(url.count('-'))  # has_dash
        features.append(sum(c.isdigit() for c in url))  # digit_count
        features.append(sum(not c.isalnum() for c in url))  # special_char_count
        
        # DNS features
        dns = analysis_results.get('dns')
        if dns:
            features.append(1 if dns.typosquatting else 0)  # typosquatting_score
            features.append(dns.domain_age_days or 0)  # domain_age
            features.append(1 if dns.ssl_valid else 0)  # ssl_valid
        else:
            features.extend([0, 0, 0])
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, url: str, analysis_results: Dict) -> Dict:
        """
        Predict if URL is phishing
        
        Args:
            url: URL to predict
            analysis_results: Previous analysis results
            
        Returns:
            Dictionary with prediction results
        """
        if not self.model:
            logger.warning("Model not available, using rule-based fallback")
            return self._rule_based_prediction(analysis_results)
        
        try:
            # Extract features
            features = self.extract_features(url, analysis_results)
            
            # Predict
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # Get confidence
            confidence = float(max(probabilities))
            
            # Calculate risk score
            risk_score = int(probabilities[1] * 100)  # Phishing probability
            
            return {
                'is_phishing': bool(prediction),
                'risk_score': risk_score,
                'confidence': confidence,
                'model_used': 'random_forest'
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return self._rule_based_prediction(analysis_results)
    
    def _rule_based_prediction(self, analysis_results: Dict) -> Dict:
        """
        Rule-based fallback prediction
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            Dictionary with prediction results
        """
        risk_score = 0
        
        # DNS-based rules
        dns = analysis_results.get('dns')
        if dns:
            if dns.typosquatting:
                risk_score += 40
            if dns.homograph:
                risk_score += 35
            if dns.domain_age_days and dns.domain_age_days < 30:
                risk_score += 20
            if not dns.ssl_valid:
                risk_score += 15
        
        # URL-based rules
        url = analysis_results.get('url')
        if url:
            if url.is_shortener:
                risk_score += 20
            if url.redirect_count > 0:
                risk_score += 15
            if url.suspicious_params:
                risk_score += 20
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        return {
            'is_phishing': risk_score >= 70,
            'risk_score': risk_score,
            'confidence': 0.75,
            'model_used': 'rule_based'
        }
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train the model
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        if not self.model:
            self._initialize_default_model()
        
        logger.info("Training model...")
        self.model.fit(X_train, y_train)
        
        # Save model
        self.save_model()
        
        logger.info("Model training complete")
    
    def save_model(self):
        """Save trained model"""
        model_path = self.config.PHISHING_MODEL_PATH
        
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(self.model, model_path)
            logger.info(f"Model saved to {model_path}")
        except Exception as e:
            logger.error(f"Model save failed: {str(e)}")
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance"""
        if not self.model or not hasattr(self.model, 'feature_importances_'):
            return {}
        
        importances = self.model.feature_importances_
        return dict(zip(self.feature_names, importances))


# Factory function
def create_phishing_classifier(config: Config) -> PhishingClassifier:
    """Create phishing classifier instance"""
    return PhishingClassifier(config)