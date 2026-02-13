"""
SecureLink Guardian - Domain Classifier
ML-based domain reputation and risk classification
"""

import logging
from typing import Dict, List
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
import joblib
import os
from backend.config import Config

logger = logging.getLogger(__name__)


class DomainClassifier:
    """ML-based domain classification"""
    
    def __init__(self, config: Config):
        self.config = config
        self.model = None
        self.feature_names = [
            # Domain features
            'domain_length',
            'subdomain_count',
            'digit_count',
            'hyphen_count',
            'has_https',
            'domain_entropy',
            
            # DNS features
            'domain_age_normalized',
            'has_mx_records',
            'has_spf_record',
            'ssl_valid',
            
            # Lexical features
            'typosquatting_score',
            'homograph_score',
            'suspicious_tld',
            'contains_brand_name',
            
            # Historical features
            'reputation_score'
        ]
        
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained model"""
        model_path = self.config.DOMAIN_MODEL_PATH
        
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                logger.info(f"Domain model loaded from {model_path}")
            except Exception as e:
                logger.warning(f"Domain model loading failed: {str(e)}")
                self._initialize_default_model()
        else:
            self._initialize_default_model()
    
    def _initialize_default_model(self):
        """Initialize default model"""
        logger.info("Initializing default domain model")
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
    
    def extract_features(self, domain: str, dns_analysis: Dict, url_analysis: Dict) -> np.ndarray:
        """
        Extract features from domain and analysis results
        
        Args:
            domain: Domain name
            dns_analysis: DNS analysis results
            url_analysis: URL analysis results
            
        Returns:
            Feature vector
        """
        features = []
        
        # Domain length
        features.append(len(domain))
        
        # Subdomain count
        features.append(domain.count('.') - 1)
        
        # Digit count
        features.append(sum(c.isdigit() for c in domain))
        
        # Hyphen count
        features.append(domain.count('-'))
        
        # Has HTTPS (from analysis)
        features.append(1 if dns_analysis.get('ssl_valid') else 0)
        
        # Domain entropy
        features.append(self._calculate_entropy(domain))
        
        # Domain age (normalized to 0-1)
        domain_age = dns_analysis.get('domain_age_days', 0)
        features.append(min(1.0, domain_age / 365.0))
        
        # Has MX records
        features.append(1 if dns_analysis.get('mx_records_exist') else 0)
        
        # Has SPF record (would need to check TXT records)
        features.append(0)  # Placeholder
        
        # SSL valid
        features.append(1 if dns_analysis.get('ssl_valid') else 0)
        
        # Typosquatting score
        features.append(1 if dns_analysis.get('typosquatting') else 0)
        
        # Homograph score
        features.append(1 if dns_analysis.get('homograph') else 0)
        
        # Suspicious TLD
        features.append(1 if url_analysis.get('suspicious_tld') else 0)
        
        # Contains brand name
        features.append(self._contains_brand_name(domain))
        
        # Reputation score (would come from threat intel)
        features.append(dns_analysis.get('dns_reputation_score', 50) / 100.0)
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, domain: str, dns_analysis: Dict, url_analysis: Dict) -> Dict:
        """
        Predict domain risk
        
        Args:
            domain: Domain name
            dns_analysis: DNS analysis results
            url_analysis: URL analysis results
            
        Returns:
            Prediction results
        """
        if not self.model:
            logger.warning("Model not available, using rule-based fallback")
            return self._rule_based_prediction(domain, dns_analysis, url_analysis)
        
        try:
            # Extract features
            features = self.extract_features(domain, dns_analysis, url_analysis)
            
            # Predict
            prediction = self.model.predict(features)[0]
            probabilities = self.model.predict_proba(features)[0]
            
            # Get confidence
            confidence = float(max(probabilities))
            
            # Risk score
            risk_score = int(probabilities[1] * 100)  # Phishing probability
            
            return {
                'is_phishing': bool(prediction),
                'risk_score': risk_score,
                'confidence': confidence,
                'model_used': 'gradient_boosting'
            }
            
        except Exception as e:
            logger.error(f"Domain prediction error: {str(e)}")
            return self._rule_based_prediction(domain, dns_analysis, url_analysis)
    
    def _rule_based_prediction(self, domain: str, dns_analysis: Dict, url_analysis: Dict) -> Dict:
        """
        Rule-based fallback prediction
        
        Args:
            domain: Domain name
            dns_analysis: DNS analysis results
            url_analysis: URL analysis results
            
        Returns:
            Prediction results
        """
        risk_score = 0
        
        # Domain features
        if len(domain) > 30:
            risk_score += 10
        
        if domain.count('-') > 2:
            risk_score += 15
        
        if sum(c.isdigit() for c in domain) > 3:
            risk_score += 10
        
        # DNS features
        if dns_analysis.get('typosquatting'):
            risk_score += 40
        
        if dns_analysis.get('homograph'):
            risk_score += 35
        
        domain_age = dns_analysis.get('domain_age_days', 0)
        if domain_age < 7:
            risk_score += 25
        elif domain_age < 30:
            risk_score += 15
        
        if not dns_analysis.get('ssl_valid'):
            risk_score += 20
        
        # URL features
        if url_analysis.get('suspicious_tld'):
            risk_score += 15
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        return {
            'is_phishing': risk_score >= 70,
            'risk_score': risk_score,
            'confidence': 0.75,
            'model_used': 'rule_based'
        }
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text
        
        Args:
            text: Text to analyze
            
        Returns:
            Entropy value
        """
        if not text:
            return 0.0
        
        # Calculate frequency of each character
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in freq.values():
            probability = count / text_len
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _contains_brand_name(self, domain: str) -> float:
        """
        Check if domain contains known brand names
        
        Args:
            domain: Domain name
            
        Returns:
            1.0 if contains brand name, 0.0 otherwise
        """
        domain_lower = domain.lower()
        
        brands = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'facebook', 'twitter', 'linkedin', 'netflix', 'bank'
        ]
        
        for brand in brands:
            if brand in domain_lower:
                return 1.0
        
        return 0.0
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray):
        """
        Train the model
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        if not self.model:
            self._initialize_default_model()
        
        logger.info("Training domain model...")
        self.model.fit(X_train, y_train)
        
        # Save model
        self.save_model()
        
        logger.info("Domain model training complete")
    
    def save_model(self):
        """Save trained model"""
        model_path = self.config.DOMAIN_MODEL_PATH
        
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(self.model, model_path)
            logger.info(f"Domain model saved to {model_path}")
        except Exception as e:
            logger.error(f"Domain model save failed: {str(e)}")
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance"""
        if not self.model or not hasattr(self.model, 'feature_importances_'):
            return {}
        
        importances = self.model.feature_importances_
        return dict(zip(self.feature_names, importances))


# Factory function
def create_domain_classifier(config: Config) -> DomainClassifier:
    """Create domain classifier instance"""
    return DomainClassifier(config)