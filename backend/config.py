"""
SecureLink Guardian - Configuration
Environment-based configuration management
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """Base configuration"""
    
    # Application
    APP_NAME = "SecureLink Guardian"
    VERSION = "1.0.0"
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    ENV = os.getenv('ENV', 'development')
    
    # Server
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5000))
    
    # Security
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    API_KEY_HEADER = 'X-API-Key'
    
    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:8080,http://localhost:3000').split(',')
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
    RATE_LIMIT_DEFAULT = os.getenv('RATE_LIMIT_DEFAULT', '100 per hour')
    RATE_LIMIT_SCAN = os.getenv('RATE_LIMIT_SCAN', '20 per minute')
    
    # Redis
    REDIS_ENABLED = os.getenv('REDIS_ENABLED', 'True').lower() == 'true'
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
    REDIS_URL = os.getenv('REDIS_URL', f'redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}')
    
    # MongoDB
    MONGODB_ENABLED = os.getenv('MONGODB_ENABLED', 'True').lower() == 'true'
    MONGODB_HOST = os.getenv('MONGODB_HOST', 'localhost')
    MONGODB_PORT = int(os.getenv('MONGODB_PORT', 27017))
    MONGODB_DB = os.getenv('MONGODB_DB', 'securelink_guardian')
    MONGODB_USERNAME = os.getenv('MONGODB_USERNAME', None)
    MONGODB_PASSWORD = os.getenv('MONGODB_PASSWORD', None)
    
    # MongoDB URL construction
    if MONGODB_USERNAME and MONGODB_PASSWORD:
        MONGODB_URL = f'mongodb://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DB}'
    else:
        MONGODB_URL = f'mongodb://{MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DB}'
    
    # Cache Settings
    CACHE_TTL_SHORT = int(os.getenv('CACHE_TTL_SHORT', 300))  # 5 minutes
    CACHE_TTL_MEDIUM = int(os.getenv('CACHE_TTL_MEDIUM', 3600))  # 1 hour
    CACHE_TTL_LONG = int(os.getenv('CACHE_TTL_LONG', 86400))  # 24 hours
    
    # Detection Settings
    ENABLE_DNS_ANALYSIS = os.getenv('ENABLE_DNS_ANALYSIS', 'True').lower() == 'true'
    ENABLE_URL_ANALYSIS = os.getenv('ENABLE_URL_ANALYSIS', 'True').lower() == 'true'
    ENABLE_WEB_ANALYSIS = os.getenv('ENABLE_WEB_ANALYSIS', 'True').lower() == 'true'
    ENABLE_ML_ANALYSIS = os.getenv('ENABLE_ML_ANALYSIS', 'True').lower() == 'true'
    ENABLE_GENETIC_ANALYSIS = os.getenv('ENABLE_GENETIC_ANALYSIS', 'True').lower() == 'true'
    
    # Sandbox Settings
    SANDBOX_TIMEOUT = int(os.getenv('SANDBOX_TIMEOUT', 30))  # seconds
    SANDBOX_MAX_REDIRECTS = int(os.getenv('SANDBOX_MAX_REDIRECTS', 5))
    SANDBOX_USER_AGENT = os.getenv('SANDBOX_USER_AGENT', 
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
    
    # ML Model Paths
    MODEL_DIR = os.getenv('MODEL_DIR', 'backend/ml/models')
    PHISHING_MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_classifier.pkl')
    DOMAIN_MODEL_PATH = os.path.join(MODEL_DIR, 'domain_classifier.pkl')
    
    # Risk Scoring Weights
    WEIGHT_DNS = float(os.getenv('WEIGHT_DNS', 0.3))
    WEIGHT_URL = float(os.getenv('WEIGHT_URL', 0.25))
    WEIGHT_WEB = float(os.getenv('WEIGHT_WEB', 0.3))
    WEIGHT_ML = float(os.getenv('WEIGHT_ML', 0.15))
    
    # Thresholds
    RISK_THRESHOLD_LOW = int(os.getenv('RISK_THRESHOLD_LOW', 30))
    RISK_THRESHOLD_HIGH = int(os.getenv('RISK_THRESHOLD_HIGH', 70))
    
    # Domain Age Thresholds (days)
    DOMAIN_AGE_SUSPICIOUS = int(os.getenv('DOMAIN_AGE_SUSPICIOUS', 30))
    DOMAIN_AGE_NEW = int(os.getenv('DOMAIN_AGE_NEW', 7))
    
    # Trusted Domains
    TRUSTED_DOMAINS = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
        'stackoverflow.com', 'reddit.com', 'youtube.com', 'wikipedia.org',
        'paypal.com', 'stripe.com', 'cloudflare.com', 'netlify.com'
    ]
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
        '.click', '.link', '.download', '.zip', '.loan', '.win'
    ]
    
    # URL Shorteners
    URL_SHORTENERS = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd',
        'buff.ly', 'adf.ly', 'bit.do', 'lnkd.in', 'shorturl.at',
        'rebrand.ly', 'cutt.ly', 'bl.ink', 'tiny.cc'
    ]
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = os.getenv('LOG_FILE', 'logs/securelink.log')
    
    @classmethod
    def get_redis_config(cls) -> dict:
        """Get Redis configuration"""
        config = {
            'host': cls.REDIS_HOST,
            'port': cls.REDIS_PORT,
            'db': cls.REDIS_DB,
            'decode_responses': True
        }
        if cls.REDIS_PASSWORD:
            config['password'] = cls.REDIS_PASSWORD
        return config
    
    @classmethod
    def get_mongodb_config(cls) -> dict:
        """Get MongoDB configuration"""
        return {
            'url': cls.MONGODB_URL,
            'db': cls.MONGODB_DB
        }
    
    @classmethod
    def validate(cls):
        """Validate configuration"""
        errors = []
        
        # Check required directories
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        if not os.path.exists(cls.MODEL_DIR):
            os.makedirs(cls.MODEL_DIR)
        
        # Validate weights sum to 1.0
        total_weight = cls.WEIGHT_DNS + cls.WEIGHT_URL + cls.WEIGHT_WEB + cls.WEIGHT_ML
        if abs(total_weight - 1.0) > 0.01:
            errors.append(f"Risk weights must sum to 1.0, got {total_weight}")
        
        if errors:
            raise ValueError(f"Configuration errors: {', '.join(errors)}")
        
        return True


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    ENV = 'development'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    ENV = 'production'
    RATE_LIMIT_DEFAULT = '50 per hour'
    RATE_LIMIT_SCAN = '10 per minute'


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    ENV = 'testing'
    REDIS_DB = 1  # Use separate Redis DB for testing
    MONGODB_DB = 'securelink_guardian_test'


# Configuration factory
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}

def get_config(env: Optional[str] = None) -> Config:
    """Get configuration based on environment"""
    if env is None:
        env = os.getenv('ENV', 'development')
    
    config_class = config_map.get(env, DevelopmentConfig)
    config = config_class()
    config.validate()
    
    return config