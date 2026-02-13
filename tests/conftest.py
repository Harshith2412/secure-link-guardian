"""
SecureLink Guardian - Test Configuration
Pytest fixtures and configuration
"""

import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import get_config, TestingConfig
from backend.app import app as flask_app

@pytest.fixture(scope="session")
def config():
    """Test configuration"""
    return get_config('testing')

@pytest.fixture(scope="session")
def app():
    """Flask application fixture"""
    flask_app.config.from_object(TestingConfig)
    return flask_app

@pytest.fixture(scope="function")
def client(app):
    """Flask test client"""
    return app.test_client()

@pytest.fixture(scope="session")
def sample_urls():
    """Sample URLs for testing"""
    return {
        'legitimate': [
            'https://google.com',
            'https://microsoft.com',
            'https://github.com',
            'https://amazon.com'
        ],
        'phishing': [
            'https://amaz0n-secure.com',
            'https://paypa1-verify.com',
            'https://micros0ft-login.com',
            'https://app1e-id.com'
        ],
        'suspicious': [
            'https://bit.ly/test',
            'https://secure-login.tk',
            'https://verify-account.ml'
        ]
    }

@pytest.fixture(scope="session")
def sample_domains():
    """Sample domains for testing"""
    return {
        'legitimate': [
            'google.com',
            'microsoft.com',
            'amazon.com',
            'paypal.com'
        ],
        'typosquatting': [
            'g00gle.com',
            'micros0ft.com',
            'amaz0n.com',
            'paypa1.com'
        ],
        'homograph': [
            'аpple.com',  # Cyrillic 'а'
            'раypal.com'  # Cyrillic 'р' and 'а'
        ]
    }

@pytest.fixture(scope="session")
def sample_texts():
    """Sample texts for NLP testing"""
    return {
        'phishing': [
            "URGENT: Your account has been suspended!",
            "Security Alert: Unusual activity detected.",
            "Click here immediately to verify your identity.",
            "Your payment failed. Update billing within 24 hours."
        ],
        'legitimate': [
            "Thank you for your order.",
            "Your monthly statement is available.",
            "We appreciate your business.",
            "Please review our updated terms."
        ]
    }

@pytest.fixture(scope="function")
def mock_dns_response():
    """Mock DNS response"""
    return {
        'typosquatting': False,
        'homograph': False,
        'domain_age_days': 365,
        'ssl_valid': True,
        'dns_reputation_score': 80,
        'mx_records_exist': True
    }

@pytest.fixture(scope="function")
def mock_url_response():
    """Mock URL analysis response"""
    return {
        'is_shortener': False,
        'redirect_count': 0,
        'suspicious_params': False,
        'encoding_tricks': False,
        'suspicious_tld': False
    }

@pytest.fixture(scope="function")
def mock_web_response():
    """Mock web analysis response"""
    return {
        'brand_impersonation': False,
        'credential_forms': False,
        'social_engineering': False,
        'javascript_suspicious': False
    }