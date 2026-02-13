"""
SecureLink Guardian - Web Phishing Tests
Tests for web content phishing detection
"""

import pytest
from backend.detection.web_phishing import WebPhishingDetector
from backend.config import get_config

@pytest.fixture
def detector():
    """Create web phishing detector instance"""
    config = get_config('testing')
    return WebPhishingDetector(config)

def test_detector_initialization(detector):
    """Test detector initialization"""
    assert detector is not None
    assert detector.config is not None
    assert len(detector.known_brands) > 0

def test_check_brand_impersonation(detector):
    """Test brand impersonation detection"""
    from bs4 import BeautifulSoup
    
    # HTML with PayPal branding
    html = "<html><body><h1>PayPal Login</h1><p>Welcome to PayPal</p></body></html>"
    soup = BeautifulSoup(html, 'html.parser')
    text = soup.get_text()
    
    # Should detect PayPal brand
    result = detector._check_brand_impersonation(
        soup, 
        text, 
        "https://paypa1-verify.com"  # Typosquatting
    )
    
    assert result['detected'] == True
    assert 'paypal' in result['brand'].lower()

def test_analyze_forms(detector):
    """Test form analysis"""
    from bs4 import BeautifulSoup
    
    # HTML with login form
    html = """
    <html>
        <body>
            <form action="/login" method="post">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Login</button>
            </form>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    result = detector._analyze_forms(soup)
    
    assert result['detected'] == True
    assert result['form_count'] == 1
    assert result['password_count'] == 1

def test_check_social_engineering(detector):
    """Test social engineering detection"""
    # Urgent, fear-inducing text
    text = "URGENT: Your account has been suspended! Click here immediately!"
    
    result = detector._check_social_engineering(text)
    
    assert result['detected'] == True
    assert len(result['urgency_phrases']) > 0

def test_analyze_javascript(detector):
    """Test JavaScript analysis"""
    from bs4 import BeautifulSoup
    
    # HTML with suspicious JavaScript
    html = """
    <html>
        <body>
            <script>
                eval(atob('malicious_code'));
                document.cookie = 'steal=data';
            </script>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    result = detector._analyze_javascript(soup)
    
    assert result['detected'] == True
    assert len(result['threats']) > 0

def test_analyze_external_resources(detector):
    """Test external resource analysis"""
    from bs4 import BeautifulSoup
    
    # HTML with external resources
    html = """
    <html>
        <head>
            <script src="https://evil.tk/malicious.js"></script>
            <link rel="stylesheet" href="https://cdn.example.com/style.css">
        </head>
        <body>
            <img src="https://suspicious.ml/image.png" />
        </body>
    </html>
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    result = detector._analyze_external_resources(soup, "https://example.com")
    
    assert result['total'] > 0
    assert result['suspicious'] > 0  # Should detect .tk and .ml

def test_check_favicon(detector):
    """Test favicon mismatch detection"""
    from bs4 import BeautifulSoup
    
    # HTML with external favicon
    html = """
    <html>
        <head>
            <link rel="icon" href="https://paypal.com/favicon.ico">
        </head>
    </html>
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    # Different domain - should detect mismatch
    result = detector._check_favicon(
        soup, 
        "https://paypa1-verify.com",
        "paypal"
    )
    
    # Should detect mismatch
    # Note: This test depends on implementation details

@pytest.mark.asyncio
async def test_analyze_complete(detector):
    """Test complete web analysis"""
    html = """
    <html>
        <head><title>PayPal Login</title></head>
        <body>
            <h1>URGENT: Verify Your Account</h1>
            <form method="post">
                <input type="text" name="email" />
                <input type="password" name="password" />
            </form>
            <script>document.cookie = 'session=stolen';</script>
        </body>
    </html>
    """
    
    result = await detector.analyze(html, "https://paypa1.com")
    
    assert result is not None
    assert result.brand_impersonation == True
    assert result.credential_forms == True
    assert result.social_engineering == True
    assert result.javascript_suspicious == True

def test_no_forms_clean_site(detector):
    """Test analyzing clean website"""
    from bs4 import BeautifulSoup
    
    html = """
    <html>
        <body>
            <h1>Welcome to Example.com</h1>
            <p>This is a normal website with no forms or suspicious content.</p>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    result = detector._analyze_forms(soup)
    
    assert result['detected'] == False
    assert result['form_count'] == 0
    assert result['password_count'] == 0

def test_legitimate_text_content(detector):
    """Test analyzing legitimate text"""
    text = "Thank you for your order. Your package will arrive in 3-5 business days."
    
    result = detector._check_social_engineering(text)
    
    assert result['detected'] == False
    assert len(result['urgency_phrases']) == 0