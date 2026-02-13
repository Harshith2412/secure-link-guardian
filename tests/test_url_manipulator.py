"""
SecureLink Guardian - URL Manipulator Tests
Tests for URL manipulation detection
"""

import pytest
from backend.detection.url_manipulator import URLManipulationDetector
from backend.config import get_config

@pytest.fixture
def manipulator():
    """Create URL manipulator instance"""
    config = get_config('testing')
    return URLManipulationDetector(config)

def test_manipulator_initialization(manipulator):
    """Test manipulator initialization"""
    assert manipulator is not None
    assert manipulator.config is not None
    assert len(manipulator.shorteners) > 0

def test_check_shortener(manipulator):
    """Test URL shortener detection"""
    from backend.utils.url_parser import url_parser
    
    # Known shortener
    parsed = url_parser.parse("https://bit.ly/test")
    result = manipulator._check_shortener("https://bit.ly/test", parsed)
    assert result['detected'] == True
    assert result['service'] == 'bit.ly'
    
    # Regular URL
    parsed = url_parser.parse("https://google.com")
    result = manipulator._check_shortener("https://google.com", parsed)
    assert result['detected'] == False

def test_trace_redirects(manipulator):
    """Test redirect tracing"""
    # This requires actual HTTP requests
    # For now, test with a non-redirecting URL
    result = manipulator._trace_redirects("https://example.com")
    assert 'chain' in result
    assert 'count' in result

def test_check_open_redirect(manipulator):
    """Test open redirect detection"""
    from backend.utils.url_parser import url_parser
    
    # URL with redirect parameter
    parsed = url_parser.parse("https://example.com?redirect=https://evil.com")
    result = manipulator._check_open_redirect(parsed)
    assert result == True
    
    # Clean URL
    parsed = url_parser.parse("https://example.com")
    result = manipulator._check_open_redirect(parsed)
    assert result == False

def test_check_suspicious_tld(manipulator):
    """Test suspicious TLD detection"""
    # Suspicious TLD
    assert manipulator._check_suspicious_tld("tk") == True
    assert manipulator._check_suspicious_tld("ml") == True
    
    # Normal TLD
    assert manipulator._check_suspicious_tld("com") == False
    assert manipulator._check_suspicious_tld("org") == False

@pytest.mark.asyncio
async def test_analyze(manipulator, sample_urls):
    """Test full URL analysis"""
    url = sample_urls['legitimate'][0]
    result = await manipulator.analyze(url)
    
    assert result is not None
    assert hasattr(result, 'is_shortener')
    assert hasattr(result, 'redirect_count')
    assert hasattr(result, 'suspicious_params')

@pytest.mark.asyncio
async def test_analyze_shortener(manipulator):
    """Test analyzing URL shortener"""
    url = "https://bit.ly/test"
    result = await manipulator.analyze(url)
    
    assert result.is_shortener == True
    assert result.shortener_service == 'bit.ly'

@pytest.mark.asyncio
async def test_analyze_suspicious_params(manipulator):
    """Test analyzing suspicious parameters"""
    url = "https://example.com?redirect=https://malicious.com"
    result = await manipulator.analyze(url)
    
    assert result.suspicious_params == True