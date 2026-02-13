"""
SecureLink Guardian - Detector Tests
Tests for main phishing detector
"""

import pytest
from backend.core.detector import PhishingDetector
from backend.config import get_config

@pytest.fixture
def detector():
    """Create detector instance"""
    config = get_config('testing')
    return PhishingDetector(config)

@pytest.mark.asyncio
async def test_detector_initialization(detector):
    """Test detector initialization"""
    assert detector is not None
    assert detector.config is not None
    assert detector.dns_analyzer is not None
    assert detector.url_manipulator is not None

@pytest.mark.asyncio
async def test_analyze_legitimate_url(detector, sample_urls):
    """Test analyzing legitimate URL"""
    url = sample_urls['legitimate'][0]
    result = await detector.analyze(url)
    
    assert result is not None
    assert 'dns' in result
    assert 'url' in result

@pytest.mark.asyncio
async def test_analyze_phishing_url(detector, sample_urls):
    """Test analyzing phishing URL"""
    url = sample_urls['phishing'][0]
    result = await detector.analyze(url)
    
    assert result is not None
    assert 'dns' in result
    assert 'url' in result

def test_feature_extraction(detector, sample_urls, mock_dns_response, mock_url_response):
    """Test feature extraction"""
    url = sample_urls['legitimate'][0]
    results = {
        'dns': mock_dns_response,
        'url': mock_url_response
    }
    
    features = detector._extract_features(url, results)
    assert features is not None
    assert isinstance(features, dict)

@pytest.mark.asyncio
async def test_analyze_with_options(detector, sample_urls):
    """Test analyze with different options"""
    url = sample_urls['legitimate'][0]
    
    # Test with deep scan
    result = await detector.analyze(url, {'deep_scan': True})
    assert result is not None
    
    # Test without deep scan
    result = await detector.analyze(url, {'deep_scan': False})
    assert result is not None

@pytest.mark.asyncio
async def test_analyze_invalid_url(detector):
    """Test analyzing invalid URL"""
    with pytest.raises(Exception):
        await detector.analyze("not-a-valid-url")

@pytest.mark.asyncio
async def test_analyze_multiple_urls(detector, sample_urls):
    """Test analyzing multiple URLs"""
    results = []
    
    for url in sample_urls['legitimate'][:2]:
        result = await detector.analyze(url)
        results.append(result)
    
    assert len(results) == 2
    assert all(r is not None for r in results)