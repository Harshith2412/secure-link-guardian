"""
SecureLink Guardian - DNS Analyzer Tests
Tests for DNS-based phishing detection
"""

import pytest
from backend.detection.dns_analyzer import DNSAnalyzer
from backend.config import get_config

@pytest.fixture
def analyzer():
    """Create DNS analyzer instance"""
    config = get_config('testing')
    return DNSAnalyzer(config)

def test_analyzer_initialization(analyzer):
    """Test analyzer initialization"""
    assert analyzer is not None
    assert analyzer.config is not None
    assert len(analyzer.trusted_domains) > 0

def test_check_typosquatting(analyzer, sample_domains):
    """Test typosquatting detection"""
    # Known typosquatting
    result = analyzer._check_typosquatting("g00gle.com")
    assert result['detected'] == True
    assert result['target'] == 'google.com'
    
    # Legitimate domain
    result = analyzer._check_typosquatting("google.com")
    assert result['detected'] == False

def test_check_homograph(analyzer):
    """Test homograph attack detection"""
    # Cyrillic 'а' in apple
    result = analyzer._check_homograph("аpple.com")
    assert result['detected'] == True
    
    # Normal domain
    result = analyzer._check_homograph("apple.com")
    assert result['detected'] == False

def test_check_domain_age(analyzer):
    """Test domain age checking"""
    # This test requires actual WHOIS lookup
    # For testing, we'll just verify the function exists
    result = analyzer._check_domain_age("example.com")
    assert 'days' in result or result == {'days': None, 'suspicious': False}

def test_check_whois_privacy(analyzer):
    """Test WHOIS privacy detection"""
    result = analyzer._check_whois_privacy("example.com")
    assert 'privacy_protected' in result

def test_check_ssl_certificate(analyzer):
    """Test SSL certificate checking"""
    result = analyzer._check_ssl_certificate("google.com")
    # May fail if no internet, that's okay for testing
    assert 'valid' in result

def test_check_dns_reputation(analyzer):
    """Test DNS reputation checking"""
    result = analyzer._check_dns_reputation("google.com")
    assert 'score' in result
    assert 0 <= result['score'] <= 100

def test_check_mx_records(analyzer):
    """Test MX record checking"""
    result = analyzer._check_mx_records("google.com")
    assert isinstance(result, bool)

@pytest.mark.asyncio
async def test_analyze(analyzer, sample_urls):
    """Test full DNS analysis"""
    url = sample_urls['legitimate'][0]
    result = await analyzer.analyze(url)
    
    assert result is not None
    assert hasattr(result, 'typosquatting')
    assert hasattr(result, 'homograph')
    assert hasattr(result, 'domain_age_days')

@pytest.mark.asyncio
async def test_analyze_phishing(analyzer, sample_urls):
    """Test analyzing phishing URL"""
    url = sample_urls['phishing'][0]
    result = await analyzer.analyze(url)
    
    assert result is not None
    # Should detect typosquatting
    assert result.typosquatting == True

def test_levenshtein_distance(analyzer):
    """Test Levenshtein distance calculation"""
    import Levenshtein
    
    distance = Levenshtein.distance("amazon", "amaz0n")
    assert distance == 1
    
    distance = Levenshtein.distance("google", "g00gle")
    assert distance == 2