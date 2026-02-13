"""
SecureLink Guardian - Genetic Matcher Tests
Tests for DNA-inspired phishing detection
"""

import pytest
from backend.core.genetic_matcher import GeneticURLMatcher
from backend.config import get_config

@pytest.fixture
def matcher():
    """Create genetic matcher instance"""
    config = get_config('testing')
    return GeneticURLMatcher(config)

def test_matcher_initialization(matcher):
    """Test matcher initialization"""
    assert matcher is not None
    assert matcher.config is not None
    assert len(matcher.campaign_signatures) > 0

def test_encode_as_dna(matcher):
    """Test DNA encoding"""
    domain = "example.com"
    dna = matcher._encode_as_dna(domain)
    
    assert dna is not None
    assert len(dna) == len(domain)
    assert all(base in ['A', 'T', 'G', 'C'] for base in dna)

def test_match_campaign_family(matcher):
    """Test campaign family matching"""
    # Known campaign pattern
    result = matcher._match_campaign_family("amaz0n-secure.com")
    assert result['detected'] == True
    assert 'amazon' in result.get('family', '').lower()
    
    # Non-campaign domain
    result = matcher._match_campaign_family("google.com")
    assert result['detected'] == False

def test_calculate_dna_similarity(matcher, sample_domains):
    """Test DNA similarity calculation"""
    # Typosquatting domain
    result = matcher._calculate_dna_similarity(
        "g00gle.com",
        sample_domains['legitimate']
    )
    
    assert 'similarity' in result
    assert result['similarity'] > 0.7  # Should be similar to google.com
    assert result['closest_match'] == 'google.com'

def test_evolutionary_distance(matcher):
    """Test evolutionary distance calculation"""
    distance = matcher._calculate_evolutionary_distance(
        "amazon.com",
        "amaz0n.com"
    )
    
    assert distance is not None
    assert distance > 0
    assert distance < 5  # Should be relatively small

def test_check_mutation_patterns(matcher):
    """Test mutation pattern detection"""
    # Character substitution
    assert matcher._check_mutation_patterns("amaz0n.com") == True
    assert matcher._check_mutation_patterns("paypa1.com") == True
    
    # Legitimate domain
    assert matcher._check_mutation_patterns("amazon.com") == False

@pytest.mark.asyncio
async def test_analyze(matcher, sample_domains):
    """Test full genetic analysis"""
    result = await matcher.analyze(
        "https://amaz0n.com",
        sample_domains['legitimate']
    )
    
    assert result is not None
    assert result.dna_similarity_score is not None

def test_generate_mutation_variants(matcher):
    """Test mutation variant generation"""
    variants = matcher.generate_mutation_variants("amazon.com", max_variants=10)
    
    assert len(variants) <= 10
    assert all(isinstance(v, str) for v in variants)
    assert "amazon.com" not in variants  # Original should not be in variants

def test_calculate_campaign_fingerprint(matcher):
    """Test campaign fingerprinting"""
    domains = ["amaz0n.com", "amazom.com", "amajon.com"]
    fingerprint = matcher.calculate_campaign_fingerprint(domains)
    
    assert fingerprint is not None
    assert len(fingerprint) == 16  # SHA256 truncated to 16 chars

def test_homoglyph_detection(matcher):
    """Test homoglyph detection"""
    # Domain with Cyrillic 'а'
    result = matcher._check_mutation_patterns("аmazon.com")
    # This test depends on implementation

def test_skeleton_generation(matcher):
    """Test URL skeleton generation"""
    from backend.utils.unicode_normalizer import unicode_normalizer
    
    skeleton1 = unicode_normalizer.get_skeleton("amazon.com")
    skeleton2 = unicode_normalizer.get_skeleton("amaz0n.com")
    
    # Different skeletons for different domains
    assert skeleton1 != skeleton2