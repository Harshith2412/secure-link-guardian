"""
SecureLink Guardian - NLP Analyzer Tests
Tests for natural language processing
"""

import pytest
from backend.ml.nlp_analyzer import NLPAnalyzer
from backend.config import get_config

@pytest.fixture
def nlp():
    """Create NLP analyzer instance"""
    config = get_config('testing')
    return NLPAnalyzer(config)

def test_nlp_initialization(nlp):
    """Test NLP analyzer initialization"""
    assert nlp is not None
    assert nlp.config is not None
    assert len(nlp.urgency_keywords) > 0

def test_analyze_sentiment(nlp, sample_texts):
    """Test sentiment analysis"""
    # Negative/urgent text
    result = nlp._analyze_sentiment(sample_texts['phishing'][0])
    assert 'polarity' in result
    assert 'subjectivity' in result
    assert 'category' in result
    
    # Neutral/positive text
    result = nlp._analyze_sentiment(sample_texts['legitimate'][0])
    assert result['category'] in ['positive', 'neutral']

def test_detect_urgency(nlp, sample_texts):
    """Test urgency detection"""
    # Urgent text
    result = nlp._detect_urgency(sample_texts['phishing'][0])
    assert result['detected'] == True
    assert result['score'] > 0
    assert len(result['keywords']) > 0
    
    # Non-urgent text
    result = nlp._detect_urgency(sample_texts['legitimate'][0])
    assert result['detected'] == False or result['score'] < 50

def test_detect_fear_tactics(nlp):
    """Test fear tactics detection"""
    # Fear-inducing text
    text = "Your account has been compromised and locked!"
    result = nlp._detect_fear_tactics(text)
    assert result['detected'] == True
    
    # Normal text
    text = "Thank you for your order"
    result = nlp._detect_fear_tactics(text)
    assert result['detected'] == False

def test_detect_scarcity(nlp):
    """Test scarcity tactics detection"""
    # Scarcity text
    text = "Limited time offer! Only 5 left! Last chance!"
    result = nlp._detect_scarcity(text)
    assert result['detected'] == True
    
    # Normal text
    text = "We have many options available"
    result = nlp._detect_scarcity(text)
    assert result['detected'] == False

def test_analyze_linguistic_features(nlp):
    """Test linguistic feature analysis"""
    text = "URGENT!!! Your account has been suspended!!!"
    result = nlp._analyze_linguistic_features(text)
    
    assert result['word_count'] > 0
    assert result['exclamation_marks'] > 0
    assert result['caps_words'] > 0

def test_detect_grammar_issues(nlp):
    """Test grammar issue detection"""
    # Poor grammar
    text = "You  has been  suspended.Act now!!"
    issues = nlp._detect_grammar_issues(text)
    assert issues > 0
    
    # Good grammar
    text = "Your account has been updated. Please review."
    issues = nlp._detect_grammar_issues(text)
    assert issues == 0 or issues < 3

def test_calculate_text_risk_score(nlp, sample_texts):
    """Test risk score calculation"""
    # High risk text
    urgency = {'score': 90}
    fear = {'score': 80}
    scarcity = {'score': 70}
    patterns = ['urgent', 'act now', 'suspended']
    linguistic = {'grammar_issues': 3, 'caps_words': 5, 'exclamation_marks': 4}
    
    score = nlp._calculate_text_risk_score(urgency, fear, scarcity, patterns, linguistic)
    assert score > 50

def test_analyze_full(nlp, sample_texts):
    """Test full NLP analysis"""
    # Phishing text
    result = nlp.analyze(sample_texts['phishing'][0])
    assert result['risk_score'] > 50
    assert result['suspicious'] == True
    
    # Legitimate text
    result = nlp.analyze(sample_texts['legitimate'][0])
    assert result['risk_score'] < 60