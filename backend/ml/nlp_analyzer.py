"""
SecureLink Guardian - NLP Analyzer
Natural language processing for phishing text analysis
"""

import logging
from typing import Dict, List
import re
from textblob import TextBlob
from backend.config import Config
from backend.utils.patterns import phishing_patterns

logger = logging.getLogger(__name__)


class NLPAnalyzer:
    """NLP-based phishing text analysis"""
    
    def __init__(self, config: Config):
        self.config = config
        self.patterns = phishing_patterns
        
        # Urgency keywords with weights
        self.urgency_keywords = {
            'urgent': 3,
            'immediately': 3,
            'act now': 4,
            'limited time': 3,
            'expires': 2,
            'suspended': 4,
            'locked': 4,
            'verify': 2,
            'confirm': 2,
            'action required': 3,
            'security alert': 3,
            'unusual activity': 3
        }
        
        # Fear-inducing keywords
        self.fear_keywords = {
            'suspended': 4,
            'locked': 4,
            'blocked': 3,
            'unauthorized': 3,
            'fraudulent': 3,
            'compromised': 4,
            'breach': 4,
            'stolen': 4,
            'hacked': 4
        }
        
        # Scarcity keywords
        self.scarcity_keywords = {
            'limited': 2,
            'exclusive': 2,
            'only': 1,
            'last chance': 3,
            'final': 2,
            'ending': 2
        }
    
    def analyze(self, text: str, context: str = 'email') -> Dict:
        """
        Perform comprehensive NLP analysis
        
        Args:
            text: Text to analyze
            context: Context type (email, webpage, sms)
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing text ({len(text)} chars)")
        
        try:
            # Basic analysis
            sentiment = self._analyze_sentiment(text)
            urgency = self._detect_urgency(text)
            fear = self._detect_fear_tactics(text)
            scarcity = self._detect_scarcity(text)
            
            # Pattern matching
            patterns_found = self.patterns.check_urgency_language(text)
            brand_mentions = self.patterns.check_brand_keywords(text)
            
            # Linguistic features
            linguistic = self._analyze_linguistic_features(text)
            
            # Calculate risk score
            risk_score = self._calculate_text_risk_score(
                urgency, fear, scarcity, patterns_found, linguistic
            )
            
            return {
                'risk_score': risk_score,
                'sentiment': sentiment,
                'urgency': urgency,
                'fear_tactics': fear,
                'scarcity_tactics': scarcity,
                'patterns': {
                    'urgency_patterns': patterns_found,
                    'brand_mentions': brand_mentions
                },
                'linguistic_features': linguistic,
                'suspicious': risk_score > 60
            }
            
        except Exception as e:
            logger.error(f"NLP analysis error: {str(e)}")
            return {
                'risk_score': 50,
                'error': str(e)
            }
    
    def _analyze_sentiment(self, text: str) -> Dict:
        """
        Analyze text sentiment
        
        Args:
            text: Text to analyze
            
        Returns:
            Sentiment analysis results
        """
        try:
            blob = TextBlob(text)
            polarity = blob.sentiment.polarity
            subjectivity = blob.sentiment.subjectivity
            
            # Categorize sentiment
            if polarity > 0.1:
                category = 'positive'
            elif polarity < -0.1:
                category = 'negative'
            else:
                category = 'neutral'
            
            return {
                'polarity': round(polarity, 3),
                'subjectivity': round(subjectivity, 3),
                'category': category
            }
        except Exception as e:
            logger.debug(f"Sentiment analysis failed: {str(e)}")
            return {
                'polarity': 0.0,
                'subjectivity': 0.0,
                'category': 'unknown'
            }
    
    def _detect_urgency(self, text: str) -> Dict:
        """
        Detect urgency indicators
        
        Args:
            text: Text to analyze
            
        Returns:
            Urgency detection results
        """
        text_lower = text.lower()
        found_keywords = []
        total_score = 0
        
        for keyword, weight in self.urgency_keywords.items():
            count = text_lower.count(keyword)
            if count > 0:
                found_keywords.append({
                    'keyword': keyword,
                    'count': count,
                    'weight': weight
                })
                total_score += weight * count
        
        return {
            'detected': len(found_keywords) > 0,
            'score': min(100, total_score * 10),
            'keywords': found_keywords,
            'level': self._categorize_score(total_score * 10)
        }
    
    def _detect_fear_tactics(self, text: str) -> Dict:
        """
        Detect fear-inducing language
        
        Args:
            text: Text to analyze
            
        Returns:
            Fear tactics detection results
        """
        text_lower = text.lower()
        found_keywords = []
        total_score = 0
        
        for keyword, weight in self.fear_keywords.items():
            count = text_lower.count(keyword)
            if count > 0:
                found_keywords.append({
                    'keyword': keyword,
                    'count': count,
                    'weight': weight
                })
                total_score += weight * count
        
        return {
            'detected': len(found_keywords) > 0,
            'score': min(100, total_score * 10),
            'keywords': found_keywords,
            'level': self._categorize_score(total_score * 10)
        }
    
    def _detect_scarcity(self, text: str) -> Dict:
        """
        Detect scarcity tactics
        
        Args:
            text: Text to analyze
            
        Returns:
            Scarcity detection results
        """
        text_lower = text.lower()
        found_keywords = []
        total_score = 0
        
        for keyword, weight in self.scarcity_keywords.items():
            count = text_lower.count(keyword)
            if count > 0:
                found_keywords.append({
                    'keyword': keyword,
                    'count': count,
                    'weight': weight
                })
                total_score += weight * count
        
        return {
            'detected': len(found_keywords) > 0,
            'score': min(100, total_score * 10),
            'keywords': found_keywords
        }
    
    def _analyze_linguistic_features(self, text: str) -> Dict:
        """
        Analyze linguistic features
        
        Args:
            text: Text to analyze
            
        Returns:
            Linguistic features
        """
        # Count sentences
        sentences = re.split(r'[.!?]+', text)
        sentence_count = len([s for s in sentences if s.strip()])
        
        # Count words
        words = text.split()
        word_count = len(words)
        
        # Average word length
        avg_word_length = sum(len(word) for word in words) / word_count if word_count > 0 else 0
        
        # Count exclamation marks
        exclamation_count = text.count('!')
        
        # Count question marks
        question_count = text.count('?')
        
        # Count ALL CAPS words
        caps_words = sum(1 for word in words if word.isupper() and len(word) > 1)
        
        # Check for poor grammar (simple heuristic)
        grammar_issues = self._detect_grammar_issues(text)
        
        return {
            'sentence_count': sentence_count,
            'word_count': word_count,
            'avg_word_length': round(avg_word_length, 2),
            'exclamation_marks': exclamation_count,
            'question_marks': question_count,
            'caps_words': caps_words,
            'grammar_issues': grammar_issues,
            'readability': self._calculate_readability(text)
        }
    
    def _detect_grammar_issues(self, text: str) -> int:
        """
        Detect potential grammar issues (simple heuristics)
        
        Args:
            text: Text to analyze
            
        Returns:
            Number of potential issues
        """
        issues = 0
        
        # Multiple spaces
        if '  ' in text:
            issues += text.count('  ')
        
        # Missing spaces after punctuation
        if re.search(r'[.!?,][a-zA-Z]', text):
            issues += len(re.findall(r'[.!?,][a-zA-Z]', text))
        
        # Multiple punctuation
        if re.search(r'[!?.]{2,}', text):
            issues += len(re.findall(r'[!?.]{2,}', text))
        
        return issues
    
    def _calculate_readability(self, text: str) -> Dict:
        """
        Calculate readability metrics
        
        Args:
            text: Text to analyze
            
        Returns:
            Readability metrics
        """
        sentences = re.split(r'[.!?]+', text)
        sentence_count = len([s for s in sentences if s.strip()])
        
        words = text.split()
        word_count = len(words)
        
        # Simple complexity score
        avg_sentence_length = word_count / sentence_count if sentence_count > 0 else 0
        
        if avg_sentence_length < 10:
            complexity = 'simple'
        elif avg_sentence_length < 20:
            complexity = 'moderate'
        else:
            complexity = 'complex'
        
        return {
            'avg_sentence_length': round(avg_sentence_length, 2),
            'complexity': complexity
        }
    
    def _calculate_text_risk_score(
        self, 
        urgency: Dict, 
        fear: Dict, 
        scarcity: Dict,
        patterns: List,
        linguistic: Dict
    ) -> int:
        """
        Calculate overall text risk score
        
        Args:
            urgency: Urgency detection results
            fear: Fear detection results
            scarcity: Scarcity detection results
            patterns: Pattern matching results
            linguistic: Linguistic features
            
        Returns:
            Risk score 0-100
        """
        score = 0
        
        # Urgency score (30% weight)
        score += urgency.get('score', 0) * 0.3
        
        # Fear tactics (30% weight)
        score += fear.get('score', 0) * 0.3
        
        # Scarcity tactics (20% weight)
        score += scarcity.get('score', 0) * 0.2
        
        # Pattern matches (10% weight)
        score += min(100, len(patterns) * 20) * 0.1
        
        # Linguistic issues (10% weight)
        grammar_score = min(100, linguistic.get('grammar_issues', 0) * 20)
        caps_score = min(100, linguistic.get('caps_words', 0) * 10)
        exclaim_score = min(100, linguistic.get('exclamation_marks', 0) * 5)
        
        linguistic_score = (grammar_score + caps_score + exclaim_score) / 3
        score += linguistic_score * 0.1
        
        return min(100, int(score))
    
    def _categorize_score(self, score: int) -> str:
        """Categorize risk score into levels"""
        if score < 30:
            return 'low'
        elif score < 60:
            return 'medium'
        else:
            return 'high'


# Factory function
def create_nlp_analyzer(config: Config) -> NLPAnalyzer:
    """Create NLP analyzer instance"""
    return NLPAnalyzer(config)