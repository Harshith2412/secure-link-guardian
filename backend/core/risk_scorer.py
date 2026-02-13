"""
SecureLink Guardian - Risk Scorer
Calculate overall risk score from multiple analysis factors
"""

from typing import Dict
from backend.config import Config
import logging

logger = logging.getLogger(__name__)


class RiskScorer:
    """Risk score calculator"""
    
    def __init__(self, config: Config):
        self.config = config
        self.weight_dns = config.WEIGHT_DNS
        self.weight_url = config.WEIGHT_URL
        self.weight_web = config.WEIGHT_WEB
        self.weight_ml = config.WEIGHT_ML
    
    def calculate_score(self, analysis_results: Dict) -> int:
        """
        Calculate overall risk score from all analyses
        
        Args:
            analysis_results: Dictionary containing all analysis results
            
        Returns:
            Risk score from 0-100
        """
        scores = []
        weights = []
        
        # DNS Analysis Score
        if 'dns' in analysis_results and analysis_results['dns']:
            dns_score = self._score_dns_analysis(analysis_results['dns'])
            scores.append(dns_score)
            weights.append(self.weight_dns)
            logger.debug(f"DNS score: {dns_score}")
        
        # URL Analysis Score
        if 'url' in analysis_results and analysis_results['url']:
            url_score = self._score_url_analysis(analysis_results['url'])
            scores.append(url_score)
            weights.append(self.weight_url)
            logger.debug(f"URL score: {url_score}")
        
        # Web Analysis Score
        if 'web' in analysis_results and analysis_results['web']:
            web_score = self._score_web_analysis(analysis_results['web'])
            scores.append(web_score)
            weights.append(self.weight_web)
            logger.debug(f"Web score: {web_score}")
        
        # ML Analysis Score
        if 'ml' in analysis_results and analysis_results['ml']:
            ml_score = analysis_results['ml'].get('risk_score', 50)
            scores.append(ml_score)
            weights.append(self.weight_ml)
            logger.debug(f"ML score: {ml_score}")
        
        # Calculate weighted average
        if not scores:
            return 50  # Neutral score if no analysis available
        
        # Normalize weights
        total_weight = sum(weights)
        if total_weight > 0:
            normalized_weights = [w / total_weight for w in weights]
        else:
            normalized_weights = [1.0 / len(scores)] * len(scores)
        
        # Calculate weighted score
        weighted_score = sum(s * w for s, w in zip(scores, normalized_weights))
        
        # Ensure score is between 0 and 100
        final_score = max(0, min(100, int(weighted_score)))
        
        logger.info(f"Final risk score: {final_score}/100")
        return final_score
    
    def _score_dns_analysis(self, dns_result) -> int:
        """
        Score DNS analysis results
        
        Args:
            dns_result: DNSAnalysisResult object
            
        Returns:
            Risk score 0-100
        """
        score = 0
        
        # Typosquatting (high weight)
        if dns_result.typosquatting:
            score += 40
        
        # Homograph attack (high weight)
        if dns_result.homograph:
            score += 35
        
        # Domain age
        if dns_result.domain_age_days is not None:
            if dns_result.domain_age_days < 7:
                score += 25
            elif dns_result.domain_age_days < 30:
                score += 15
            elif dns_result.domain_age_days < 90:
                score += 5
        
        # WHOIS privacy (minor indicator)
        if dns_result.whois_privacy:
            score += 5
        
        # SSL certificate
        if not dns_result.ssl_valid:
            score += 20
        elif dns_result.ssl_expiry_days and dns_result.ssl_expiry_days < 30:
            score += 10
        
        # DNS reputation
        if dns_result.dns_reputation_score is not None:
            # Low reputation increases score
            reputation_risk = 100 - dns_result.dns_reputation_score
            score += int(reputation_risk * 0.2)  # Max 20 points from reputation
        
        # No MX records (legitimate sites usually have email)
        if not dns_result.mx_records_exist:
            score += 5
        
        return min(100, score)
    
    def _score_url_analysis(self, url_result) -> int:
        """
        Score URL manipulation analysis results
        
        Args:
            url_result: URLAnalysisResult object
            
        Returns:
            Risk score 0-100
        """
        score = 0
        
        # URL shortener
        if url_result.is_shortener:
            score += 25
        
        # Redirect chain
        if url_result.redirect_count > 0:
            score += min(30, url_result.redirect_count * 10)
        
        # Suspicious parameters
        if url_result.suspicious_params:
            param_count = len(url_result.suspicious_param_details or [])
            score += min(25, param_count * 10)
        
        # Encoding tricks
        if url_result.encoding_tricks:
            score += 20
        
        # Open redirect
        if url_result.open_redirect:
            score += 30
        
        # Suspicious TLD
        if url_result.suspicious_tld:
            score += 15
        
        # Excessive subdomains
        if url_result.subdomain_suspicious:
            score += 10
        
        return min(100, score)
    
    def _score_web_analysis(self, web_result) -> int:
        """
        Score web content analysis results
        
        Args:
            web_result: WebAnalysisResult object
            
        Returns:
            Risk score 0-100
        """
        score = 0
        
        # Brand impersonation (very high weight)
        if web_result.brand_impersonation:
            score += 40
            # Visual similarity adds more
            if web_result.visual_similarity_score:
                score += int(web_result.visual_similarity_score * 20)
        
        # Credential forms (high weight)
        if web_result.credential_forms:
            score += 30
            # More password fields = more suspicious
            score += min(20, web_result.password_fields * 10)
        
        # Social engineering
        if web_result.social_engineering:
            score += 20
            # Urgency language adds more
            if web_result.urgency_language:
                score += min(15, len(web_result.urgency_language) * 5)
        
        # Suspicious JavaScript
        if web_result.javascript_suspicious:
            score += 25
            if web_result.javascript_threats:
                score += min(15, len(web_result.javascript_threats) * 5)
        
        # Suspicious external resources
        if web_result.suspicious_resources > 0:
            score += min(15, web_result.suspicious_resources * 3)
        
        # Favicon mismatch
        if web_result.favicon_mismatch:
            score += 10
        
        return min(100, score)