"""
SecureLink Guardian - Web Phishing Detector
Analyzes web page content for phishing indicators
"""

from bs4 import BeautifulSoup
import re
from typing import Dict, List, Optional
import logging
from backend.config import Config
from backend.models import WebAnalysisResult
from backend.utils.patterns import phishing_patterns

logger = logging.getLogger(__name__)


class WebPhishingDetector:
    """Web content phishing detection"""
    
    def __init__(self, config: Config):
        self.config = config
        self.patterns = phishing_patterns
        self.known_brands = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'facebook', 'twitter', 'linkedin', 'netflix', 'bank',
            'wells fargo', 'chase', 'citibank', 'american express'
        ]
    
    async def analyze(self, html: str, url: str, screenshot_path: Optional[str] = None) -> WebAnalysisResult:
        """
        Perform complete web phishing analysis
        
        Args:
            html: HTML content
            url: Original URL
            screenshot_path: Optional path to screenshot for visual analysis
            
        Returns:
            WebAnalysisResult with all findings
        """
        logger.info(f"Analyzing web content for: {url}")
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract text content
            text_content = soup.get_text()
            
            # Check for brand impersonation
            brand_result = self._check_brand_impersonation(soup, text_content, url)
            
            # Analyze forms for credential harvesting
            form_result = self._analyze_forms(soup)
            
            # Check for social engineering tactics
            social_eng_result = self._check_social_engineering(text_content)
            
            # Analyze JavaScript
            js_result = self._analyze_javascript(soup)
            
            # Count external resources
            resource_result = self._analyze_external_resources(soup, url)
            
            # Check favicon
            favicon_result = self._check_favicon(soup, url, brand_result.get('detected_brand'))
            
            return WebAnalysisResult(
                brand_impersonation=brand_result['detected'],
                impersonated_brand=brand_result.get('brand'),
                visual_similarity_score=brand_result.get('similarity_score'),
                credential_forms=form_result['detected'],
                form_count=form_result['form_count'],
                password_fields=form_result['password_count'],
                social_engineering=social_eng_result['detected'],
                urgency_language=social_eng_result.get('urgency_phrases', [])[:5],
                javascript_suspicious=js_result['detected'],
                javascript_threats=js_result.get('threats', [])[:5],
                external_resources=resource_result['total'],
                suspicious_resources=resource_result['suspicious'],
                favicon_mismatch=favicon_result
            )
            
        except Exception as e:
            logger.error(f"Web analysis error: {str(e)}")
            return WebAnalysisResult()
    
    def _check_brand_impersonation(self, soup: BeautifulSoup, text: str, url: str) -> Dict:
        """
        Check for brand impersonation
        
        Args:
            soup: BeautifulSoup object
            text: Page text content
            url: Page URL
            
        Returns:
            Dictionary with detection results
        """
        text_lower = text.lower()
        url_lower = url.lower()
        
        detected_brands = []
        
        # Check for brand keywords in content
        for brand in self.known_brands:
            if brand in text_lower or brand in url_lower:
                detected_brands.append(brand)
        
        if not detected_brands:
            return {'detected': False}
        
        # Get most prominent brand
        brand_counts = {}
        for brand in detected_brands:
            count = text_lower.count(brand) + url_lower.count(brand) * 2
            brand_counts[brand] = count
        
        if brand_counts:
            primary_brand = max(brand_counts, key=brand_counts.get)
            
            # Check if URL domain matches the brand
            domain_matches = primary_brand.replace(' ', '') in url_lower
            
            if not domain_matches:
                logger.warning(f"Brand impersonation detected: {primary_brand}")
                return {
                    'detected': True,
                    'brand': primary_brand.title(),
                    'detected_brand': primary_brand,
                    'similarity_score': 0.85  # Placeholder, would use visual analysis
                }
        
        return {'detected': False}
    
    def _analyze_forms(self, soup: BeautifulSoup) -> Dict:
        """
        Analyze forms for credential harvesting
        
        Args:
            soup: BeautifulSoup object
            
        Returns:
            Dictionary with form analysis
        """
        forms = soup.find_all('form')
        password_inputs = soup.find_all('input', {'type': 'password'})
        
        # Check for suspicious form attributes
        suspicious_forms = 0
        credential_patterns = self.patterns.check_credential_harvesting(str(soup))
        
        for form in forms:
            action = form.get('action', '').lower()
            
            # Check for suspicious actions
            if any(pattern in action for pattern in ['php', 'cgi', 'asp', 'jsp']):
                suspicious_forms += 1
            
            # Check for external form actions
            if action.startswith('http') and action.startswith('//'):
                suspicious_forms += 1
        
        detected = len(password_inputs) > 0 and len(forms) > 0
        
        if detected:
            logger.info(f"Credential harvesting indicators: {len(password_inputs)} password fields, {len(forms)} forms")
        
        return {
            'detected': detected or credential_patterns['detected'],
            'form_count': len(forms),
            'password_count': len(password_inputs),
            'suspicious_forms': suspicious_forms,
            'risk_score': credential_patterns.get('risk_score', 0)
        }
    
    def _check_social_engineering(self, text: str) -> Dict:
        """
        Check for social engineering tactics
        
        Args:
            text: Page text content
            
        Returns:
            Dictionary with detection results
        """
        urgency_matches = self.patterns.check_urgency_language(text)
        brand_keywords = self.patterns.check_brand_keywords(text)
        
        detected = len(urgency_matches) > 0
        
        if detected:
            logger.info(f"Social engineering detected: {len(urgency_matches)} urgency patterns")
        
        return {
            'detected': detected,
            'urgency_phrases': urgency_matches,
            'brand_context': brand_keywords
        }
    
    def _analyze_javascript(self, soup: BeautifulSoup) -> Dict:
        """
        Analyze JavaScript for suspicious patterns
        
        Args:
            soup: BeautifulSoup object
            
        Returns:
            Dictionary with JavaScript analysis
        """
        scripts = soup.find_all('script')
        all_js = '\n'.join([script.string or '' for script in scripts if script.string])
        
        # Check for suspicious JavaScript patterns
        js_analysis = self.patterns.check_javascript_threats(all_js)
        
        threats = []
        
        # Check for obfuscation
        if re.search(r'eval\s*\(', all_js):
            threats.append('eval() usage detected')
        
        if re.search(r'atob\s*\(', all_js):
            threats.append('Base64 decoding detected')
        
        if re.search(r'document\.cookie', all_js):
            threats.append('Cookie manipulation detected')
        
        if re.search(r'localStorage|sessionStorage', all_js):
            threats.append('Local storage access detected')
        
        # Check for redirects
        if re.search(r'window\.location|document\.location', all_js):
            threats.append('JavaScript redirect detected')
        
        detected = len(threats) > 0 or js_analysis['detected']
        
        if detected:
            logger.info(f"Suspicious JavaScript: {len(threats)} threats")
        
        return {
            'detected': detected,
            'threats': threats + [t['pattern'] for t in js_analysis.get('threats', [])],
            'risk_score': js_analysis.get('risk_score', 0)
        }
    
    def _analyze_external_resources(self, soup: BeautifulSoup, url: str) -> Dict:
        """
        Analyze external resources
        
        Args:
            soup: BeautifulSoup object
            url: Page URL
            
        Returns:
            Dictionary with resource analysis
        """
        from urllib.parse import urlparse
        
        base_domain = urlparse(url).netloc
        
        # Find all external resources
        external_links = []
        suspicious_count = 0
        
        # Scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith('http') and base_domain not in src:
                external_links.append(src)
                # Check for suspicious CDNs or domains
                if any(suspicious in src.lower() for suspicious in ['.tk', '.ml', '.ga', '.cf']):
                    suspicious_count += 1
        
        # Stylesheets
        for link in soup.find_all('link', rel='stylesheet'):
            href = link.get('href', '')
            if href.startswith('http') and base_domain not in href:
                external_links.append(href)
        
        # Images
        for img in soup.find_all('img', src=True):
            src = img['src']
            if src.startswith('http') and base_domain not in src:
                external_links.append(src)
        
        return {
            'total': len(external_links),
            'suspicious': suspicious_count
        }
    
    def _check_favicon(self, soup: BeautifulSoup, url: str, detected_brand: Optional[str]) -> bool:
        """
        Check if favicon matches the claimed brand
        
        Args:
            soup: BeautifulSoup object
            url: Page URL
            detected_brand: Brand detected in content
            
        Returns:
            True if mismatch detected
        """
        if not detected_brand:
            return False
        
        # Find favicon
        favicon = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
        
        if favicon:
            favicon_href = favicon.get('href', '')
            
            # Check if favicon is hosted externally
            if favicon_href.startswith('http'):
                favicon_domain = favicon_href.split('/')[2]
                url_domain = url.split('/')[2]
                
                # If domains don't match, it's suspicious
                if favicon_domain != url_domain:
                    logger.warning(f"Favicon mismatch: {favicon_domain} vs {url_domain}")
                    return True
        
        return False


# Factory function
def create_web_phishing_detector(config: Config) -> WebPhishingDetector:
    """Create web phishing detector instance"""
    return WebPhishingDetector(config)