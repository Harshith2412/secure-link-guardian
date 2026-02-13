"""
SecureLink Guardian - URL Manipulation Detector
Detects URL shorteners, redirect chains, parameter injection, and encoding tricks
"""

import requests
from typing import Dict, List
import logging
from backend.config import Config
from backend.models import URLAnalysisResult
from backend.utils.url_parser import url_parser

logger = logging.getLogger(__name__)


class URLManipulationDetector:
    """URL manipulation detection"""
    
    def __init__(self, config: Config):
        self.config = config
        self.shorteners = config.URL_SHORTENERS
        self.max_redirects = config.SANDBOX_MAX_REDIRECTS
        self.timeout = 10
    
    async def analyze(self, url: str) -> URLAnalysisResult:
        """
        Perform complete URL manipulation analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            URLAnalysisResult with all findings
        """
        logger.info(f"Analyzing URL manipulation for: {url}")
        
        try:
            parsed = url_parser.parse(url)
            
            # Check for URL shortener
            shortener_result = self._check_shortener(url, parsed)
            
            # Trace redirect chain
            redirect_result = self._trace_redirects(url)
            
            # Analyze parameters
            param_result = url_parser.has_suspicious_params(url)
            
            # Check encoding tricks
            encoding_result = url_parser.detect_encoding_tricks(url)
            
            # Check for open redirect
            open_redirect = self._check_open_redirect(parsed)
            
            # Check TLD
            suspicious_tld = self._check_suspicious_tld(parsed.get('suffix', ''))
            
            # Count subdomains
            subdomain_count = parsed.get('subdomain_count', 0)
            subdomain_suspicious = subdomain_count > 3
            
            return URLAnalysisResult(
                is_shortener=shortener_result['detected'],
                shortener_service=shortener_result.get('service'),
                expanded_url=shortener_result.get('expanded_url'),
                redirect_chain=redirect_result['chain'],
                redirect_count=redirect_result['count'],
                suspicious_params=param_result['suspicious'],
                suspicious_param_details=param_result.get('details', [])[:3],  # Limit to 3
                encoding_tricks=encoding_result['detected'],
                encoding_details=', '.join(encoding_result.get('tricks', [])),
                open_redirect=open_redirect,
                suspicious_tld=suspicious_tld,
                subdomain_count=subdomain_count,
                subdomain_suspicious=subdomain_suspicious
            )
            
        except Exception as e:
            logger.error(f"URL analysis error: {str(e)}")
            return URLAnalysisResult()
    
    def _check_shortener(self, url: str, parsed: Dict) -> Dict:
        """
        Check if URL uses a shortening service
        
        Args:
            url: URL to check
            parsed: Parsed URL components
            
        Returns:
            Dictionary with detection results
        """
        hostname = parsed.get('hostname', '').lower()
        
        for shortener in self.shorteners:
            if shortener in hostname:
                logger.info(f"URL shortener detected: {shortener}")
                
                # Try to expand URL
                expanded = self._expand_shortener(url)
                
                return {
                    'detected': True,
                    'service': shortener,
                    'expanded_url': expanded
                }
        
        return {'detected': False}
    
    def _expand_shortener(self, url: str) -> str:
        """
        Attempt to expand a shortened URL
        
        Args:
            url: Shortened URL
            
        Returns:
            Expanded URL or original if expansion fails
        """
        try:
            response = requests.head(url, allow_redirects=True, timeout=self.timeout)
            return response.url
        except Exception as e:
            logger.debug(f"Could not expand URL: {str(e)}")
            return url
    
    def _trace_redirects(self, url: str) -> Dict:
        """
        Trace redirect chain
        
        Args:
            url: URL to trace
            
        Returns:
            Dictionary with redirect chain
        """
        chain = [url]
        
        try:
            session = requests.Session()
            session.max_redirects = self.max_redirects
            
            response = session.get(
                url,
                allow_redirects=True,
                timeout=self.timeout,
                headers={'User-Agent': self.config.SANDBOX_USER_AGENT}
            )
            
            # Get redirect history
            if response.history:
                for resp in response.history:
                    chain.append(resp.url)
                chain.append(response.url)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_chain = []
            for item in chain:
                if item not in seen:
                    seen.add(item)
                    unique_chain.append(item)
            
            if len(unique_chain) > 1:
                logger.info(f"Redirect chain detected: {len(unique_chain)} hops")
            
            return {
                'chain': unique_chain,
                'count': len(unique_chain) - 1
            }
            
        except requests.exceptions.TooManyRedirects:
            logger.warning(f"Too many redirects for: {url}")
            return {
                'chain': chain + ['[Too many redirects]'],
                'count': self.max_redirects
            }
        except Exception as e:
            logger.debug(f"Redirect trace failed: {str(e)}")
            return {
                'chain': chain,
                'count': 0
            }
    
    def _check_open_redirect(self, parsed: Dict) -> bool:
        """
        Check for open redirect vulnerability indicators
        
        Args:
            parsed: Parsed URL components
            
        Returns:
            True if open redirect indicators found
        """
        params = parsed.get('query_params', {})
        
        redirect_params = [
            'redirect', 'url', 'link', 'goto', 'next', 'return',
            'callback', 'redir', 'target', 'dest', 'continue', 'out'
        ]
        
        for key in params.keys():
            if any(rp in key.lower() for rp in redirect_params):
                values = params[key]
                for value in values:
                    # Check if value is a URL
                    if value.startswith(('http://', 'https://', '//')):
                        logger.warning(f"Open redirect detected: {key}={value}")
                        return True
        
        return False
    
    def _check_suspicious_tld(self, tld: str) -> bool:
        """
        Check if TLD is suspicious
        
        Args:
            tld: Top-level domain
            
        Returns:
            True if suspicious
        """
        tld_with_dot = f".{tld}" if not tld.startswith('.') else tld
        return tld_with_dot.lower() in [t.lower() for t in self.config.SUSPICIOUS_TLDS]


# Factory function
def create_url_manipulator(config: Config) -> URLManipulationDetector:
    """Create URL manipulation detector instance"""
    return URLManipulationDetector(config)