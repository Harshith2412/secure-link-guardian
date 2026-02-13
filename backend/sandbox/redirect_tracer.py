"""
SecureLink Guardian - Redirect Tracer
Traces redirect chains to detect malicious redirects
"""

import requests
from typing import List, Dict, Optional
import logging
from urllib.parse import urlparse, urljoin
from backend.config import Config

logger = logging.getLogger(__name__)


class RedirectTracer:
    """Trace and analyze redirect chains"""
    
    def __init__(self, config: Config):
        self.config = config
        self.max_redirects = config.SANDBOX_MAX_REDIRECTS
        self.timeout = 10
        self.user_agent = config.SANDBOX_USER_AGENT
    
    def trace(self, url: str) -> Dict:
        """
        Trace complete redirect chain
        
        Args:
            url: Starting URL
            
        Returns:
            Dictionary with redirect chain and analysis
        """
        logger.info(f"Tracing redirects for: {url}")
        
        chain = []
        current_url = url
        redirect_types = []
        
        try:
            session = requests.Session()
            session.max_redirects = 0  # Handle redirects manually
            
            for i in range(self.max_redirects + 1):
                try:
                    response = session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=self.timeout,
                        headers={'User-Agent': self.user_agent}
                    )
                    
                    # Add to chain
                    chain.append({
                        'url': current_url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    })
                    
                    # Check if it's a redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        redirect_type = self._get_redirect_type(response.status_code)
                        redirect_types.append(redirect_type)
                        
                        # Get next URL
                        location = response.headers.get('Location')
                        if not location:
                            break
                        
                        # Handle relative URLs
                        if not location.startswith(('http://', 'https://')):
                            location = urljoin(current_url, location)
                        
                        current_url = location
                        
                        # Check for redirect loop
                        if self._is_redirect_loop(chain):
                            logger.warning("Redirect loop detected")
                            break
                    else:
                        # Final destination
                        break
                        
                except requests.exceptions.Timeout:
                    logger.warning(f"Timeout at hop {i+1}")
                    break
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Request failed at hop {i+1}: {str(e)}")
                    break
            
            # Analyze the chain
            analysis = self._analyze_chain(chain, redirect_types)
            
            return {
                'success': True,
                'chain': [hop['url'] for hop in chain],
                'detailed_chain': chain,
                'redirect_count': len(chain) - 1,
                'redirect_types': redirect_types,
                'final_url': chain[-1]['url'] if chain else url,
                'analysis': analysis
            }
            
        except Exception as e:
            logger.error(f"Redirect tracing failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'chain': [url],
                'redirect_count': 0
            }
    
    def _get_redirect_type(self, status_code: int) -> str:
        """Get redirect type description"""
        redirect_types = {
            301: 'Permanent (301)',
            302: 'Temporary (302)',
            303: 'See Other (303)',
            307: 'Temporary (307)',
            308: 'Permanent (308)'
        }
        return redirect_types.get(status_code, f'Unknown ({status_code})')
    
    def _is_redirect_loop(self, chain: List[Dict]) -> bool:
        """Check if there's a redirect loop"""
        urls = [hop['url'] for hop in chain]
        return len(urls) != len(set(urls))
    
    def _analyze_chain(self, chain: List[Dict], redirect_types: List[str]) -> Dict:
        """
        Analyze redirect chain for suspicious patterns
        
        Args:
            chain: List of redirect hops
            redirect_types: Types of redirects
            
        Returns:
            Analysis results
        """
        if len(chain) <= 1:
            return {
                'suspicious': False,
                'reasons': []
            }
        
        suspicious = False
        reasons = []
        
        # Check for excessive redirects
        if len(chain) > 3:
            suspicious = True
            reasons.append(f"Excessive redirects ({len(chain)-1} hops)")
        
        # Check for domain changes
        domains = [urlparse(hop['url']).netloc for hop in chain]
        unique_domains = set(domains)
        
        if len(unique_domains) > 2:
            suspicious = True
            reasons.append(f"Multiple domain changes ({len(unique_domains)} different domains)")
        
        # Check for suspicious TLDs
        for hop in chain:
            domain = urlparse(hop['url']).netloc
            for tld in self.config.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    suspicious = True
                    reasons.append(f"Suspicious TLD detected: {tld}")
                    break
        
        # Check for protocol downgrade (HTTPS -> HTTP)
        protocols = [urlparse(hop['url']).scheme for hop in chain]
        if 'https' in protocols and 'http' in protocols:
            https_index = protocols.index('https')
            http_index = protocols.index('http')
            if http_index > https_index:
                suspicious = True
                reasons.append("Protocol downgrade (HTTPS → HTTP)")
        
        # Check for redirect through URL shorteners
        for hop in chain[1:]:  # Skip first URL
            domain = urlparse(hop['url']).netloc
            if any(shortener in domain for shortener in self.config.URL_SHORTENERS):
                suspicious = True
                reasons.append(f"Redirect through URL shortener: {domain}")
        
        # Check for JavaScript redirects in response
        for hop in chain:
            content_type = hop['headers'].get('Content-Type', '')
            if 'text/html' in content_type:
                # Would need to check content for JS redirects
                # Placeholder for now
                pass
        
        return {
            'suspicious': suspicious,
            'reasons': reasons,
            'domain_changes': len(unique_domains) - 1,
            'unique_domains': list(unique_domains)
        }
    
    def check_open_redirect(self, url: str) -> Dict:
        """
        Check if URL is vulnerable to open redirect
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with vulnerability assessment
        """
        parsed = urlparse(url)
        params = parsed.query
        
        # Common redirect parameters
        redirect_params = [
            'redirect', 'url', 'link', 'goto', 'next', 'return',
            'callback', 'redir', 'target', 'dest', 'continue', 'out'
        ]
        
        vulnerable = False
        findings = []
        
        for param in redirect_params:
            if param in params.lower():
                vulnerable = True
                findings.append({
                    'parameter': param,
                    'value': parsed.query,
                    'risk': 'high' if param in ['redirect', 'url', 'goto'] else 'medium'
                })
        
        return {
            'vulnerable': vulnerable,
            'findings': findings,
            'recommendation': 'Validate and whitelist redirect destinations' if vulnerable else None
        }


# Factory function
def create_redirect_tracer(config: Config) -> RedirectTracer:
    """Create redirect tracer instance"""
    return RedirectTracer(config)