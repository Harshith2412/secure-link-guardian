"""
SecureLink Guardian - URL Parser
URL parsing and analysis utilities
"""

from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, Optional, List
import tldextract
import re


class URLParser:
    """URL parsing and analysis"""
    
    def __init__(self):
        self.url_pattern = re.compile(
            r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
        )
    
    def parse(self, url: str) -> Dict:
        """
        Parse URL into components
        
        Args:
            url: URL to parse
            
        Returns:
            Dictionary with URL components
        """
        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            return {
                'original': url,
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'hostname': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'username': parsed.username,
                'password': parsed.password,
                
                # Extracted components
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'suffix': extracted.suffix,
                'registered_domain': extracted.registered_domain,
                'fqdn': extracted.fqdn,
                
                # Query parameters
                'query_params': parse_qs(parsed.query),
                
                # Additional analysis
                'is_ip': self._is_ip_address(parsed.hostname or ''),
                'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
                'path_depth': len([p for p in parsed.path.split('/') if p]),
                'param_count': len(parse_qs(parsed.query))
            }
        except Exception as e:
            return {
                'error': str(e),
                'original': url
            }
    
    def extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from text
        
        Args:
            text: Text containing URLs
            
        Returns:
            List of extracted URLs
        """
        return self.url_pattern.findall(text)
    
    def normalize(self, url: str) -> str:
        """
        Normalize URL for comparison
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        parsed = urlparse(url)
        
        # Remove www
        hostname = parsed.hostname or ''
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        
        # Lowercase
        hostname = hostname.lower()
        path = parsed.path.lower()
        
        # Remove trailing slash
        if path.endswith('/'):
            path = path[:-1]
        
        # Rebuild URL
        normalized = f"{parsed.scheme}://{hostname}"
        if parsed.port:
            normalized += f":{parsed.port}"
        normalized += path
        if parsed.query:
            normalized += f"?{parsed.query}"
        
        return normalized
    
    def get_base_domain(self, url: str) -> Optional[str]:
        """
        Get base domain (e.g., example.com from subdomain.example.com)
        
        Args:
            url: URL to analyze
            
        Returns:
            Base domain or None
        """
        extracted = tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        return None
    
    def is_suspicious_path(self, url: str) -> bool:
        """
        Check if URL path contains suspicious patterns
        
        Args:
            url: URL to check
            
        Returns:
            True if suspicious patterns found
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        suspicious_keywords = [
            'login', 'signin', 'verify', 'confirm', 'secure', 'account',
            'update', 'billing', 'suspended', 'locked', 'validate',
            'authentication', 'credential', 'webscr', 'banking'
        ]
        
        return any(keyword in path for keyword in suspicious_keywords)
    
    def has_suspicious_params(self, url: str) -> Dict:
        """
        Check for suspicious URL parameters
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with analysis results
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        suspicious = []
        redirect_params = ['redirect', 'url', 'link', 'goto', 'next', 'return', 
                          'callback', 'redir', 'target', 'dest', 'continue']
        
        for key, values in params.items():
            key_lower = key.lower()
            
            # Check for redirect parameters
            if any(pattern in key_lower for pattern in redirect_params):
                for value in values:
                    # Check if value is a URL
                    if self._is_url(value):
                        suspicious.append({
                            'param': key,
                            'value': value,
                            'reason': 'Redirect parameter contains URL'
                        })
            
            # Check for encoded content
            if self._is_base64(values[0] if values else ''):
                suspicious.append({
                    'param': key,
                    'value': values[0][:50] + '...' if len(values[0]) > 50 else values[0],
                    'reason': 'Parameter contains Base64 encoded data'
                })
            
            # Check for excessively long parameters
            if values and len(values[0]) > 500:
                suspicious.append({
                    'param': key,
                    'value': values[0][:50] + '...',
                    'reason': 'Excessively long parameter value'
                })
        
        return {
            'suspicious': len(suspicious) > 0,
            'count': len(suspicious),
            'details': suspicious
        }
    
    def detect_encoding_tricks(self, url: str) -> Dict:
        """
        Detect URL encoding tricks
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with detection results
        """
        tricks = []
        
        # Check for excessive URL encoding
        if url.count('%') > 10:
            tricks.append('Excessive URL encoding detected')
        
        # Check for Unicode encoding
        if re.search(r'%u[0-9a-fA-F]{4}', url):
            tricks.append('Unicode encoding detected')
        
        # Check for double encoding
        if '%%' in url or re.search(r'%25[0-9a-fA-F]{2}', url):
            tricks.append('Double encoding detected')
        
        # Check for null bytes
        if '%00' in url:
            tricks.append('Null byte detected')
        
        # Check for directory traversal
        if '../' in unquote(url) or '..\\' in unquote(url):
            tricks.append('Directory traversal pattern detected')
        
        return {
            'detected': len(tricks) > 0,
            'count': len(tricks),
            'tricks': tricks
        }
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address"""
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        return bool(ip_pattern.match(hostname))
    
    def _is_url(self, text: str) -> bool:
        """Check if text is a URL"""
        return bool(self.url_pattern.match(text))
    
    def _is_base64(self, text: str) -> bool:
        """Check if text appears to be Base64 encoded"""
        if len(text) < 10:
            return False
        base64_pattern = re.compile(r'^[A-Za-z0-9+/=]{10,}$')
        return bool(base64_pattern.match(text))


# Global parser instance
url_parser = URLParser()