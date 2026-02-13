"""
SecureLink Guardian - Sandbox Analyzer
Analyzes rendered page data from sandbox
"""

import logging
from typing import Dict
from bs4 import BeautifulSoup
from backend.config import Config
from backend.detection.web_phishing import create_web_phishing_detector

logger = logging.getLogger(__name__)


class SandboxAnalyzer:
    """Analyzes sandbox rendering results"""
    
    def __init__(self, config: Config):
        self.config = config
        self.web_detector = create_web_phishing_detector(config)
    
    async def analyze_rendered_page(self, render_result: Dict) -> Dict:
        """
        Analyze rendered page data
        
        Args:
            render_result: Result from SandboxRenderer
            
        Returns:
            Dictionary with analysis results
        """
        if not render_result.get('success'):
            logger.warning("Cannot analyze failed render")
            return {
                'success': False,
                'error': render_result.get('error', 'Unknown error')
            }
        
        try:
            html = render_result.get('html', '')
            url = render_result.get('url', '')
            
            # Web phishing detection
            web_analysis = await self.web_detector.analyze(html, url)
            
            # Network analysis
            network_analysis = self._analyze_network_traffic(
                render_result.get('requests', []),
                render_result.get('responses', [])
            )
            
            # Form analysis
            form_analysis = self._analyze_forms(render_result.get('forms', []))
            
            # JavaScript analysis
            js_analysis = self._analyze_javascript(render_result.get('javascript', {}))
            
            # Cookie analysis
            cookie_analysis = self._analyze_cookies(render_result.get('cookies', []))
            
            # Storage analysis
            storage_analysis = self._analyze_storage(
                render_result.get('local_storage', {})
            )
            
            return {
                'success': True,
                'web_phishing': web_analysis,
                'network': network_analysis,
                'forms': form_analysis,
                'javascript': js_analysis,
                'cookies': cookie_analysis,
                'storage': storage_analysis,
                'final_url': render_result.get('final_url'),
                'page_title': render_result.get('title')
            }
            
        except Exception as e:
            logger.error(f"Sandbox analysis error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _analyze_network_traffic(self, requests: list, responses: list) -> Dict:
        """
        Analyze network requests and responses
        
        Args:
            requests: List of requests
            responses: List of responses
            
        Returns:
            Dictionary with network analysis
        """
        suspicious_domains = []
        external_requests = 0
        total_requests = len(requests)
        
        for req in requests:
            url = req.get('url', '')
            
            # Check for suspicious TLDs
            for tld in self.config.SUSPICIOUS_TLDS:
                if tld in url:
                    suspicious_domains.append(url)
            
            # Count external requests
            if req.get('resource_type') in ['script', 'stylesheet', 'image']:
                external_requests += 1
        
        # Check response statuses
        error_responses = [r for r in responses if r.get('status', 0) >= 400]
        
        return {
            'total_requests': total_requests,
            'external_requests': external_requests,
            'suspicious_domains': suspicious_domains[:5],  # Limit to 5
            'error_count': len(error_responses),
            'suspicious': len(suspicious_domains) > 0
        }
    
    def _analyze_forms(self, forms: list) -> Dict:
        """
        Analyze forms on the page
        
        Args:
            forms: List of forms
            
        Returns:
            Dictionary with form analysis
        """
        total_forms = len(forms)
        password_fields = 0
        external_actions = 0
        suspicious_forms = []
        
        for form in forms:
            action = form.get('action', '')
            inputs = form.get('inputs', [])
            
            # Count password fields
            password_fields += sum(1 for inp in inputs if inp.get('type') == 'password')
            
            # Check for external form actions
            if action.startswith('http') and action.startswith('//'):
                external_actions += 1
                suspicious_forms.append(action)
        
        return {
            'total': total_forms,
            'password_fields': password_fields,
            'external_actions': external_actions,
            'suspicious_forms': suspicious_forms,
            'suspicious': password_fields > 0 or external_actions > 0
        }
    
    def _analyze_javascript(self, js_info: Dict) -> Dict:
        """
        Analyze JavaScript usage
        
        Args:
            js_info: JavaScript information
            
        Returns:
            Dictionary with JS analysis
        """
        inline_count = js_info.get('inline_count', 0)
        external_count = js_info.get('external_count', 0)
        external_sources = js_info.get('external_sources', [])
        
        suspicious_sources = []
        
        for source in external_sources:
            # Check for suspicious patterns
            if any(pattern in source.lower() for pattern in ['eval', 'atob', 'btoa']):
                suspicious_sources.append(source)
            
            # Check for suspicious TLDs
            for tld in self.config.SUSPICIOUS_TLDS:
                if tld in source:
                    suspicious_sources.append(source)
        
        return {
            'inline_scripts': inline_count,
            'external_scripts': external_count,
            'suspicious_sources': list(set(suspicious_sources))[:5],
            'suspicious': len(suspicious_sources) > 0 or inline_count > 10
        }
    
    def _analyze_cookies(self, cookies: list) -> Dict:
        """
        Analyze cookies
        
        Args:
            cookies: List of cookies
            
        Returns:
            Dictionary with cookie analysis
        """
        total_cookies = len(cookies)
        third_party = 0
        no_httponly = 0
        no_secure = 0
        
        for cookie in cookies:
            # Check for third-party cookies
            if cookie.get('domain', '').startswith('.'):
                third_party += 1
            
            # Check security flags
            if not cookie.get('httpOnly', False):
                no_httponly += 1
            
            if not cookie.get('secure', False):
                no_secure += 1
        
        return {
            'total': total_cookies,
            'third_party': third_party,
            'no_httponly': no_httponly,
            'no_secure': no_secure,
            'suspicious': third_party > 5 or no_httponly > 3
        }
    
    def _analyze_storage(self, local_storage: Dict) -> Dict:
        """
        Analyze local storage usage
        
        Args:
            local_storage: Local storage data
            
        Returns:
            Dictionary with storage analysis
        """
        total_items = len(local_storage)
        suspicious_keys = []
        
        # Check for suspicious key names
        suspicious_patterns = [
            'password', 'token', 'secret', 'key', 'auth',
            'credential', 'session', 'cookie'
        ]
        
        for key in local_storage.keys():
            key_lower = key.lower()
            if any(pattern in key_lower for pattern in suspicious_patterns):
                suspicious_keys.append(key)
        
        return {
            'total_items': total_items,
            'suspicious_keys': suspicious_keys,
            'suspicious': len(suspicious_keys) > 0
        }


# Factory function
def create_sandbox_analyzer(config: Config) -> SandboxAnalyzer:
    """Create sandbox analyzer instance"""
    return SandboxAnalyzer(config)