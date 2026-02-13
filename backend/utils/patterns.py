"""
SecureLink Guardian - Phishing Patterns
Database of known phishing patterns and indicators
"""

from typing import List, Dict
import re


class PhishingPatterns:
    """Phishing pattern database and matching"""
    
    # Urgency and fear language patterns
    URGENCY_PATTERNS = [
        r'act\s+now',
        r'urgent',
        r'immediately',
        r'limited\s+time',
        r'expires?\s+(?:in|within|today)',
        r'suspended',
        r'locked',
        r'blocked',
        r'verify\s+(?:your|account)',
        r'confirm\s+(?:your|identity)',
        r'unusual\s+activity',
        r'security\s+alert',
        r'action\s+required',
        r'click\s+here\s+(?:now|immediately)',
        r'within\s+\d+\s+hours',
        r'last\s+chance'
    ]
    
    # Brand impersonation keywords
    BRAND_KEYWORDS = {
        'financial': [
            'paypal', 'bank', 'credit', 'payment', 'billing', 'invoice',
            'transaction', 'account', 'balance', 'card', 'transfer'
        ],
        'tech': [
            'microsoft', 'apple', 'google', 'amazon', 'facebook',
            'twitter', 'linkedin', 'netflix', 'adobe', 'dropbox'
        ],
        'ecommerce': [
            'amazon', 'ebay', 'aliexpress', 'walmart', 'target',
            'order', 'delivery', 'shipping', 'tracking'
        ],
        'government': [
            'irs', 'social security', 'tax', 'refund', 'government',
            'federal', 'official', 'department'
        ]
    }
    
    # Credential harvesting indicators
    CREDENTIAL_PATTERNS = [
        r'password',
        r'username',
        r'user\s*id',
        r'account\s*number',
        r'social\s*security',
        r'credit\s*card',
        r'card\s*number',
        r'cvv',
        r'pin\s*code',
        r'date\s*of\s*birth',
        r'mother.*maiden',
        r'security\s*question'
    ]
    
    # Suspicious form actions
    SUSPICIOUS_FORM_ACTIONS = [
        r'https?://(?!.*(?:' + '|'.join(['paypal', 'amazon', 'google', 'microsoft']) + '))',
        r'\.php\?',
        r'/cgi-bin/',
        r'/webscr',
        r'data:text/html',
        r'javascript:',
    ]
    
    # JavaScript red flags
    JS_RED_FLAGS = [
        r'document\.write',
        r'eval\s*\(',
        r'atob\s*\(',  # Base64 decode
        r'btoa\s*\(',  # Base64 encode
        r'String\.fromCharCode',
        r'unescape\s*\(',
        r'decodeURI',
        r'\.cookie',
        r'localStorage',
        r'sessionStorage',
        r'clipboardData',
        r'navigator\.credentials',
        r'window\.location\s*=',
        r'document\.location\s*=',
        r'\.submit\s*\(',
        r'XMLHttpRequest',
        r'fetch\s*\('
    ]
    
    # Common typosquatting patterns
    TYPOSQUATTING_TECHNIQUES = {
        'character_omission': lambda s: [s[:i] + s[i+1:] for i in range(len(s))],
        'character_addition': lambda s: [s[:i] + c + s[i:] for i in range(len(s)+1) 
                                        for c in 'abcdefghijklmnopqrstuvwxyz'],
        'character_substitution': lambda s: [s[:i] + c + s[i+1:] for i in range(len(s)) 
                                            for c in 'abcdefghijklmnopqrstuvwxyz'],
        'character_swap': lambda s: [s[:i] + s[i+1] + s[i] + s[i+2:] for i in range(len(s)-1)],
        'homoglyphs': {
            'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å'],
            'e': ['е', 'è', 'é', 'ê', 'ë'],
            'i': ['і', 'ì', 'í', 'î', 'ï'],
            'o': ['о', 'ò', 'ó', 'ô', 'õ', 'ö', '0'],
            'c': ['с', 'ć', 'č'],
            'l': ['l', '1', 'I'],
            's': ['ѕ', '$', '5'],
            'u': ['и', 'ù', 'ú', 'û', 'ü'],
            'p': ['р'],
            'x': ['х'],
            'y': ['у', 'ý', 'ÿ']
        }
    }
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.apk', '.dmg', '.pkg', '.deb', '.rpm', '.msi', '.app'
    ]
    
    # Known phishing URL patterns
    PHISHING_URL_PATTERNS = [
        r'-secure',
        r'-verify',
        r'-account',
        r'-login',
        r'-update',
        r'-confirm',
        r'-validation',
        r'secure-',
        r'verify-',
        r'account-',
        r'login-',
        r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}',  # IP address in domain
        r'@',  # Username in URL
    ]
    
    def __init__(self):
        self.urgency_regex = [re.compile(p, re.IGNORECASE) for p in self.URGENCY_PATTERNS]
        self.credential_regex = [re.compile(p, re.IGNORECASE) for p in self.CREDENTIAL_PATTERNS]
        self.js_redflags_regex = [re.compile(p, re.IGNORECASE) for p in self.JS_RED_FLAGS]
        self.phishing_url_regex = [re.compile(p, re.IGNORECASE) for p in self.PHISHING_URL_PATTERNS]
    
    def check_urgency_language(self, text: str) -> List[str]:
        """
        Check for urgency and fear-inducing language
        
        Args:
            text: Text to analyze
            
        Returns:
            List of matched urgency patterns
        """
        matches = []
        for pattern in self.urgency_regex:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return matches
    
    def check_brand_keywords(self, text: str) -> Dict[str, List[str]]:
        """
        Check for brand-related keywords
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary of matched brands by category
        """
        text_lower = text.lower()
        matches = {}
        
        for category, keywords in self.BRAND_KEYWORDS.items():
            category_matches = [kw for kw in keywords if kw in text_lower]
            if category_matches:
                matches[category] = category_matches
        
        return matches
    
    def check_credential_harvesting(self, html: str) -> Dict:
        """
        Check for credential harvesting indicators
        
        Args:
            html: HTML content to analyze
            
        Returns:
            Dictionary with analysis results
        """
        html_lower = html.lower()
        matches = []
        
        for pattern in self.credential_regex:
            found = pattern.findall(html_lower)
            if found:
                matches.extend(found)
        
        # Check for password inputs
        password_inputs = len(re.findall(r'type\s*=\s*["\']password["\']', html_lower))
        
        # Check for form submissions
        form_count = len(re.findall(r'<form', html_lower))
        
        return {
            'detected': len(matches) > 0 or password_inputs > 0,
            'patterns_found': list(set(matches)),
            'password_fields': password_inputs,
            'form_count': form_count,
            'risk_score': min(100, (len(matches) * 10) + (password_inputs * 20))
        }
    
    def check_javascript_threats(self, js_code: str) -> Dict:
        """
        Check JavaScript for suspicious patterns
        
        Args:
            js_code: JavaScript code to analyze
            
        Returns:
            Dictionary with analysis results
        """
        threats = []
        
        for pattern in self.js_redflags_regex:
            matches = pattern.findall(js_code)
            if matches:
                threats.append({
                    'pattern': pattern.pattern,
                    'count': len(matches)
                })
        
        return {
            'detected': len(threats) > 0,
            'threat_count': len(threats),
            'threats': threats,
            'risk_score': min(100, len(threats) * 15)
        }
    
    def check_url_patterns(self, url: str) -> Dict:
        """
        Check URL for known phishing patterns
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with analysis results
        """
        matches = []
        
        for pattern in self.phishing_url_regex:
            if pattern.search(url):
                matches.append(pattern.pattern)
        
        # Check for excessive subdomains
        subdomain_count = url.count('.') - 1
        excessive_subdomains = subdomain_count > 3
        
        # Check for IP address
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        has_ip = bool(ip_pattern.search(url))
        
        return {
            'detected': len(matches) > 0 or excessive_subdomains or has_ip,
            'patterns': matches,
            'excessive_subdomains': excessive_subdomains,
            'subdomain_count': subdomain_count,
            'has_ip_address': has_ip
        }
    
    def get_risk_keywords(self) -> List[str]:
        """Get all risk-related keywords"""
        keywords = []
        for category in self.BRAND_KEYWORDS.values():
            keywords.extend(category)
        return list(set(keywords))


# Global patterns instance
phishing_patterns = PhishingPatterns()