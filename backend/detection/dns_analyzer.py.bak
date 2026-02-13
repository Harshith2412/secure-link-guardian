"""
SecureLink Guardian - DNS Analyzer
DNS-based phishing detection including typosquatting, homograph attacks, and domain reputation
"""

import dns.resolver
import socket
import ssl
import whois
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from rapidfuzz.distance import Levenshtein
import logging
from backend.config import Config
from backend.models import DNSAnalysisResult
from backend.utils.url_parser import url_parser

logger = logging.getLogger(__name__)


class DNSAnalyzer:
    """DNS-based phishing detection"""
    
    def __init__(self, config: Config):
        self.config = config
        self.trusted_domains = config.TRUSTED_DOMAINS
        self.suspicious_tlds = config.SUSPICIOUS_TLDS
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    async def analyze(self, url: str) -> DNSAnalysisResult:
        """
        Perform complete DNS analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            DNSAnalysisResult with all findings
        """
        parsed = url_parser.parse(url)
        domain = parsed.get('registered_domain', '')
        hostname = parsed.get('hostname', '')
        
        logger.info(f"Analyzing DNS for: {hostname}")
        
        try:
            # Run all DNS checks
            typosquatting_result = self._check_typosquatting(domain)
            homograph_result = self._check_homograph(hostname)
            domain_age = self._check_domain_age(domain)
            whois_info = self._check_whois_privacy(domain)
            ssl_info = self._check_ssl_certificate(hostname)
            dns_reputation = self._check_dns_reputation(hostname)
            mx_records = self._check_mx_records(domain)
            
            return DNSAnalysisResult(
                typosquatting=typosquatting_result['detected'],
                typosquatting_target=typosquatting_result.get('target'),
                typosquatting_similarity=typosquatting_result.get('similarity'),
                homograph=homograph_result['detected'],
                homograph_details=homograph_result.get('details'),
                domain_age_days=domain_age.get('days'),
                domain_age_suspicious=domain_age.get('suspicious', False),
                whois_privacy=whois_info.get('privacy_protected', False),
                ssl_valid=ssl_info.get('valid', False),
                ssl_issuer=ssl_info.get('issuer'),
                ssl_expiry_days=ssl_info.get('days_until_expiry'),
                dns_reputation_score=dns_reputation.get('score'),
                mx_records_exist=mx_records
            )
            
        except Exception as e:
            logger.error(f"DNS analysis error: {str(e)}")
            # Return empty result on error
            return DNSAnalysisResult()
    
    def _check_typosquatting(self, domain: str) -> Dict:
        """
        Check for typosquatting against known legitimate domains
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with detection results
        """
        if not domain:
            return {'detected': False}
        
        domain_lower = domain.lower()
        
        # Check against trusted domains
        best_match = None
        min_distance = float('inf')
        
        for trusted in self.trusted_domains:
            # Skip if exact match
            if domain_lower == trusted:
                return {'detected': False}
            
            # Calculate Levenshtein distance
            distance = Levenshtein.distance(domain_lower, trusted)
            
            # Calculate similarity ratio
            similarity = 1 - (distance / max(len(domain_lower), len(trusted)))
            
            # If very similar but not exact, it's suspicious
            if distance <= 2 and distance > 0 and similarity > 0.7:
                if distance < min_distance:
                    min_distance = distance
                    best_match = {
                        'target': trusted,
                        'distance': distance,
                        'similarity': round(similarity, 3)
                    }
        
        if best_match:
            logger.warning(f"Typosquatting detected: {domain} → {best_match['target']}")
            return {
                'detected': True,
                **best_match
            }
        
        return {'detected': False}
    
    def _check_homograph(self, hostname: str) -> Dict:
        """
        Check for homograph attacks (IDN spoofing)
        
        Args:
            hostname: Hostname to check
            
        Returns:
            Dictionary with detection results
        """
        if not hostname:
            return {'detected': False}
        
        # Check for non-ASCII characters
        has_non_ascii = not all(ord(char) < 128 for char in hostname)
        
        if not has_non_ascii:
            return {'detected': False}
        
        # Map of lookalike characters (Cyrillic, Greek, etc.)
        homoglyphs = {
            'а': 'a',  # Cyrillic
            'е': 'e',
            'о': 'o',
            'р': 'p',
            'с': 'c',
            'х': 'x',
            'у': 'y',
            'і': 'i',
            'ј': 'j',
            'ѕ': 's',
            'һ': 'h',
            'ԁ': 'd',
            'ԛ': 'q',
            'ԝ': 'w',
            'ԍ': 'g'
        }
        
        # Check for lookalike characters
        found_homoglyphs = []
        for char in hostname:
            if char in homoglyphs:
                found_homoglyphs.append(f"{char} → {homoglyphs[char]}")
        
        if found_homoglyphs:
            logger.warning(f"Homograph attack detected in: {hostname}")
            return {
                'detected': True,
                'details': f"Found {len(found_homoglyphs)} lookalike character(s): {', '.join(found_homoglyphs[:3])}"
            }
        
        # Check for mixed scripts
        scripts = set()
        for char in hostname:
            if 0x0400 <= ord(char) <= 0x04FF:
                scripts.add('Cyrillic')
            elif 0x0370 <= ord(char) <= 0x03FF:
                scripts.add('Greek')
            elif ord(char) < 128:
                scripts.add('Latin')
        
        if len(scripts) > 1:
            return {
                'detected': True,
                'details': f"Mixed character scripts detected: {', '.join(scripts)}"
            }
        
        return {'detected': False}
    
    def _check_domain_age(self, domain: str) -> Dict:
        """
        Check domain age using WHOIS
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with age information
        """
        try:
            w = whois.whois(domain)
            
            # Get creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age = datetime.now() - creation_date
                age_days = age.days
                
                # Check if suspiciously new
                suspicious = age_days < self.config.DOMAIN_AGE_SUSPICIOUS
                
                return {
                    'days': age_days,
                    'creation_date': creation_date.isoformat(),
                    'suspicious': suspicious
                }
        
        except Exception as e:
            logger.debug(f"Could not get domain age for {domain}: {str(e)}")
        
        return {'days': None, 'suspicious': False}
    
    def _check_whois_privacy(self, domain: str) -> Dict:
        """
        Check if WHOIS privacy protection is enabled
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with WHOIS information
        """
        try:
            w = whois.whois(domain)
            
            # Common privacy protection indicators
            privacy_indicators = [
                'privacy', 'protect', 'proxy', 'redacted', 'whoisguard',
                'domains by proxy', 'registration private', 'data redacted'
            ]
            
            registrar = str(w.registrar or '').lower()
            name = str(w.name or '').lower()
            org = str(w.org or '').lower()
            
            privacy_protected = any(
                indicator in registrar or indicator in name or indicator in org
                for indicator in privacy_indicators
            )
            
            return {
                'privacy_protected': privacy_protected,
                'registrar': w.registrar
            }
        
        except Exception as e:
            logger.debug(f"WHOIS check failed for {domain}: {str(e)}")
        
        return {'privacy_protected': False}
    
    def _check_ssl_certificate(self, hostname: str) -> Dict:
        """
        Check SSL/TLS certificate validity
        
        Args:
            hostname: Hostname to check
            
        Returns:
            Dictionary with SSL information
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse expiry date
                    expiry_date_str = cert.get('notAfter')
                    if expiry_date_str:
                        expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                    else:
                        days_until_expiry = None
                    
                    # Get issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    issuer_name = issuer.get('organizationName', 'Unknown')
                    
                    return {
                        'valid': True,
                        'issuer': issuer_name,
                        'days_until_expiry': days_until_expiry,
                        'expired': days_until_expiry < 0 if days_until_expiry else False
                    }
        
        except ssl.SSLError as e:
            logger.debug(f"SSL error for {hostname}: {str(e)}")
            return {'valid': False, 'error': 'SSL certificate invalid'}
        except Exception as e:
            logger.debug(f"SSL check failed for {hostname}: {str(e)}")
            return {'valid': False}
    
    def _check_dns_reputation(self, hostname: str) -> Dict:
        """
        Check DNS reputation (simplified version)
        In production, integrate with services like VirusTotal, Google Safe Browsing, etc.
        
        Args:
            hostname: Hostname to check
            
        Returns:
            Dictionary with reputation score
        """
        score = 50  # Neutral score
        
        try:
            # Check if domain resolves
            answers = self.resolver.resolve(hostname, 'A')
            if not answers:
                score -= 20
            
            # Check for multiple A records (can be sign of CDN or legitimate site)
            if len(answers) > 3:
                score += 10
            
            # Check for AAAA record (IPv6 support indicates more legitimate)
            try:
                aaaa_answers = self.resolver.resolve(hostname, 'AAAA')
                if aaaa_answers:
                    score += 5
            except:
                pass
            
        except dns.resolver.NXDOMAIN:
            score = 0  # Domain doesn't exist
        except Exception as e:
            logger.debug(f"DNS reputation check failed: {str(e)}")
        
        return {'score': max(0, min(100, score))}
    
    def _check_mx_records(self, domain: str) -> bool:
        """
        Check if domain has MX records (email capability)
        
        Args:
            domain: Domain to check
            
        Returns:
            True if MX records exist
        """
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return len(answers) > 0
        except:
            return False


# Factory function
def create_dns_analyzer(config: Config) -> DNSAnalyzer:
    """Create DNS analyzer instance"""
    return DNSAnalyzer(config)