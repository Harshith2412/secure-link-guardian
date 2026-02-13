"""
SecureLink Guardian - Privacy Utilities
Secure hashing and privacy protection
"""

import hashlib
import hmac
import secrets
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class PrivacyUtils:
    """Privacy and security utilities"""
    
    @staticmethod
    def hash_url(url: str, algorithm: str = 'sha256') -> str:
        """
        Hash URL for privacy-preserving lookups
        
        Args:
            url: URL to hash
            algorithm: Hash algorithm (sha256, sha512, md5)
            
        Returns:
            Hex hash string
        """
        url_bytes = url.encode('utf-8')
        
        if algorithm == 'sha256':
            return hashlib.sha256(url_bytes).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(url_bytes).hexdigest()
        elif algorithm == 'md5':
            return hashlib.md5(url_bytes).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def hash_url_prefix(url: str, prefix_length: int = 8) -> str:
        """
        Hash URL and return prefix for privacy-preserving queries
        
        Used for k-anonymity in threat intelligence lookups
        
        Args:
            url: URL to hash
            prefix_length: Length of prefix to return
            
        Returns:
            Hash prefix
        """
        full_hash = PrivacyUtils.hash_url(url)
        return full_hash[:prefix_length]
    
    @staticmethod
    def hmac_sign(data: str, secret_key: str, algorithm: str = 'sha256') -> str:
        """
        Generate HMAC signature
        
        Args:
            data: Data to sign
            secret_key: Secret key
            algorithm: Hash algorithm
            
        Returns:
            HMAC signature
        """
        key_bytes = secret_key.encode('utf-8')
        data_bytes = data.encode('utf-8')
        
        if algorithm == 'sha256':
            return hmac.new(key_bytes, data_bytes, hashlib.sha256).hexdigest()
        elif algorithm == 'sha512':
            return hmac.new(key_bytes, data_bytes, hashlib.sha512).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def verify_hmac(data: str, signature: str, secret_key: str, algorithm: str = 'sha256') -> bool:
        """
        Verify HMAC signature
        
        Args:
            data: Original data
            signature: Signature to verify
            secret_key: Secret key
            algorithm: Hash algorithm
            
        Returns:
            True if signature is valid
        """
        expected_signature = PrivacyUtils.hmac_sign(data, secret_key, algorithm)
        return hmac.compare_digest(expected_signature, signature)
    
    @staticmethod
    def generate_scan_id() -> str:
        """
        Generate cryptographically secure scan ID
        
        Returns:
            Unique scan ID
        """
        return secrets.token_urlsafe(16)
    
    @staticmethod
    def anonymize_ip(ip_address: str) -> str:
        """
        Anonymize IP address
        
        Args:
            ip_address: IP address to anonymize
            
        Returns:
            Anonymized IP (last octet removed for IPv4, last 80 bits for IPv6)
        """
        if ':' in ip_address:
            # IPv6
            parts = ip_address.split(':')
            return ':'.join(parts[:4]) + ':0:0:0:0'
        else:
            # IPv4
            parts = ip_address.split('.')
            if len(parts) == 4:
                return '.'.join(parts[:3]) + '.0'
        
        return ip_address
    
    @staticmethod
    def sanitize_user_input(text: str, max_length: int = 1000) -> str:
        """
        Sanitize user input
        
        Args:
            text: Input text
            max_length: Maximum allowed length
            
        Returns:
            Sanitized text
        """
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        # Strip whitespace
        text = text.strip()
        
        return text
    
    @staticmethod
    def mask_sensitive_data(text: str, patterns: Optional[list] = None) -> str:
        """
        Mask sensitive data in text
        
        Args:
            text: Text to mask
            patterns: List of regex patterns to mask
            
        Returns:
            Text with sensitive data masked
        """
        import re
        
        if patterns is None:
            patterns = [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{16}\b',  # Credit card
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            ]
        
        masked_text = text
        for pattern in patterns:
            masked_text = re.sub(pattern, '[REDACTED]', masked_text)
        
        return masked_text
    
    @staticmethod
    def generate_api_key(length: int = 32) -> str:
        """
        Generate API key
        
        Args:
            length: Key length
            
        Returns:
            API key
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison
        
        Prevents timing attacks
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if strings are equal
        """
        return hmac.compare_digest(a, b)


# Global instance
privacy_utils = PrivacyUtils()