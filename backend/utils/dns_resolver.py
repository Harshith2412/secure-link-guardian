"""
SecureLink Guardian - DNS Resolver
DNS resolution and network utilities
"""

import dns.resolver
import dns.reversename
import socket
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class DNSResolver:
    """DNS resolution utilities"""
    
    def __init__(self, timeout: int = 5):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def resolve_a(self, domain: str) -> List[str]:
        """
        Resolve A records (IPv4)
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of IPv4 addresses
        """
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"A record resolution failed for {domain}: {str(e)}")
            return []
    
    def resolve_aaaa(self, domain: str) -> List[str]:
        """
        Resolve AAAA records (IPv6)
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of IPv6 addresses
        """
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"AAAA record resolution failed for {domain}: {str(e)}")
            return []
    
    def resolve_mx(self, domain: str) -> List[Dict]:
        """
        Resolve MX records
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of MX records with priority
        """
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [
                {
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange)
                }
                for rdata in answers
            ]
        except Exception as e:
            logger.debug(f"MX record resolution failed for {domain}: {str(e)}")
            return []
    
    def resolve_txt(self, domain: str) -> List[str]:
        """
        Resolve TXT records
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of TXT records
        """
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"TXT record resolution failed for {domain}: {str(e)}")
            return []
    
    def resolve_ns(self, domain: str) -> List[str]:
        """
        Resolve NS records
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of nameservers
        """
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        except Exception as e:
            logger.debug(f"NS record resolution failed for {domain}: {str(e)}")
            return []
    
    def resolve_cname(self, domain: str) -> Optional[str]:
        """
        Resolve CNAME record
        
        Args:
            domain: Domain to resolve
            
        Returns:
            CNAME target or None
        """
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            if answers:
                return str(answers[0])
            return None
        except Exception as e:
            logger.debug(f"CNAME record resolution failed for {domain}: {str(e)}")
            return None
    
    def reverse_dns(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Hostname or None
        """
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = self.resolver.resolve(rev_name, 'PTR')
            if answers:
                return str(answers[0])
            return None
        except Exception as e:
            logger.debug(f"Reverse DNS failed for {ip_address}: {str(e)}")
            return None
    
    def get_all_records(self, domain: str) -> Dict:
        """
        Get all DNS records for a domain
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary with all records
        """
        return {
            'a': self.resolve_a(domain),
            'aaaa': self.resolve_aaaa(domain),
            'mx': self.resolve_mx(domain),
            'txt': self.resolve_txt(domain),
            'ns': self.resolve_ns(domain),
            'cname': self.resolve_cname(domain)
        }
    
    def check_domain_exists(self, domain: str) -> bool:
        """
        Check if domain exists (has DNS records)
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain exists
        """
        try:
            # Try A record first
            self.resolver.resolve(domain, 'A')
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:
            # Other errors might indicate domain exists but has issues
            return True
    
    def get_ip_info(self, ip_address: str) -> Dict:
        """
        Get information about an IP address
        
        Args:
            ip_address: IP address
            
        Returns:
            Dictionary with IP information
        """
        info = {
            'ip': ip_address,
            'hostname': None,
            'is_private': False,
            'is_loopback': False,
            'is_multicast': False
        }
        
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip_address)
            
            info['is_private'] = ip_obj.is_private
            info['is_loopback'] = ip_obj.is_loopback
            info['is_multicast'] = ip_obj.is_multicast
            
            # Reverse DNS
            info['hostname'] = self.reverse_dns(ip_address)
            
        except Exception as e:
            logger.debug(f"IP info lookup failed: {str(e)}")
        
        return info
    
    def resolve_with_fallback(self, domain: str) -> List[str]:
        """
        Resolve domain with fallback to getaddrinfo
        
        Args:
            domain: Domain to resolve
            
        Returns:
            List of IP addresses
        """
        # Try DNS resolution first
        ips = self.resolve_a(domain)
        
        if not ips:
            # Fallback to socket.getaddrinfo
            try:
                result = socket.getaddrinfo(domain, None)
                ips = list(set([r[4][0] for r in result]))
            except Exception as e:
                logger.debug(f"Fallback resolution failed: {str(e)}")
        
        return ips


# Global instance
dns_resolver = DNSResolver()