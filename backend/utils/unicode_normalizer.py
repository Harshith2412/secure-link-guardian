"""
SecureLink Guardian - Unicode Normalizer
Normalizes Unicode characters to detect homograph attacks
"""

import unicodedata
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class UnicodeNormalizer:
    """Unicode normalization and homograph detection"""
    
    def __init__(self):
        # Comprehensive homoglyph mappings
        self.homoglyphs = {
            # Cyrillic to Latin
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
            'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
            'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ԍ': 'g',
            'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
            'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
            
            # Greek to Latin
            'α': 'a', 'β': 'b', 'γ': 'y', 'δ': 'd', 'ε': 'e',
            'ζ': 'z', 'η': 'n', 'θ': '0', 'ι': 'i', 'κ': 'k',
            'λ': 'l', 'μ': 'u', 'ν': 'v', 'ξ': 'e', 'ο': 'o',
            'π': 'n', 'ρ': 'p', 'σ': 'o', 'τ': 't', 'υ': 'u',
            'φ': 'o', 'χ': 'x', 'ψ': 'w', 'ω': 'w',
            'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
            'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
            'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
            
            # Other lookalikes
            '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
            '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
            'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E',
            'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
        }
    
    def normalize(self, text: str, form: str = 'NFKC') -> str:
        """
        Normalize Unicode text
        
        Args:
            text: Text to normalize
            form: Normalization form (NFC, NFD, NFKC, NFKD)
            
        Returns:
            Normalized text
        """
        return unicodedata.normalize(form, text)
    
    def to_ascii(self, text: str) -> str:
        """
        Convert text to ASCII, replacing special characters
        
        Args:
            text: Text to convert
            
        Returns:
            ASCII text
        """
        # First normalize
        normalized = self.normalize(text)
        
        # Try to encode/decode
        try:
            return normalized.encode('ascii', 'ignore').decode('ascii')
        except Exception:
            return text
    
    def replace_homoglyphs(self, text: str) -> str:
        """
        Replace homoglyphs with their ASCII equivalents
        
        Args:
            text: Text containing possible homoglyphs
            
        Returns:
            Text with homoglyphs replaced
        """
        result = []
        
        for char in text:
            if char in self.homoglyphs:
                result.append(self.homoglyphs[char])
            else:
                result.append(char)
        
        return ''.join(result)
    
    def detect_homoglyphs(self, text: str) -> Dict:
        """
        Detect homoglyphs in text
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary with detection results
        """
        found_homoglyphs = []
        positions = []
        
        for i, char in enumerate(text):
            if char in self.homoglyphs:
                found_homoglyphs.append({
                    'char': char,
                    'replacement': self.homoglyphs[char],
                    'position': i,
                    'unicode_name': unicodedata.name(char, 'UNKNOWN')
                })
                positions.append(i)
        
        return {
            'detected': len(found_homoglyphs) > 0,
            'count': len(found_homoglyphs),
            'homoglyphs': found_homoglyphs,
            'positions': positions,
            'normalized': self.replace_homoglyphs(text)
        }
    
    def detect_mixed_scripts(self, text: str) -> Dict:
        """
        Detect mixed character scripts
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary with script information
        """
        scripts = set()
        script_positions = {}
        
        for i, char in enumerate(text):
            # Get character script
            try:
                script = unicodedata.name(char).split()[0]
                scripts.add(script)
                
                if script not in script_positions:
                    script_positions[script] = []
                script_positions[script].append(i)
                
            except (ValueError, IndexError):
                continue
        
        # Common legitimate mixed scripts
        legitimate_mixes = [
            {'LATIN'},  # Pure Latin
            {'LATIN', 'DIGIT'},  # Latin with digits
            {'LATIN', 'HYPHEN-MINUS'},  # Latin with hyphens
            {'LATIN', 'FULL', 'STOP'}  # Latin with periods
        ]
        
        is_suspicious = (
            len(scripts) > 1 and 
            scripts not in legitimate_mixes
        )
        
        return {
            'scripts': list(scripts),
            'script_count': len(scripts),
            'mixed_scripts': len(scripts) > 1,
            'suspicious': is_suspicious,
            'script_positions': script_positions
        }
    
    def is_confusable(self, text1: str, text2: str) -> bool:
        """
        Check if two strings are confusable (look similar)
        
        Args:
            text1: First string
            text2: Second string
            
        Returns:
            True if confusable
        """
        # Normalize both strings
        norm1 = self.replace_homoglyphs(text1.lower())
        norm2 = self.replace_homoglyphs(text2.lower())
        
        return norm1 == norm2 and text1 != text2
    
    def get_skeleton(self, text: str) -> str:
        """
        Get "skeleton" of text (normalized, homoglyphs replaced, lowercased)
        
        Used for comparison
        
        Args:
            text: Text to skeletonize
            
        Returns:
            Skeleton string
        """
        # Normalize
        normalized = self.normalize(text)
        
        # Replace homoglyphs
        no_homoglyphs = self.replace_homoglyphs(normalized)
        
        # Lowercase
        lowercase = no_homoglyphs.lower()
        
        # Remove non-alphanumeric
        import re
        skeleton = re.sub(r'[^a-z0-9]', '', lowercase)
        
        return skeleton
    
    def analyze_domain(self, domain: str) -> Dict:
        """
        Comprehensive domain analysis for Unicode attacks
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary with complete analysis
        """
        homoglyph_result = self.detect_homoglyphs(domain)
        script_result = self.detect_mixed_scripts(domain)
        skeleton = self.get_skeleton(domain)
        
        # Check if domain contains non-ASCII
        has_non_ascii = any(ord(char) > 127 for char in domain)
        
        return {
            'original': domain,
            'skeleton': skeleton,
            'has_non_ascii': has_non_ascii,
            'homoglyphs': homoglyph_result,
            'scripts': script_result,
            'suspicious': (
                homoglyph_result['detected'] or 
                script_result['suspicious'] or 
                has_non_ascii
            )
        }


# Global instance
unicode_normalizer = UnicodeNormalizer()