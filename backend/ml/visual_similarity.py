"""
SecureLink Guardian - Visual Similarity Analyzer
Computer vision for brand logo and visual phishing detection
"""

import cv2
import numpy as np
from PIL import Image
import imagehash
import logging
from typing import Dict, Optional, Tuple
import io
from backend.config import Config

logger = logging.getLogger(__name__)


class VisualSimilarityAnalyzer:
    """Visual analysis for brand impersonation detection"""
    
    def __init__(self, config: Config):
        self.config = config
        
        # Known brand logo hashes (would be populated from database)
        self.brand_logo_hashes = {
            'paypal': None,  # Would store actual perceptual hashes
            'amazon': None,
            'microsoft': None,
            'apple': None,
            'google': None,
            'facebook': None
        }
    
    def analyze_screenshot(self, screenshot_data: bytes, suspected_brand: Optional[str] = None) -> Dict:
        """
        Analyze screenshot for visual phishing indicators
        
        Args:
            screenshot_data: Screenshot image bytes
            suspected_brand: Brand that might be impersonated
            
        Returns:
            Visual analysis results
        """
        logger.info(f"Analyzing screenshot (brand: {suspected_brand})")
        
        try:
            # Convert bytes to image
            image = Image.open(io.BytesIO(screenshot_data))
            
            # Analyze layout
            layout_analysis = self._analyze_layout(image)
            
            # Detect logos
            logo_analysis = self._detect_logos(image, suspected_brand)
            
            # Color scheme analysis
            color_analysis = self._analyze_color_scheme(image)
            
            # Calculate overall similarity if brand is suspected
            similarity_score = None
            if suspected_brand and suspected_brand in self.brand_logo_hashes:
                similarity_score = self._calculate_brand_similarity(
                    image,
                    suspected_brand
                )
            
            return {
                'layout': layout_analysis,
                'logos': logo_analysis,
                'colors': color_analysis,
                'similarity_score': similarity_score,
                'suspicious': self._is_visually_suspicious(
                    layout_analysis, 
                    logo_analysis, 
                    similarity_score
                )
            }
            
        except Exception as e:
            logger.error(f"Visual analysis error: {str(e)}")
            return {
                'error': str(e),
                'suspicious': False
            }
    
    def _analyze_layout(self, image: Image.Image) -> Dict:
        """
        Analyze page layout
        
        Args:
            image: PIL Image
            
        Returns:
            Layout analysis results
        """
        width, height = image.size
        aspect_ratio = width / height if height > 0 else 0
        
        # Convert to numpy array for OpenCV
        img_array = np.array(image)
        
        # Convert to grayscale
        if len(img_array.shape) == 3:
            gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)
        else:
            gray = img_array
        
        # Detect edges
        edges = cv2.Canny(gray, 50, 150)
        edge_density = np.sum(edges > 0) / (width * height)
        
        # Detect forms/rectangles (potential input fields)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        rectangles = [cv2.boundingRect(c) for c in contours]
        
        # Filter for form-like rectangles
        potential_forms = [
            r for r in rectangles 
            if r[2] > 100 and r[3] > 20  # Width > 100, Height > 20
        ]
        
        return {
            'width': width,
            'height': height,
            'aspect_ratio': round(aspect_ratio, 2),
            'edge_density': round(edge_density, 4),
            'potential_forms': len(potential_forms),
            'has_forms': len(potential_forms) > 0
        }
    
    def _detect_logos(self, image: Image.Image, suspected_brand: Optional[str] = None) -> Dict:
        """
        Detect logos in image
        
        Args:
            image: PIL Image
            suspected_brand: Brand to check for
            
        Returns:
            Logo detection results
        """
        # Calculate perceptual hash
        img_hash = imagehash.phash(image)
        
        detected_logos = []
        
        # Compare with known brand logos
        if suspected_brand and suspected_brand in self.brand_logo_hashes:
            brand_hash = self.brand_logo_hashes[suspected_brand]
            if brand_hash:
                # Calculate hash difference
                difference = img_hash - brand_hash
                
                if difference < 10:  # Similar
                    detected_logos.append({
                        'brand': suspected_brand,
                        'confidence': 1.0 - (difference / 64),
                        'hash_difference': difference
                    })
        
        return {
            'detected': len(detected_logos) > 0,
            'logos': detected_logos,
            'image_hash': str(img_hash)
        }
    
    def _analyze_color_scheme(self, image: Image.Image) -> Dict:
        """
        Analyze color scheme
        
        Args:
            image: PIL Image
            
        Returns:
            Color analysis results
        """
        # Resize for faster processing
        small_image = image.resize((100, 100))
        
        # Get dominant colors
        img_array = np.array(small_image)
        
        # Reshape to list of pixels
        pixels = img_array.reshape(-1, 3)
        
        # Calculate mean color
        mean_color = pixels.mean(axis=0)
        
        # Calculate color variance
        color_variance = pixels.var(axis=0)
        
        # Detect if mostly white/blank (suspicious for phishing)
        is_mostly_white = np.all(mean_color > 240)
        
        return {
            'mean_color': [int(c) for c in mean_color],
            'color_variance': [float(v) for v in color_variance],
            'is_mostly_white': is_mostly_white
        }
    
    def _calculate_brand_similarity(self, image: Image.Image, brand: str) -> float:
        """
        Calculate similarity to known brand
        
        Args:
            image: PIL Image
            brand: Brand name
            
        Returns:
            Similarity score 0-1
        """
        # This would use actual brand logo database
        # For now, return placeholder
        
        # Calculate image hash
        img_hash = imagehash.phash(image)
        
        # Would compare with stored brand hash
        # Placeholder: random similarity for demo
        return 0.85 if brand in ['paypal', 'amazon'] else 0.3
    
    def _is_visually_suspicious(
        self, 
        layout: Dict, 
        logos: Dict, 
        similarity_score: Optional[float]
    ) -> bool:
        """
        Determine if visually suspicious
        
        Args:
            layout: Layout analysis
            logos: Logo detection
            similarity_score: Brand similarity score
            
        Returns:
            True if suspicious
        """
        suspicious = False
        
        # High similarity to brand logo but different domain
        if similarity_score and similarity_score > 0.7:
            suspicious = True
        
        # Has forms (potential credential harvesting)
        if layout.get('has_forms'):
            suspicious = True
        
        # Logo detected but might be fake
        if logos.get('detected'):
            suspicious = True
        
        return suspicious
    
    def compare_images(self, image1: Image.Image, image2: Image.Image) -> float:
        """
        Compare two images for similarity
        
        Args:
            image1: First image
            image2: Second image
            
        Returns:
            Similarity score 0-1
        """
        hash1 = imagehash.phash(image1)
        hash2 = imagehash.phash(image2)
        
        difference = hash1 - hash2
        similarity = 1.0 - (difference / 64.0)
        
        return max(0.0, min(1.0, similarity))


# Factory function
def create_visual_similarity_analyzer(config: Config) -> VisualSimilarityAnalyzer:
    """Create visual similarity analyzer instance"""
    return VisualSimilarityAnalyzer(config)