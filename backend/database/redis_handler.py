"""
SecureLink Guardian - Redis Handler
Caching layer for improved performance
"""

import redis
import json
import logging
from typing import Optional, Any
from backend.config import Config

logger = logging.getLogger(__name__)


class RedisHandler:
    """Redis cache handler"""
    
    def __init__(self, config: Config):
        self.config = config
        self.client = None
        self.enabled = config.REDIS_ENABLED
        
        if self.enabled:
            try:
                self.client = redis.Redis(**config.get_redis_config())
                self.client.ping()
                logger.info("Redis connection established")
            except Exception as e:
                logger.warning(f"Redis connection failed: {str(e)}")
                self.enabled = False
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        if not self.enabled or not self.client:
            return None
        
        try:
            value = self.client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.debug(f"Cache get error: {str(e)}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            
        Returns:
            True if successful
        """
        if not self.enabled or not self.client:
            return False
        
        try:
            serialized = json.dumps(value)
            if ttl:
                self.client.setex(key, ttl, serialized)
            else:
                self.client.set(key, serialized)
            return True
        except Exception as e:
            logger.debug(f"Cache set error: {str(e)}")
            return False
    
    def delete(self, key: str) -> bool:
        """
        Delete key from cache
        
        Args:
            key: Cache key
            
        Returns:
            True if successful
        """
        if not self.enabled or not self.client:
            return False
        
        try:
            self.client.delete(key)
            return True
        except Exception as e:
            logger.debug(f"Cache delete error: {str(e)}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if not self.enabled or not self.client:
            return False
        
        try:
            return self.client.exists(key) > 0
        except Exception as e:
            logger.debug(f"Cache exists check error: {str(e)}")
            return False
    
    def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter"""
        if not self.enabled or not self.client:
            return None
        
        try:
            return self.client.incrby(key, amount)
        except Exception as e:
            logger.debug(f"Cache increment error: {str(e)}")
            return None
    
    def get_scan_cache_key(self, url: str) -> str:
        """Generate cache key for scan result"""
        import hashlib
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        return f"scan:{url_hash}"
    
    def get_dns_cache_key(self, domain: str) -> str:
        """Generate cache key for DNS result"""
        return f"dns:{domain}"
    
    def flush_all(self) -> bool:
        """Flush all cache (use with caution)"""
        if not self.enabled or not self.client:
            return False
        
        try:
            self.client.flushdb()
            logger.warning("Cache flushed")
            return True
        except Exception as e:
            logger.error(f"Cache flush error: {str(e)}")
            return False


# Factory function
def create_redis_handler(config: Config) -> RedisHandler:
    """Create Redis handler instance"""
    return RedisHandler(config)