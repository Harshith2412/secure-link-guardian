"""
SecureLink Guardian - MongoDB Handler
Long-term storage and analytics
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
import logging
from typing import Dict, List, Optional
from datetime import datetime
from backend.config import Config

logger = logging.getLogger(__name__)


class MongoHandler:
    """MongoDB handler for analytics"""
    
    def __init__(self, config: Config):
        self.config = config
        self.client = None
        self.db = None
        self.enabled = config.MONGODB_ENABLED
        
        if self.enabled:
            try:
                self.client = MongoClient(
                    config.MONGODB_URL,
                    serverSelectionTimeoutMS=5000
                )
                # Test connection
                self.client.admin.command('ping')
                self.db = self.client[config.MONGODB_DB]
                logger.info("MongoDB connection established")
                
                # Create indexes
                self._create_indexes()
                
            except ConnectionFailure as e:
                logger.warning(f"MongoDB connection failed: {str(e)}")
                self.enabled = False
    
    def _create_indexes(self):
        """Create database indexes"""
        try:
            # Scans collection
            self.db.scans.create_index('url')
            self.db.scans.create_index('timestamp')
            self.db.scans.create_index('risk_score')
            self.db.scans.create_index('verdict')
            
            # Reports collection
            self.db.reports.create_index('url')
            self.db.reports.create_index('timestamp')
            
            logger.info("MongoDB indexes created")
        except Exception as e:
            logger.error(f"Index creation failed: {str(e)}")
    
    def store_scan(self, scan_result: Dict) -> Optional[str]:
        """
        Store scan result
        
        Args:
            scan_result: Scan result dictionary
            
        Returns:
            Inserted document ID or None
        """
        if not self.enabled or not self.db:
            return None
        
        try:
            # Add timestamp if not present
            if 'timestamp' not in scan_result:
                scan_result['timestamp'] = datetime.utcnow()
            
            result = self.db.scans.insert_one(scan_result)
            logger.info(f"Scan stored: {result.inserted_id}")
            return str(result.inserted_id)
            
        except Exception as e:
            logger.error(f"Scan storage error: {str(e)}")
            return None
    
    def get_scan_history(self, limit: int = 10, skip: int = 0) -> List[Dict]:
        """
        Get scan history
        
        Args:
            limit: Number of results
            skip: Number of results to skip
            
        Returns:
            List of scan results
        """
        if not self.enabled or not self.db:
            return []
        
        try:
            scans = self.db.scans.find().sort('timestamp', -1).limit(limit).skip(skip)
            return list(scans)
        except Exception as e:
            logger.error(f"Scan history retrieval error: {str(e)}")
            return []
    
    def get_scan_by_url(self, url: str, limit: int = 5) -> List[Dict]:
        """
        Get scans for a specific URL
        
        Args:
            url: URL to search for
            limit: Number of results
            
        Returns:
            List of scan results
        """
        if not self.enabled or not self.db:
            return []
        
        try:
            scans = self.db.scans.find({'url': url}).sort('timestamp', -1).limit(limit)
            return list(scans)
        except Exception as e:
            logger.error(f"URL scan retrieval error: {str(e)}")
            return []
    
    def store_report(self, report: Dict) -> Optional[str]:
        """
        Store false positive report
        
        Args:
            report: Report dictionary
            
        Returns:
            Inserted document ID or None
        """
        if not self.enabled or not self.db:
            return None
        
        try:
            report['timestamp'] = datetime.utcnow()
            result = self.db.reports.insert_one(report)
            logger.info(f"Report stored: {result.inserted_id}")
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Report storage error: {str(e)}")
            return None
    
    def get_statistics(self) -> Dict:
        """
        Get overall statistics
        
        Returns:
            Dictionary with statistics
        """
        if not self.enabled or not self.db:
            return {
                'total_scans': 0,
                'threats_blocked': 0,
                'safe_sites': 0
            }
        
        try:
            total_scans = self.db.scans.count_documents({})
            
            threats_blocked = self.db.scans.count_documents({
                'risk_score': {'$gte': 70}
            })
            
            safe_sites = self.db.scans.count_documents({
                'risk_score': {'$lt': 30}
            })
            
            # Get average response time
            pipeline = [
                {
                    '$group': {
                        '_id': None,
                        'avg_response_time': {'$avg': '$response_time_ms'}
                    }
                }
            ]
            
            result = list(self.db.scans.aggregate(pipeline))
            avg_response_time = int(result[0]['avg_response_time']) if result else 0
            
            return {
                'total_scans': total_scans,
                'threats_blocked': threats_blocked,
                'safe_sites': safe_sites,
                'avg_response_time': avg_response_time
            }
            
        except Exception as e:
            logger.error(f"Statistics retrieval error: {str(e)}")
            return {
                'total_scans': 0,
                'threats_blocked': 0,
                'safe_sites': 0
            }
    
    def get_top_threats(self, limit: int = 10) -> List[Dict]:
        """
        Get top threat types
        
        Args:
            limit: Number of results
            
        Returns:
            List of threat types with counts
        """
        if not self.enabled or not self.db:
            return []
        
        try:
            pipeline = [
                {'$match': {'risk_score': {'$gte': 70}}},
                {'$group': {
                    '_id': '$verdict',
                    'count': {'$sum': 1}
                }},
                {'$sort': {'count': -1}},
                {'$limit': limit}
            ]
            
            return list(self.db.scans.aggregate(pipeline))
            
        except Exception as e:
            logger.error(f"Top threats retrieval error: {str(e)}")
            return []
    
    def search_scans(self, query: Dict, limit: int = 10) -> List[Dict]:
        """
        Search scans with custom query
        
        Args:
            query: MongoDB query
            limit: Number of results
            
        Returns:
            List of scan results
        """
        if not self.enabled or not self.db:
            return []
        
        try:
            scans = self.db.scans.find(query).sort('timestamp', -1).limit(limit)
            return list(scans)
        except Exception as e:
            logger.error(f"Scan search error: {str(e)}")
            return []
    
    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")


# Factory function
def create_mongo_handler(config: Config) -> MongoHandler:
    """Create MongoDB handler instance"""
    return MongoHandler(config)