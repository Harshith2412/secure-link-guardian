"""
SecureLink Guardian - Main Flask Application
API server for phishing detection
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict

from backend.config import get_config
from backend.models import (
    ScanRequest, ScanResult, ReportRequest,
    StatisticsResponse, HealthResponse, ErrorResponse,
    VerdictEnum, DNSAnalysisResult, URLAnalysisResult,
    WebAnalysisResult, GeneticAnalysisResult
)
from backend.core.detector import PhishingDetector
from backend.core.risk_scorer import RiskScorer

# Initialize Flask app
app = Flask(__name__)
config = get_config()

# Configure CORS
CORS(app, origins=config.CORS_ORIGINS)

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[config.RATE_LIMIT_DEFAULT] if config.RATE_LIMIT_ENABLED else []
)

# Configure logging
logging.basicConfig(
    level=config.LOG_LEVEL,
    format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)

# Initialize detector
detector = PhishingDetector(config)
risk_scorer = RiskScorer(config)

# Simple in-memory statistics (in production, use Redis/MongoDB)
stats = {
    'total_scans': 0,
    'threats_blocked': 0,
    'safe_sites': 0,
    'total_response_time': 0
}


@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        services = {
            'api': True,
            'detector': detector is not None,
            'config': config is not None
        }
        
        return jsonify(HealthResponse(
            status='healthy',
            version=config.VERSION,
            services=services
        ).dict()), 200
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify(HealthResponse(
            status='unhealthy',
            services={}
        ).dict()), 503


@app.route('/api/v1/version', methods=['GET'])
def get_version():
    """Get API version"""
    return jsonify({
        'name': config.APP_NAME,
        'version': config.VERSION,
        'environment': config.ENV
    }), 200


@app.route('/api/v1/scan', methods=['POST'])
@limiter.limit(config.RATE_LIMIT_SCAN if config.RATE_LIMIT_ENABLED else "1000 per minute")
def scan_url():
    """
    Scan a URL for phishing threats
    
    Request body:
        {
            "url": "https://example.com",
            "deep_scan": true,
            "include_screenshot": false
        }
    
    Response:
        ScanResult with risk score and detailed analysis
    """
    start_time = datetime.now()
    
    try:
        # Parse request
        data = request.get_json()
        scan_request = ScanRequest(**data)
        
        logger.info(f"Scanning URL: {scan_request.url}")
        
        # Run detection (sync wrapper for async code)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            detector.analyze(scan_request.url, scan_request.dict())
        )
        loop.close()
        
        # Calculate response time
        response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        # Calculate risk score
        risk_score = risk_scorer.calculate_score(result)
        
        # Determine verdict
        if risk_score < config.RISK_THRESHOLD_LOW:
            verdict = VerdictEnum.SAFE
            stats['safe_sites'] += 1
        elif risk_score < config.RISK_THRESHOLD_HIGH:
            verdict = VerdictEnum.SUSPICIOUS
        else:
            verdict = VerdictEnum.BLOCKED
            stats['threats_blocked'] += 1
        
        # Update statistics
        stats['total_scans'] += 1
        stats['total_response_time'] += response_time_ms
        
        # Build response
        scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            url=scan_request.url,
            risk_score=risk_score,
            verdict=verdict,
            response_time_ms=response_time_ms,
            dns_analysis=result.get('dns'),
            url_analysis=result.get('url'),
            web_analysis=result.get('web'),
            genetic_analysis=result.get('genetic'),
            final_url=result.get('final_url', scan_request.url)
        )
        
        logger.info(f"Scan complete: {scan_request.url} - Risk: {risk_score} - Verdict: {verdict}")
        
        return jsonify(scan_result.dict()), 200
        
    except ValueError as e:
        logger.warning(f"Invalid request: {str(e)}")
        return jsonify(ErrorResponse(
            error="Invalid request",
            details=str(e)
        ).dict()), 400
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify(ErrorResponse(
            error="Scan failed",
            details=str(e) if config.DEBUG else "Internal server error"
        ).dict()), 500


@app.route('/api/v1/report', methods=['POST'])
def report_false_positive():
    """
    Report a false positive
    
    Request body:
        {
            "url": "https://example.com",
            "scan_id": "uuid",
            "feedback": "This is actually safe..."
        }
    """
    try:
        data = request.get_json()
        report = ReportRequest(**data)
        
        logger.info(f"False positive report for: {report.url}")
        
        # In production, store in database for review
        # For now, just log it
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your feedback'
        }), 200
        
    except Exception as e:
        logger.error(f"Report submission failed: {str(e)}")
        return jsonify(ErrorResponse(
            error="Failed to submit report",
            details=str(e)
        ).dict()), 400


@app.route('/api/v1/statistics', methods=['GET'])
def get_statistics():
    """Get system statistics"""
    try:
        avg_response_time = (
            stats['total_response_time'] // stats['total_scans']
            if stats['total_scans'] > 0 else 0
        )
        
        return jsonify(StatisticsResponse(
            total_scans=stats['total_scans'],
            threats_blocked=stats['threats_blocked'],
            safe_sites=stats['safe_sites'],
            avg_response_time=avg_response_time,
            scans_last_hour=0,  # TODO: Implement with Redis
            scans_last_24h=0,   # TODO: Implement with Redis
            top_threats=[]      # TODO: Implement with MongoDB
        ).dict()), 200
        
    except Exception as e:
        logger.error(f"Statistics retrieval failed: {str(e)}")
        return jsonify(ErrorResponse(
            error="Failed to retrieve statistics"
        ).dict()), 500


@app.route('/api/v1/history', methods=['GET'])
def get_scan_history():
    """
    Get scan history
    
    Query params:
        limit: Number of results (default 10)
    """
    try:
        limit = request.args.get('limit', 10, type=int)
        
        # TODO: Implement with MongoDB
        # For now, return empty list
        
        return jsonify({
            'scans': [],
            'total': 0,
            'limit': limit
        }), 200
        
    except Exception as e:
        logger.error(f"History retrieval failed: {str(e)}")
        return jsonify(ErrorResponse(
            error="Failed to retrieve history"
        ).dict()), 500


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify(ErrorResponse(
        error="Endpoint not found",
        details="The requested endpoint does not exist"
    ).dict()), 404


@app.errorhandler(429)
def rate_limit_exceeded(e):
    """Handle rate limit errors"""
    return jsonify(ErrorResponse(
        error="Rate limit exceeded",
        details="Too many requests. Please try again later."
    ).dict()), 429


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(e)}", exc_info=True)
    return jsonify(ErrorResponse(
        error="Internal server error",
        details="An unexpected error occurred" if not config.DEBUG else str(e)
    ).dict()), 500


if __name__ == '__main__':
    logger.info(f"Starting {config.APP_NAME} v{config.VERSION}")
    logger.info(f"Environment: {config.ENV}")
    logger.info(f"Debug mode: {config.DEBUG}")
    
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )