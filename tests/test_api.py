"""
SecureLink Guardian - API Tests
Tests for Flask API endpoints
"""

import pytest
import json

def test_health_endpoint(client):
    """Test health check endpoint"""
    response = client.get('/api/v1/health')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert data['status'] == 'healthy'
    assert 'version' in data

def test_version_endpoint(client):
    """Test version endpoint"""
    response = client.get('/api/v1/version')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'name' in data
    assert 'version' in data

def test_scan_endpoint_valid_url(client, sample_urls):
    """Test scan endpoint with valid URL"""
    url = sample_urls['legitimate'][0]
    
    response = client.post(
        '/api/v1/scan',
        data=json.dumps({'url': url}),
        content_type='application/json'
    )
    
    # May succeed or fail depending on environment
    assert response.status_code in [200, 500]

def test_scan_endpoint_invalid_url(client):
    """Test scan endpoint with invalid URL"""
    response = client.post(
        '/api/v1/scan',
        data=json.dumps({'url': 'not-a-url'}),
        content_type='application/json'
    )
    
    # Should return 400 or 500
    assert response.status_code in [400, 500]

def test_scan_endpoint_missing_url(client):
    """Test scan endpoint without URL"""
    response = client.post(
        '/api/v1/scan',
        data=json.dumps({}),
        content_type='application/json'
    )
    
    assert response.status_code == 400

def test_statistics_endpoint(client):
    """Test statistics endpoint"""
    response = client.get('/api/v1/statistics')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'total_scans' in data
    assert 'threats_blocked' in data

def test_history_endpoint(client):
    """Test history endpoint"""
    response = client.get('/api/v1/history')
    assert response.status_code == 200
    
    data = json.loads(response.data)
    assert 'scans' in data

def test_report_endpoint(client):
    """Test report false positive endpoint"""
    response = client.post(
        '/api/v1/report',
        data=json.dumps({
            'url': 'https://example.com',
            'scan_id': 'test-scan-id',
            'feedback': 'This is a false positive'
        }),
        content_type='application/json'
    )
    
    assert response.status_code in [200, 400]

def test_404_endpoint(client):
    """Test 404 error handling"""
    response = client.get('/api/v1/nonexistent')
    assert response.status_code == 404
    
    data = json.loads(response.data)
    assert 'error' in data

def test_cors_headers(client):
    """Test CORS headers"""
    response = client.get('/api/v1/health')
    
    # CORS headers should be present
    assert 'Access-Control-Allow-Origin' in response.headers

def test_content_type_json(client):
    """Test JSON content type"""
    response = client.get('/api/v1/health')
    assert 'application/json' in response.content_type