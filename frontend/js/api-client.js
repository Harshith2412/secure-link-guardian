/**
 * SecureLink Guardian - API Client
 * Handles all communication with the backend API
 */

class APIClient {
    constructor(baseURL = 'http://localhost:5000/api/v1') {
        this.baseURL = baseURL;
        this.timeout = 30000; // 30 seconds
        this.retryAttempts = 3;
        this.retryDelay = 1000; // 1 second
    }

    /**
     * Make HTTP request with timeout and retry logic
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            signal: controller.signal
        };

        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, mergedOptions);
            clearTimeout(timeoutId);

            if (!response.ok) {
                const error = await response.json().catch(() => ({}));
                throw new Error(error.message || `HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            clearTimeout(timeoutId);
            
            if (error.name === 'AbortError') {
                throw new Error('Request timeout - server took too long to respond');
            }
            
            throw error;
        }
    }

    /**
     * Retry a request with exponential backoff
     */
    async requestWithRetry(endpoint, options = {}, attempt = 1) {
        try {
            return await this.request(endpoint, options);
        } catch (error) {
            if (attempt >= this.retryAttempts) {
                throw error;
            }

            // Exponential backoff
            const delay = this.retryDelay * Math.pow(2, attempt - 1);
            await new Promise(resolve => setTimeout(resolve, delay));

            return this.requestWithRetry(endpoint, options, attempt + 1);
        }
    }

    /**
     * Scan a URL for phishing threats
     */
    async scanURL(url, options = {}) {
        const requestBody = {
            url: url,
            deep_scan: options.deepScan !== false,
            include_screenshot: options.includeScreenshot || false,
            check_redirects: options.checkRedirects !== false,
            analyze_javascript: options.analyzeJavaScript !== false
        };

        return await this.requestWithRetry('/scan', {
            method: 'POST',
            body: JSON.stringify(requestBody)
        });
    }

    /**
     * Get scan history
     */
    async getScanHistory(limit = 10) {
        return await this.request(`/history?limit=${limit}`, {
            method: 'GET'
        });
    }

    /**
     * Report a false positive
     */
    async reportFalsePositive(url, scanId, feedback) {
        return await this.request('/report', {
            method: 'POST',
            body: JSON.stringify({
                url: url,
                scan_id: scanId,
                feedback: feedback,
                timestamp: new Date().toISOString()
            })
        });
    }

    /**
     * Get system statistics
     */
    async getStatistics() {
        return await this.request('/statistics', {
            method: 'GET'
        });
    }

    /**
     * Health check
     */
    async healthCheck() {
        try {
            const response = await this.request('/health', {
                method: 'GET'
            });
            return response.status === 'healthy';
        } catch (error) {
            return false;
        }
    }

    /**
     * Get API version
     */
    async getVersion() {
        return await this.request('/version', {
            method: 'GET'
        });
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = APIClient;
}