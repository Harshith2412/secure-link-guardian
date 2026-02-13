/**
 * SecureLink Guardian - Link Scanner
 * Utilities for URL extraction, validation, and analysis
 */

class LinkScanner {
    constructor() {
        // URL regex pattern
        this.urlPattern = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/gi;
        
        // Common URL shorteners
        this.shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'lnkd.in',
            'shorturl.at', 'rebrand.ly', 'cutt.ly', 'bl.ink'
        ];

        // Suspicious TLDs
        this.suspiciousTLDs = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
            '.work', '.click', '.link', '.download', '.zip'
        ];

        // Trusted domains
        this.trustedDomains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'stackoverflow.com', 'reddit.com', 'youtube.com'
        ];
    }

    /**
     * Extract URLs from text
     */
    extractURLs(text) {
        const matches = text.match(this.urlPattern);
        return matches ? [...new Set(matches)] : [];
    }

    /**
     * Validate URL format
     */
    isValidURL(url) {
        try {
            const urlObj = new URL(url);
            return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
        } catch (error) {
            return false;
        }
    }

    /**
     * Parse URL components
     */
    parseURL(url) {
        try {
            const urlObj = new URL(url);
            return {
                protocol: urlObj.protocol,
                hostname: urlObj.hostname,
                port: urlObj.port,
                pathname: urlObj.pathname,
                search: urlObj.search,
                hash: urlObj.hash,
                domain: this.extractDomain(urlObj.hostname),
                subdomain: this.extractSubdomain(urlObj.hostname),
                tld: this.extractTLD(urlObj.hostname),
                params: this.extractParams(urlObj.search)
            };
        } catch (error) {
            return null;
        }
    }

    /**
     * Extract domain from hostname
     */
    extractDomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length >= 2) {
            return parts.slice(-2).join('.');
        }
        return hostname;
    }

    /**
     * Extract subdomain from hostname
     */
    extractSubdomain(hostname) {
        const parts = hostname.split('.');
        if (parts.length > 2) {
            return parts.slice(0, -2).join('.');
        }
        return '';
    }

    /**
     * Extract TLD from hostname
     */
    extractTLD(hostname) {
        const parts = hostname.split('.');
        return parts.length > 0 ? '.' + parts[parts.length - 1] : '';
    }

    /**
     * Extract URL parameters
     */
    extractParams(search) {
        const params = {};
        if (search) {
            const urlParams = new URLSearchParams(search);
            for (const [key, value] of urlParams) {
                params[key] = value;
            }
        }
        return params;
    }

    /**
     * Check if URL uses a shortener
     */
    isShortener(url) {
        const parsed = this.parseURL(url);
        if (!parsed) return false;

        return this.shorteners.some(shortener => 
            parsed.hostname.includes(shortener)
        );
    }

    /**
     * Check if URL has suspicious TLD
     */
    hasSuspiciousTLD(url) {
        const parsed = this.parseURL(url);
        if (!parsed) return false;

        return this.suspiciousTLDs.some(tld => 
            parsed.tld === tld
        );
    }

    /**
     * Check if domain is trusted
     */
    isTrustedDomain(url) {
        const parsed = this.parseURL(url);
        if (!parsed) return false;

        return this.trustedDomains.some(domain => 
            parsed.domain === domain
        );
    }

    /**
     * Calculate Levenshtein distance for typosquatting detection
     */
    levenshteinDistance(str1, str2) {
        const matrix = [];

        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        return matrix[str2.length][str1.length];
    }

    /**
     * Check for potential typosquatting
     */
    checkTyposquatting(url) {
        const parsed = this.parseURL(url);
        if (!parsed) return { suspicious: false };

        const results = [];

        for (const trusted of this.trustedDomains) {
            const distance = this.levenshteinDistance(parsed.domain, trusted);
            const similarity = 1 - (distance / Math.max(parsed.domain.length, trusted.length));

            if (distance <= 2 && distance > 0 && similarity > 0.7) {
                results.push({
                    suspicious: true,
                    targetDomain: trusted,
                    distance: distance,
                    similarity: (similarity * 100).toFixed(1) + '%'
                });
            }
        }

        return results.length > 0 ? results[0] : { suspicious: false };
    }

    /**
     * Detect potential homograph attacks
     */
    detectHomograph(url) {
        const parsed = this.parseURL(url);
        if (!parsed) return false;

        // Check for non-ASCII characters
        const hasNonASCII = /[^\x00-\x7F]/.test(parsed.hostname);
        
        // Check for lookalike characters
        const lookalikes = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
            'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's'
        };

        let hasLookalike = false;
        for (const char of parsed.hostname) {
            if (lookalikes[char]) {
                hasLookalike = true;
                break;
            }
        }

        return hasNonASCII || hasLookalike;
    }

    /**
     * Analyze URL parameters for suspicious content
     */
    analyzeParameters(url) {
        const parsed = this.parseURL(url);
        if (!parsed || Object.keys(parsed.params).length === 0) {
            return { suspicious: false };
        }

        const suspiciousPatterns = [
            'redirect', 'url', 'link', 'goto', 'next', 'continue',
            'return', 'callback', 'ref', 'redir', 'target'
        ];

        const suspicious = [];

        for (const [key, value] of Object.entries(parsed.params)) {
            // Check for suspicious parameter names
            if (suspiciousPatterns.some(pattern => key.toLowerCase().includes(pattern))) {
                // Check if value is a URL
                if (this.isValidURL(value)) {
                    suspicious.push({
                        param: key,
                        value: value,
                        reason: 'Parameter contains redirect URL'
                    });
                }
            }

            // Check for Base64 encoded content
            if (this.isBase64(value)) {
                suspicious.push({
                    param: key,
                    value: value.substring(0, 50) + '...',
                    reason: 'Parameter contains Base64 encoded data'
                });
            }
        }

        return {
            suspicious: suspicious.length > 0,
            findings: suspicious
        };
    }

    /**
     * Check if string is Base64 encoded
     */
    isBase64(str) {
        if (str.length < 10) return false;
        const base64Pattern = /^[A-Za-z0-9+/=]{10,}$/;
        return base64Pattern.test(str);
    }

    /**
     * Get URL risk indicators
     */
    getQuickRiskIndicators(url) {
        const indicators = [];

        if (this.isShortener(url)) {
            indicators.push({
                type: 'warning',
                message: 'URL shortener detected'
            });
        }

        if (this.hasSuspiciousTLD(url)) {
            indicators.push({
                type: 'warning',
                message: 'Suspicious TLD'
            });
        }

        const typosquatting = this.checkTyposquatting(url);
        if (typosquatting.suspicious) {
            indicators.push({
                type: 'danger',
                message: `Possible typosquatting of ${typosquatting.targetDomain}`
            });
        }

        if (this.detectHomograph(url)) {
            indicators.push({
                type: 'danger',
                message: 'Possible homograph attack detected'
            });
        }

        const params = this.analyzeParameters(url);
        if (params.suspicious) {
            indicators.push({
                type: 'warning',
                message: `Suspicious URL parameters (${params.findings.length})`
            });
        }

        if (this.isTrustedDomain(url)) {
            indicators.push({
                type: 'safe',
                message: 'Trusted domain'
            });
        }

        return indicators;
    }

    /**
     * Format URL for display
     */
    formatURLForDisplay(url, maxLength = 60) {
        if (url.length <= maxLength) return url;
        
        const parsed = this.parseURL(url);
        if (!parsed) return url.substring(0, maxLength) + '...';

        return `${parsed.protocol}//${parsed.hostname}${parsed.pathname.substring(0, 20)}...`;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LinkScanner;
}