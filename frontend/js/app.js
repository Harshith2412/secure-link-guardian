/**
 * SecureLink Guardian - Main Application
 * Orchestrates the entire application flow
 */

// Initialize components
const apiClient = new APIClient();
const linkScanner = new LinkScanner();
const ui = new UIComponents();

// Application state
const appState = {
    currentScan: null,
    scanHistory: [],
    statistics: {
        total_scans: 0,
        threats_blocked: 0,
        safe_sites: 0,
        avg_response_time: 0
    }
};

/**
 * Initialize application
 */
function initializeApp() {
    console.log('🛡️ SecureLink Guardian initializing...');

    // Setup event listeners
    setupEventListeners();

    // Setup UI components
    ui.setupTabs();

    // Load statistics
    loadStatistics();

    // Check backend health
    checkBackendHealth();

    console.log('✅ Application initialized');
}

/**
 * Setup all event listeners
 */
function setupEventListeners() {
    // Scan button
    const scanButton = document.getElementById('scanButton');
    scanButton?.addEventListener('click', handleScan);

    // URL input - Enter key
    const urlInput = document.getElementById('urlInput');
    urlInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleScan();
        }
    });

    // Example links
    const exampleLinks = document.querySelectorAll('.example-link');
    exampleLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            const url = e.currentTarget.dataset.url;
            if (urlInput) {
                urlInput.value = url;
            }
            handleScan();
        });
    });

    // New scan button
    const newScanButton = document.getElementById('newScanButton');
    newScanButton?.addEventListener('click', () => {
        ui.clearInput();
        document.getElementById('resultsArea')?.classList.add('hidden');
    });

    // Retry button
    const retryButton = document.getElementById('retryButton');
    retryButton?.addEventListener('click', handleScan);

    // Report button
    const reportButton = document.getElementById('reportButton');
    reportButton?.addEventListener('click', handleReportFalsePositive);

    // Details button (show raw JSON)
    const detailsButton = document.getElementById('detailsButton');
    detailsButton?.addEventListener('click', () => {
        if (appState.currentScan) {
            ui.showModal(appState.currentScan);
        }
    });

    // Modal close button
    const modalClose = document.querySelector('.modal-close');
    modalClose?.addEventListener('click', () => ui.hideModal());

    // Close modal on background click
    const modal = document.getElementById('jsonModal');
    modal?.addEventListener('click', (e) => {
        if (e.target === modal) {
            ui.hideModal();
        }
    });
}

/**
 * Handle URL scan
 */
async function handleScan() {
    const urlInput = document.getElementById('urlInput');
    const inputValue = urlInput?.value.trim();

    if (!inputValue) {
        ui.showToast('Please enter a URL or message with links', 'warning');
        return;
    }

    // Extract URLs from input
    const urls = linkScanner.extractURLs(inputValue);
    
    if (urls.length === 0) {
        // Check if input is a URL without protocol
        if (!inputValue.startsWith('http')) {
            const withProtocol = 'https://' + inputValue;
            if (linkScanner.isValidURL(withProtocol)) {
                await scanURL(withProtocol);
                return;
            }
        }
        ui.showToast('No valid URLs found in input', 'danger');
        return;
    }

    // Scan first URL found
    await scanURL(urls[0]);
}

/**
 * Scan a single URL
 */
async function scanURL(url) {
    console.log(`🔍 Scanning URL: ${url}`);

    // Validate URL
    if (!linkScanner.isValidURL(url)) {
        ui.showToast('Invalid URL format', 'danger');
        return;
    }

    // Show loading state
    ui.showLoading();
    ui.disableScanButton();

    // Get quick risk indicators (client-side)
    const quickIndicators = linkScanner.getQuickRiskIndicators(url);
    console.log('Quick risk indicators:', quickIndicators);

    try {
        // Call backend API for deep analysis
        const startTime = Date.now();
        const result = await apiClient.scanURL(url, {
            deepScan: true,
            checkRedirects: true,
            analyzeJavaScript: true
        });
        const responseTime = Date.now() - startTime;

        console.log('✅ Scan complete:', result);

        // Store current scan
        appState.currentScan = result;
        appState.scanHistory.unshift({
            url: url,
            timestamp: new Date().toISOString(),
            riskScore: result.risk_score,
            verdict: result.verdict
        });

        // Update statistics
        updateStatistics(responseTime, result.risk_score);

        // Hide loading and show results
        ui.hideLoading();
        ui.showResults();

        // Render results
        renderScanResults(url, result);

        // Scroll to results
        setTimeout(() => ui.scrollToResults(), 100);

    } catch (error) {
        console.error('❌ Scan failed:', error);
        ui.hideLoading();
        ui.showError(error.message || 'Failed to scan URL. Please try again.');
    } finally {
        ui.enableScanButton();
    }
}

/**
 * Render scan results
 */
function renderScanResults(url, result) {
    // Render verdict banner
    ui.renderVerdict(result.risk_score || 0, url);

    // Render DNS analysis
    ui.renderDNSResults(result.dns_analysis || {});

    // Render URL analysis
    ui.renderURLResults(result.url_analysis || {});

    // Render web content analysis
    ui.renderWebResults(result.web_analysis || {});

    // Render genetic matching
    ui.renderGeneticResults(result.genetic_analysis || {});
}

/**
 * Handle false positive report
 */
async function handleReportFalsePositive() {
    if (!appState.currentScan) {
        ui.showToast('No scan to report', 'warning');
        return;
    }

    const feedback = prompt('Please provide details about why this is a false positive:');
    if (!feedback) return;

    try {
        await apiClient.reportFalsePositive(
            appState.currentScan.url,
            appState.currentScan.scan_id,
            feedback
        );

        ui.showToast('Thank you for your feedback!', 'success');
    } catch (error) {
        console.error('Failed to report false positive:', error);
        ui.showToast('Failed to submit report', 'danger');
    }
}

/**
 * Update statistics
 */
function updateStatistics(responseTime, riskScore) {
    appState.statistics.total_scans++;
    
    if (riskScore >= 70) {
        appState.statistics.threats_blocked++;
    } else if (riskScore < 30) {
        appState.statistics.safe_sites++;
    }

    // Update average response time
    const prevTotal = appState.statistics.avg_response_time * (appState.statistics.total_scans - 1);
    appState.statistics.avg_response_time = Math.round(
        (prevTotal + responseTime) / appState.statistics.total_scans
    );

    // Update UI
    ui.updateStatistics(appState.statistics);

    // Save to localStorage
    saveStatistics();
}

/**
 * Load statistics from localStorage
 */
function loadStatistics() {
    try {
        const saved = localStorage.getItem('securelink_stats');
        if (saved) {
            appState.statistics = JSON.parse(saved);
            ui.updateStatistics(appState.statistics);
        }
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

/**
 * Save statistics to localStorage
 */
function saveStatistics() {
    try {
        localStorage.setItem('securelink_stats', JSON.stringify(appState.statistics));
    } catch (error) {
        console.error('Failed to save statistics:', error);
    }
}

/**
 * Check backend health
 */
async function checkBackendHealth() {
    try {
        const healthy = await apiClient.healthCheck();
        if (healthy) {
            console.log('✅ Backend is healthy');
        } else {
            console.warn('⚠️ Backend health check failed');
            showBackendWarning();
        }
    } catch (error) {
        console.error('❌ Cannot connect to backend:', error);
        showBackendWarning();
    }
}

/**
 * Show backend connection warning
 */
function showBackendWarning() {
    const warningHTML = `
        <div class="backend-warning">
            <i class="fas fa-exclamation-triangle"></i>
            <span>Backend server is not responding. Please ensure the server is running.</span>
            <button onclick="location.reload()">Retry</button>
        </div>
    `;
    
    // Insert warning at top of page
    const container = document.querySelector('.container');
    if (container) {
        container.insertAdjacentHTML('afterbegin', warningHTML);
    }
}

/**
 * Demo mode - simulate API response
 */
function getDemoResponse(url) {
    const demoData = {
        scan_id: 'demo_' + Date.now(),
        url: url,
        risk_score: Math.floor(Math.random() * 100),
        verdict: 'demo',
        timestamp: new Date().toISOString(),
        
        dns_analysis: {
            typosquatting: Math.random() > 0.7,
            homograph: false,
            domain_age: '2 years',
            ssl_certificate: 'Valid'
        },
        
        url_analysis: {
            is_shortener: linkScanner.isShortener(url),
            redirect_chain: [],
            suspicious_params: 'None',
            encoding_tricks: false
        },
        
        web_analysis: {
            brand_impersonation: 'None detected',
            credential_forms: false,
            social_engineering: 'Not detected',
            javascript_analysis: 'Clean'
        },
        
        genetic_analysis: {
            dna_similarity: 'No match',
            mutation_family: 'Unknown'
        }
    };

    // Adjust based on URL
    if (url.includes('amaz0n') || url.includes('paypa1')) {
        demoData.risk_score = 95;
        demoData.dns_analysis.typosquatting = true;
    } else if (linkScanner.isShortener(url)) {
        demoData.risk_score = 65;
    } else if (linkScanner.isTrustedDomain(url)) {
        demoData.risk_score = 5;
    }

    return demoData;
}

/**
 * Enable demo mode if backend is not available
 */
function enableDemoMode() {
    console.log('🔄 Demo mode enabled');
    
    // Override scanURL to use demo data
    window.originalScanURL = scanURL;
    window.scanURL = async function(url) {
        ui.showLoading();
        ui.disableScanButton();

        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 2000));

        const result = getDemoResponse(url);
        
        appState.currentScan = result;
        updateStatistics(200, result.risk_score);

        ui.hideLoading();
        ui.showResults();
        renderScanResults(url, result);
        ui.enableScanButton();
        
        setTimeout(() => ui.scrollToResults(), 100);
    };
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        initializeApp,
        handleScan,
        scanURL,
        renderScanResults
    };
}