/**
 * SecureLink Guardian - UI Components
 * Handles UI rendering and interactions
 */

class UIComponents {
    constructor() {
        this.animationDuration = 300;
    }

    /**
     * Show loading state with step animation
     */
    showLoading(steps = ['dns', 'url', 'web', 'ml']) {
        const loadingState = document.getElementById('loadingState');
        const resultsArea = document.getElementById('resultsArea');
        const errorState = document.getElementById('errorState');

        resultsArea?.classList.add('hidden');
        errorState?.classList.add('hidden');
        loadingState?.classList.remove('hidden');

        // Animate through steps
        this.animateLoadingSteps(steps);
    }

    /**
     * Animate loading steps sequentially
     */
    animateLoadingSteps(steps, currentIndex = 0) {
        if (currentIndex >= steps.length) return;

        const stepElements = document.querySelectorAll('.loading-step');
        stepElements.forEach(el => el.classList.remove('active'));

        const currentStep = document.querySelector(`[data-step="${steps[currentIndex]}"]`);
        if (currentStep) {
            currentStep.classList.add('active');
        }

        setTimeout(() => {
            this.animateLoadingSteps(steps, currentIndex + 1);
        }, 800);
    }

    /**
     * Hide loading state
     */
    hideLoading() {
        const loadingState = document.getElementById('loadingState');
        loadingState?.classList.add('hidden');
    }

    /**
     * Show error state
     */
    showError(message) {
        const loadingState = document.getElementById('loadingState');
        const resultsArea = document.getElementById('resultsArea');
        const errorState = document.getElementById('errorState');
        const errorMessage = document.getElementById('errorMessage');

        loadingState?.classList.add('hidden');
        resultsArea?.classList.add('hidden');
        errorState?.classList.remove('hidden');

        if (errorMessage) {
            errorMessage.textContent = message;
        }
    }

    /**
     * Show results area
     */
    showResults() {
        const loadingState = document.getElementById('loadingState');
        const resultsArea = document.getElementById('resultsArea');
        const errorState = document.getElementById('errorState');

        loadingState?.classList.add('hidden');
        errorState?.classList.add('hidden');
        resultsArea?.classList.remove('hidden');
    }

    /**
     * Render verdict banner
     */
    renderVerdict(riskScore, url) {
        const verdictBanner = document.getElementById('verdictBanner');
        const riskScoreEl = document.getElementById('riskScore');
        const verdictStatus = document.getElementById('verdictStatus');
        const scannedUrl = document.getElementById('scannedUrl');

        // Determine risk level
        let riskLevel, statusText;
        if (riskScore < 30) {
            riskLevel = 'safe';
            statusText = 'SAFE';
        } else if (riskScore < 70) {
            riskLevel = 'warning';
            statusText = 'SUSPICIOUS';
        } else {
            riskLevel = 'danger';
            statusText = 'BLOCKED';
        }

        // Update verdict banner
        verdictBanner?.classList.remove('safe', 'warning', 'danger');
        verdictBanner?.classList.add(riskLevel);

        // Animate risk score
        if (riskScoreEl) {
            this.animateNumber(riskScoreEl, 0, riskScore, 1000);
        }

        if (verdictStatus) {
            verdictStatus.textContent = statusText;
        }

        if (scannedUrl) {
            scannedUrl.textContent = url;
        }
    }

    /**
     * Animate number counting up
     */
    animateNumber(element, start, end, duration) {
        const range = end - start;
        const increment = range / (duration / 16);
        let current = start;

        const timer = setInterval(() => {
            current += increment;
            if (current >= end) {
                element.textContent = Math.round(end);
                clearInterval(timer);
            } else {
                element.textContent = Math.round(current);
            }
        }, 16);
    }

    /**
     * Render detection result item
     */
    renderResultItem(elementId, data) {
        const element = document.getElementById(elementId);
        if (!element) return;

        if (typeof data === 'boolean') {
            element.innerHTML = this.createBooleanResult(data);
        } else if (typeof data === 'object') {
            element.innerHTML = this.createObjectResult(data);
        } else {
            element.innerHTML = `<div class="result-details">${data}</div>`;
        }
    }

    /**
     * Create boolean result HTML
     */
    createBooleanResult(value) {
        const status = value ? 'danger' : 'safe';
        const icon = value ? 'fa-exclamation-circle' : 'fa-check-circle';
        const text = value ? 'Detected' : 'Not Detected';

        return `
            <div class="result-details ${status}">
                <span class="result-badge ${status}">
                    <i class="fas ${icon}"></i>
                    ${text}
                </span>
            </div>
        `;
    }

    /**
     * Create object result HTML
     */
    createObjectResult(data) {
        let html = '<div class="result-details">';

        for (const [key, value] of Object.entries(data)) {
            if (typeof value === 'boolean') {
                const status = value ? 'danger' : 'safe';
                const icon = value ? 'fa-times-circle' : 'fa-check-circle';
                html += `
                    <div class="result-row">
                        <strong>${this.formatKey(key)}:</strong>
                        <span class="${status}">
                            <i class="fas ${icon}"></i>
                            ${value ? 'Yes' : 'No'}
                        </span>
                    </div>
                `;
            } else if (Array.isArray(value)) {
                html += `
                    <div class="result-row">
                        <strong>${this.formatKey(key)}:</strong>
                        <ul>
                            ${value.map(item => `<li>${item}</li>`).join('')}
                        </ul>
                    </div>
                `;
            } else {
                html += `
                    <div class="result-row">
                        <strong>${this.formatKey(key)}:</strong>
                        <span>${value}</span>
                    </div>
                `;
            }
        }

        html += '</div>';
        return html;
    }

    /**
     * Format object key for display
     */
    formatKey(key) {
        return key
            .replace(/_/g, ' ')
            .replace(/\b\w/g, c => c.toUpperCase());
    }

    /**
     * Render DNS analysis results
     */
    renderDNSResults(data) {
        this.renderResultItem('typosquatting', data.typosquatting || false);
        this.renderResultItem('homograph', data.homograph || false);
        this.renderResultItem('domainAge', data.domain_age || 'Unknown');
        this.renderResultItem('sslCert', data.ssl_certificate || 'Not checked');
    }

    /**
     * Render URL analysis results
     */
    renderURLResults(data) {
        this.renderResultItem('urlShortener', data.is_shortener || false);
        this.renderResultItem('redirectChain', data.redirect_chain || []);
        this.renderResultItem('parameters', data.suspicious_params || 'None detected');
        this.renderResultItem('encoding', data.encoding_tricks || false);
    }

    /**
     * Render web content analysis results
     */
    renderWebResults(data) {
        this.renderResultItem('brandImpersonation', data.brand_impersonation || 'None detected');
        this.renderResultItem('credentialForms', data.credential_forms || false);
        this.renderResultItem('socialEngineering', data.social_engineering || 'Not detected');
        this.renderResultItem('jsAnalysis', data.javascript_analysis || 'Clean');
    }

    /**
     * Render genetic matching results
     */
    renderGeneticResults(data) {
        this.renderResultItem('dnaSimilarity', data.dna_similarity || 'No match');
        this.renderResultItem('mutationFamily', data.mutation_family || 'Unknown');
    }

    /**
     * Setup tab navigation
     */
    setupTabs() {
        const tabButtons = document.querySelectorAll('.tab-button');
        const tabContents = document.querySelectorAll('.tab-content');

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTab = button.dataset.tab;

                // Update active states
                tabButtons.forEach(btn => btn.classList.remove('active'));
                tabContents.forEach(content => content.classList.remove('active'));

                button.classList.add('active');
                document.getElementById(`${targetTab}Tab`)?.classList.add('active');
            });
        });
    }

    /**
     * Show modal
     */
    showModal(content) {
        const modal = document.getElementById('jsonModal');
        const jsonContent = document.getElementById('jsonContent');

        if (jsonContent) {
            jsonContent.textContent = JSON.stringify(content, null, 2);
        }

        modal?.classList.remove('hidden');
    }

    /**
     * Hide modal
     */
    hideModal() {
        const modal = document.getElementById('jsonModal');
        modal?.classList.add('hidden');
    }

    /**
     * Update statistics
     */
    updateStatistics(stats) {
        const totalScans = document.getElementById('totalScans');
        const threatsBlocked = document.getElementById('threatsBlocked');
        const safeSites = document.getElementById('safeSites');
        const avgResponseTime = document.getElementById('avgResponseTime');

        if (totalScans) this.animateNumber(totalScans, 0, stats.total_scans || 0, 1000);
        if (threatsBlocked) this.animateNumber(threatsBlocked, 0, stats.threats_blocked || 0, 1000);
        if (safeSites) this.animateNumber(safeSites, 0, stats.safe_sites || 0, 1000);
        if (avgResponseTime) {
            avgResponseTime.textContent = `${stats.avg_response_time || 0}ms`;
        }
    }

    /**
     * Show toast notification
     */
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('show');
        }, 100);

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    /**
     * Disable scan button
     */
    disableScanButton() {
        const scanButton = document.getElementById('scanButton');
        if (scanButton) {
            scanButton.disabled = true;
            scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Scanning...</span>';
        }
    }

    /**
     * Enable scan button
     */
    enableScanButton() {
        const scanButton = document.getElementById('scanButton');
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.innerHTML = '<i class="fas fa-shield-alt"></i> <span>Scan Link</span>';
        }
    }

    /**
     * Clear input
     */
    clearInput() {
        const urlInput = document.getElementById('urlInput');
        if (urlInput) {
            urlInput.value = '';
            urlInput.focus();
        }
    }

    /**
     * Scroll to results
     */
    scrollToResults() {
        const resultsArea = document.getElementById('resultsArea');
        if (resultsArea) {
            resultsArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UIComponents;
}