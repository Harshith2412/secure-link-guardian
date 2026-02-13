"""
SecureLink Guardian - Sandbox Renderer
Headless browser for safe web page rendering and analysis
"""

import asyncio
import logging
from typing import Dict, Optional
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
from backend.config import Config

logger = logging.getLogger(__name__)


class SandboxRenderer:
    """
    Headless browser renderer for safe page analysis
    
    Uses Playwright to render pages in an isolated environment
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.SANDBOX_TIMEOUT * 1000  # Convert to milliseconds
        self.user_agent = config.SANDBOX_USER_AGENT
        self.playwright = None
        self.browser = None
    
    async def initialize(self):
        """Initialize Playwright browser"""
        if not self.playwright:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-web-security'
                ]
            )
            logger.info("Sandbox browser initialized")
    
    async def cleanup(self):
        """Cleanup browser resources"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("Sandbox browser cleaned up")
    
    async def render_page(self, url: str, options: Optional[Dict] = None) -> Dict:
        """
        Render a page in the sandbox
        
        Args:
            url: URL to render
            options: Optional rendering options
            
        Returns:
            Dictionary with page data
        """
        options = options or {}
        
        try:
            await self.initialize()
            
            # Create new page with context
            context = await self.browser.new_context(
                user_agent=self.user_agent,
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True
            )
            
            page = await context.new_page()
            
            # Set up request/response tracking
            requests = []
            responses = []
            
            page.on('request', lambda req: requests.append({
                'url': req.url,
                'method': req.method,
                'resource_type': req.resource_type
            }))
            
            page.on('response', lambda res: responses.append({
                'url': res.url,
                'status': res.status,
                'headers': dict(res.headers)
            }))
            
            # Navigate to page
            logger.info(f"Rendering page: {url}")
            response = await page.goto(
                url,
                wait_until='networkidle',
                timeout=self.timeout
            )
            
            # Extract page data
            result = {
                'success': True,
                'url': url,
                'final_url': page.url,
                'status': response.status if response else None,
                'title': await page.title(),
                'html': await page.content(),
                'screenshot': None,
                'requests': requests,
                'responses': responses,
                'cookies': await context.cookies(),
                'local_storage': await page.evaluate('() => Object.assign({}, localStorage)'),
                'console_logs': []
            }
            
            # Capture screenshot if requested
            if options.get('screenshot', False):
                screenshot_data = await page.screenshot(
                    full_page=False,
                    type='png'
                )
                result['screenshot'] = screenshot_data
            
            # Get meta tags
            result['meta_tags'] = await self._extract_meta_tags(page)
            
            # Get forms
            result['forms'] = await self._extract_forms(page)
            
            # Get JavaScript
            result['javascript'] = await self._extract_javascript(page)
            
            await context.close()
            
            logger.info(f"Page rendered successfully: {url}")
            return result
            
        except PlaywrightTimeout:
            logger.warning(f"Page render timeout: {url}")
            return {
                'success': False,
                'error': 'Timeout',
                'url': url
            }
            
        except Exception as e:
            logger.error(f"Page render error: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'url': url
            }
    
    async def _extract_meta_tags(self, page) -> Dict:
        """Extract meta tags from page"""
        try:
            meta_tags = await page.evaluate('''() => {
                const metas = Array.from(document.querySelectorAll('meta'));
                return metas.map(meta => ({
                    name: meta.getAttribute('name'),
                    property: meta.getAttribute('property'),
                    content: meta.getAttribute('content')
                }));
            }''')
            return meta_tags
        except Exception as e:
            logger.debug(f"Meta tag extraction failed: {str(e)}")
            return []
    
    async def _extract_forms(self, page) -> list:
        """Extract forms from page"""
        try:
            forms = await page.evaluate('''() => {
                const forms = Array.from(document.querySelectorAll('form'));
                return forms.map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.querySelectorAll('input')).map(input => ({
                        type: input.type,
                        name: input.name,
                        id: input.id
                    }))
                }));
            }''')
            return forms
        except Exception as e:
            logger.debug(f"Form extraction failed: {str(e)}")
            return []
    
    async def _extract_javascript(self, page) -> Dict:
        """Extract JavaScript information"""
        try:
            js_info = await page.evaluate('''() => {
                const scripts = Array.from(document.querySelectorAll('script'));
                return {
                    inline_count: scripts.filter(s => !s.src).length,
                    external_count: scripts.filter(s => s.src).length,
                    external_sources: scripts.filter(s => s.src).map(s => s.src)
                };
            }''')
            return js_info
        except Exception as e:
            logger.debug(f"JavaScript extraction failed: {str(e)}")
            return {}
    
    async def check_redirect_chain(self, url: str) -> list:
        """
        Check for redirect chain
        
        Args:
            url: URL to check
            
        Returns:
            List of URLs in redirect chain
        """
        chain = [url]
        
        try:
            await self.initialize()
            
            context = await self.browser.new_context(
                user_agent=self.user_agent
            )
            page = await context.new_page()
            
            # Track navigation
            async def handle_response(response):
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('location')
                    if location and location not in chain:
                        chain.append(location)
            
            page.on('response', handle_response)
            
            await page.goto(url, timeout=self.timeout)
            
            # Add final URL if different
            if page.url != url and page.url not in chain:
                chain.append(page.url)
            
            await context.close()
            
        except Exception as e:
            logger.debug(f"Redirect chain check failed: {str(e)}")
        
        return chain


# Factory function
def create_sandbox_renderer(config: Config) -> SandboxRenderer:
    """Create sandbox renderer instance"""
    return SandboxRenderer(config)