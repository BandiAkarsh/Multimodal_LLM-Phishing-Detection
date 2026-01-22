import os
import time
import asyncio
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from PIL import Image
import io
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebScraper:
    """Scrapes screenshots, HTML, and DOM structure from URLs using Playwright (Async)"""
    
    def __init__(self, headless=True, timeout=30000):
        self.timeout = timeout  # Playwright uses milliseconds
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.context = None
    
    async def _init_browser(self):
        """Initialize Playwright browser"""
        if self.playwright is None:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=self.headless)
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
    
    async def scrape_url(self, url):
        """
        Scrape all modalities from a URL
        
        Returns:
            dict: {
                'screenshot': PIL.Image,
                'html': str,
                'dom_structure': dict,
                'url': str,
                'success': bool
            }
        """
        # Initialize browser if not already done
        await self._init_browser()
        
        result = {
            'url': url,
            'screenshot': None,
            'html': None,
            'dom_structure': None,
            'success': False
        }
        
        page = None
        
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Create new page
            page = await self.context.new_page()
            
            # Navigate to URL
            await page.goto(url, timeout=self.timeout, wait_until='networkidle')
            
            # Wait a bit for dynamic content
            await page.wait_for_timeout(3000)
            
            # Get screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            result['screenshot'] = Image.open(io.BytesIO(screenshot_bytes))
            
            # Get HTML
            result['html'] = await page.content()
            
            # Parse DOM structure
            soup = BeautifulSoup(result['html'], 'lxml')
            result['dom_structure'] = self._extract_dom_features(soup)
            
            result['success'] = True
            logger.info(f"Successfully scraped: {url}")
            
        except Exception as e:
            logger.error(f"Error scraping {url}: {str(e)}")
        
        finally:
            if page:
                await page.close()
        
        return result
    
    def _extract_dom_features(self, soup):
        """Extract structural features from DOM"""
        return {
            'num_forms': len(soup.find_all('form')),
            'num_inputs': len(soup.find_all('input')),
            'num_links': len(soup.find_all('a')),
            'num_images': len(soup.find_all('img')),
            'num_scripts': len(soup.find_all('script')),
            'num_iframes': len(soup.find_all('iframe')),
            'has_login_form': bool(soup.find('input', {'type': 'password'})),
            'title': soup.title.string if soup.title else "",
            'meta_tags': len(soup.find_all('meta'))
        }
    
    async def close(self):
        """Close the browser"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._init_browser()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
