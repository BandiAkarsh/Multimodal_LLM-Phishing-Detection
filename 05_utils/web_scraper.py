import os
import time
import asyncio
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from PIL import Image
import io
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebScraper:
    """Scrapes screenshots, HTML, and DOM structure from URLs using Playwright"""
    
    def __init__(self, headless=True, timeout=30000):
        self.timeout = timeout  # Playwright uses milliseconds
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.context = None
        self._init_browser()
    
    def _init_browser(self):
        """Initialize Playwright browser"""
        self.playwright = sync_playwright().start()
        self.browser = self.playwright.chromium.launch(headless=self.headless)
        self.context = self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            ignore_https_errors=True,
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
    
    def scrape_url(self, url):
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
            page = self.context.new_page()
            
            # Navigate to URL
            page.goto(url, timeout=self.timeout, wait_until='networkidle')
            
            # Wait a bit for dynamic content
            page.wait_for_timeout(3000)
            
            # Get screenshot
            screenshot_bytes = page.screenshot(full_page=False)
            result['screenshot'] = Image.open(io.BytesIO(screenshot_bytes))
            
            # Get HTML
            result['html'] = page.content()
            
            # Parse DOM structure
            soup = BeautifulSoup(result['html'], 'lxml')
            result['dom_structure'] = self._extract_dom_features(soup)
            
            result['success'] = True
            logger.info(f"Successfully scraped: {url}")
            
        except Exception as e:
            logger.error(f"Error scraping {url}: {str(e)}")
        
        finally:
            if page:
                page.close()
        
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
    
    def close(self):
        """Close the browser"""
        if self.context:
            self.context.close()
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()
    
    def __del__(self):
        """Cleanup"""
        try:
            self.close()
        except:
            pass
