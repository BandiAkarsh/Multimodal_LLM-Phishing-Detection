"""
Web Scraper with Phishing Toolkit Detection

This module scrapes websites using Playwright and detects signatures of common
phishing toolkits like Gophish, HiddenEye, King Phisher, etc.

Toolkit Detection Signatures:
1. Gophish: ?rid= parameter, X-Gophish-Contact header, standard form names
2. HiddenEye: Specific CSS/JS patterns, form structures
3. King Phisher: Campaign tracking, specific DOM patterns
4. SocialFish: Unique file structures and patterns
5. Evilginx2: Proxy-based, specific redirect patterns
"""

import os
import time
import asyncio
import re
import json
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
from PIL import Image
import io
import logging
from typing import Dict, List, Optional, Any, Set

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load TLD list for proper domain parsing
_TLD_SET: Optional[Set[str]] = None

def _load_tld_set() -> Set[str]:
    """Load valid TLDs from the JSON database."""
    global _TLD_SET
    if _TLD_SET is not None:
        return _TLD_SET
    
    tld_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        '01_data', 'external', 'tld_list.json'
    )
    
    try:
        with open(tld_file, 'r', encoding='utf-8') as f:
            tld_data = json.load(f)
            _TLD_SET = set(tld_data.keys())
            logger.info(f"Loaded {len(_TLD_SET)} valid TLDs")
    except Exception as e:
        logger.warning(f"Failed to load TLD list: {e}, using fallback")
        # Fallback with common TLDs
        _TLD_SET = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'co', 'io',
            'bank', 'in', 'uk', 'us', 'de', 'fr', 'jp', 'cn', 'au',
        }
    
    return _TLD_SET


class ToolkitSignatureDetector:
    """
    Detects signatures of common phishing toolkits.
    
    This class contains fingerprints for popular phishing frameworks
    that attackers use to quickly deploy phishing campaigns.
    """
    
    # Gophish signatures
    GOPHISH_SIGNATURES = {
        'url_params': ['rid'],  # Recipient ID tracking
        'headers': ['x-gophish-contact', 'x-gophish-signature'],
        'form_fields': ['username', 'password'],  # Standard Gophish form
        'js_patterns': [
            r'var\s+rid\s*=',
            r'gophish',
            r'campaign_id',
            r'rid=[a-zA-Z0-9]+',
        ],
        'html_patterns': [
            r'<input[^>]*name=["\']rid["\']',
            r'<form[^>]*action=["\'][^"\']*\?rid=',
        ],
        'css_classes': ['gophish', 'phish-form'],
    }
    
    # HiddenEye signatures
    HIDDENEYE_SIGNATURES = {
        'url_patterns': [
            r'/login\.php$',
            r'/index\.php\?',
        ],
        'form_fields': ['login', 'passwd', 'credential'],
        'js_patterns': [
            r'hiddeneye',
            r'pish\.js',
        ],
        'html_patterns': [
            r'<title>.*Login.*</title>',
            r'class=["\']login-container["\']',
        ],
        'meta_patterns': [
            r'<meta[^>]*content=["\']hiddeneye',
        ],
    }
    
    # King Phisher signatures
    KING_PHISHER_SIGNATURES = {
        'url_params': ['id', 'uid', 'campaign'],
        'headers': ['x-king-phisher'],
        'js_patterns': [
            r'king_phisher',
            r'kp_track',
        ],
        'html_patterns': [
            r'<!-- KingPhisher -->',
            r'king-phisher-tracking',
        ],
    }
    
    # SocialFish signatures
    SOCIALFISH_SIGNATURES = {
        'url_patterns': [
            r'/social\.php',
            r'/phish/',
        ],
        'form_fields': ['email', 'pass'],
        'js_patterns': [
            r'socialfish',
            r'sftrack',
        ],
    }
    
    # Evilginx2 signatures (Man-in-the-middle proxy)
    EVILGINX_SIGNATURES = {
        'url_patterns': [
            r'[a-z]+\.[a-z]+\.[a-z]+\.[a-z]+',  # Deeply nested subdomains
        ],
        'cookie_patterns': [
            r'ew_[a-z]+',  # Evilginx session cookies
        ],
        'redirect_patterns': [
            r'redirect_uri=',
            r'oauth.*redirect',
        ],
    }
    
    # Generic phishing kit patterns
    GENERIC_KIT_SIGNATURES = {
        'form_fields': ['log', 'pwd', 'user', 'pass', 'email', 'password'],
        'html_patterns': [
            r'<form[^>]*method=["\']post["\'][^>]*>.*?<input[^>]*type=["\']password',
            r'action=["\'][^"\']*login',
            r'verify.*your.*account',
        ],
        'js_patterns': [
            r'document\.forms\[0\]\.submit',
            r'btoa\(',  # Base64 encoding (credential exfiltration)
            r'XMLHttpRequest.*password',
        ],
        'suspicious_hosts': [
            r'\.000webhostapp\.com',
            r'\.netlify\.app',
            r'\.herokuapp\.com',
            r'\.ngrok\.io',
            r'\.serveo\.net',
        ],
    }
    
    @classmethod
    def detect_toolkit(cls, url: str, html: str, headers: Dict[str, str] = None,
                       soup: BeautifulSoup = None) -> Dict[str, Any]:
        """
        Detect phishing toolkit signatures in scraped content.
        
        Args:
            url: The URL being analyzed
            html: Raw HTML content
            headers: HTTP response headers
            soup: BeautifulSoup parsed HTML
            
        Returns:
            Dictionary with detection results
        """
        result = {
            'detected': False,
            'toolkit_name': None,
            'confidence': 0.0,
            'signatures_found': [],
            'risk_multiplier': 1.0,
        }
        
        if not html:
            return result
        
        if soup is None:
            try:
                soup = BeautifulSoup(html, 'lxml')
            except Exception:
                soup = BeautifulSoup(html, 'html.parser')
        
        headers = headers or {}
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Check each toolkit
        gophish_score, gophish_sigs = cls._check_gophish(url, html, headers, query_params, soup)
        hiddeneye_score, hiddeneye_sigs = cls._check_hiddeneye(url, html, soup)
        kingphisher_score, kingphisher_sigs = cls._check_king_phisher(url, html, headers, query_params)
        socialfish_score, socialfish_sigs = cls._check_socialfish(url, html, soup)
        evilginx_score, evilginx_sigs = cls._check_evilginx(url, html)
        generic_score, generic_sigs = cls._check_generic_kit(url, html, soup)
        
        # Determine the most likely toolkit
        scores = [
            ('Gophish', gophish_score, gophish_sigs),
            ('HiddenEye', hiddeneye_score, hiddeneye_sigs),
            ('King Phisher', kingphisher_score, kingphisher_sigs),
            ('SocialFish', socialfish_score, socialfish_sigs),
            ('Evilginx2', evilginx_score, evilginx_sigs),
            ('Generic Phishing Kit', generic_score, generic_sigs),
        ]
        
        # Sort by score
        scores.sort(key=lambda x: x[1], reverse=True)
        best_match = scores[0]
        
        if best_match[1] >= 0.3:  # Threshold for detection
            result['detected'] = True
            result['toolkit_name'] = best_match[0]
            result['confidence'] = min(1.0, best_match[1])
            result['signatures_found'] = best_match[2]
            result['risk_multiplier'] = 1.5 if best_match[1] >= 0.6 else 1.2
        
        return result
    
    @classmethod
    def _check_gophish(cls, url: str, html: str, headers: Dict, 
                       query_params: Dict, soup: BeautifulSoup) -> tuple:
        """Check for Gophish signatures."""
        score = 0.0
        signatures = []
        
        # Check URL parameters (strongest indicator)
        for param in cls.GOPHISH_SIGNATURES['url_params']:
            if param in query_params:
                score += 0.5
                signatures.append(f"URL parameter: ?{param}=")
        
        # Check headers
        for header in cls.GOPHISH_SIGNATURES['headers']:
            if header.lower() in [h.lower() for h in headers.keys()]:
                score += 0.6
                signatures.append(f"HTTP header: {header}")
        
        # Check HTML patterns
        for pattern in cls.GOPHISH_SIGNATURES['html_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.3
                signatures.append(f"HTML pattern: {pattern[:30]}...")
        
        # Check JS patterns
        for pattern in cls.GOPHISH_SIGNATURES['js_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.2
                signatures.append(f"JavaScript: {pattern[:30]}...")
        
        # Check form structure (Gophish uses standard form with username/password)
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            input_names = [inp.get('name', '').lower() for inp in inputs]
            if 'username' in input_names and 'password' in input_names:
                if 'rid' in url.lower() or len(inputs) <= 3:
                    score += 0.4
                    signatures.append("Standard Gophish form structure")
        
        return score, signatures
    
    @classmethod
    def _check_hiddeneye(cls, url: str, html: str, soup: BeautifulSoup) -> tuple:
        """Check for HiddenEye signatures."""
        score = 0.0
        signatures = []
        
        # Check URL patterns
        for pattern in cls.HIDDENEYE_SIGNATURES['url_patterns']:
            if re.search(pattern, url, re.IGNORECASE):
                score += 0.3
                signatures.append(f"URL pattern: {pattern}")
        
        # Check HTML patterns
        for pattern in cls.HIDDENEYE_SIGNATURES['html_patterns']:
            if re.search(pattern, html, re.IGNORECASE | re.DOTALL):
                score += 0.3
                signatures.append(f"HTML pattern detected")
        
        # Check meta patterns
        for pattern in cls.HIDDENEYE_SIGNATURES['meta_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.5
                signatures.append("HiddenEye meta tag")
        
        # Check JS patterns
        for pattern in cls.HIDDENEYE_SIGNATURES['js_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.4
                signatures.append(f"JavaScript: {pattern}")
        
        return score, signatures
    
    @classmethod
    def _check_king_phisher(cls, url: str, html: str, headers: Dict, 
                            query_params: Dict) -> tuple:
        """Check for King Phisher signatures."""
        score = 0.0
        signatures = []
        
        # Check URL parameters
        for param in cls.KING_PHISHER_SIGNATURES['url_params']:
            if param in query_params:
                score += 0.2
                signatures.append(f"URL parameter: {param}")
        
        # Check headers
        for header in cls.KING_PHISHER_SIGNATURES['headers']:
            if header.lower() in [h.lower() for h in headers.keys()]:
                score += 0.6
                signatures.append(f"HTTP header: {header}")
        
        # Check HTML patterns
        for pattern in cls.KING_PHISHER_SIGNATURES['html_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.5
                signatures.append("King Phisher HTML comment")
        
        # Check JS patterns
        for pattern in cls.KING_PHISHER_SIGNATURES['js_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.3
                signatures.append(f"JavaScript: {pattern}")
        
        return score, signatures
    
    @classmethod
    def _check_socialfish(cls, url: str, html: str, soup: BeautifulSoup) -> tuple:
        """Check for SocialFish signatures."""
        score = 0.0
        signatures = []
        
        # Check URL patterns
        for pattern in cls.SOCIALFISH_SIGNATURES['url_patterns']:
            if re.search(pattern, url, re.IGNORECASE):
                score += 0.3
                signatures.append(f"URL pattern: {pattern}")
        
        # Check JS patterns
        for pattern in cls.SOCIALFISH_SIGNATURES['js_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.4
                signatures.append(f"JavaScript: {pattern}")
        
        # Check form fields
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            input_names = [inp.get('name', '').lower() for inp in inputs]
            matches = sum(1 for f in cls.SOCIALFISH_SIGNATURES['form_fields'] if f in input_names)
            if matches >= 2:
                score += 0.3
                signatures.append("SocialFish form structure")
        
        return score, signatures
    
    @classmethod
    def _check_evilginx(cls, url: str, html: str) -> tuple:
        """
        Check for Evilginx2 signatures.
        
        IMPORTANT: This method now properly handles multi-part TLDs to avoid
        false positives on legitimate domains like netbanking.kotak.bank.in
        where .bank is a legitimate gTLD and .in is India's ccTLD.
        """
        score = 0.0
        signatures = []
        
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        
        # Get actual subdomain depth by accounting for multi-part TLDs
        actual_subdomain_depth = cls._get_actual_subdomain_depth(netloc)
        
        # Only flag deeply nested subdomains if they're truly suspicious
        # (more than 2 actual subdomains, not counting TLD parts)
        if actual_subdomain_depth >= 3:
            # Additional check: legitimate domains rarely have 3+ subdomains
            # unless they're using recognized patterns
            score += 0.15
            signatures.append(f"Deeply nested subdomain ({actual_subdomain_depth} levels)")
        
        # Check redirect patterns (stronger indicator)
        redirect_matches = 0
        for pattern in cls.EVILGINX_SIGNATURES['redirect_patterns']:
            if re.search(pattern, url, re.IGNORECASE):
                redirect_matches += 1
                score += 0.25
                signatures.append(f"Redirect pattern: {pattern}")
        
        # Check URL patterns - but only add score if combined with other indicators
        for pattern in cls.EVILGINX_SIGNATURES['url_patterns']:
            if re.search(pattern, netloc, re.IGNORECASE):
                # Only count if we have other indicators too
                if redirect_matches > 0 or actual_subdomain_depth >= 3:
                    score += 0.15
                    signatures.append("Evilginx URL pattern")
        
        # CRITICAL: Require at least 2 different indicators to flag as Evilginx
        # This prevents false positives on legitimate multi-part TLD domains
        if len(signatures) < 2:
            # Not enough evidence - reset score to prevent false positive
            score = min(score, 0.25)
        
        return score, signatures
    
    @classmethod
    def _get_actual_subdomain_depth(cls, netloc: str) -> int:
        """
        Calculate actual subdomain depth accounting for multi-part TLDs.
        
        Examples:
        - google.com -> 0 subdomains
        - www.google.com -> 1 subdomain  
        - mail.google.com -> 1 subdomain
        - netbanking.kotak.bank.in -> 1 subdomain (bank.in is a valid TLD combo)
        - evil.login.secure.paypal.com.attacker.xyz -> 5 subdomains (suspicious)
        
        Returns:
            Number of actual subdomain levels (excluding TLD parts)
        """
        tld_set = _load_tld_set()
        parts = netloc.split('.')
        
        if len(parts) <= 1:
            return 0
        
        # Check for multi-part TLDs from the right
        # e.g., .co.uk, .bank.in, .com.au
        tld_parts_count = 0
        
        # First check: Is the rightmost part a valid ccTLD or gTLD?
        if parts[-1] in tld_set:
            tld_parts_count = 1
            
            # Check if second-to-last is also a valid TLD (multi-part TLD)
            # e.g., .co.uk where both 'co' and 'uk' are valid TLDs
            # or .bank.in where 'bank' is a gTLD and 'in' is a ccTLD
            if len(parts) >= 2 and parts[-2] in tld_set:
                tld_parts_count = 2
                
                # Check for rare 3-part TLDs (uncommon but possible)
                if len(parts) >= 3 and parts[-3] in tld_set:
                    # Only count as 3-part if it's a known pattern
                    # Most legitimate 3-part are specific like .sch.uk
                    pass  # Keep at 2 for safety
        
        # Special case: Second-level domains under ccTLDs
        # e.g., .co.uk, .com.au, .ac.in, .gov.in, .nic.in
        COMMON_SLD_PATTERNS = {'co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'nic', 'res'}
        if len(parts) >= 2 and parts[-2].lower() in COMMON_SLD_PATTERNS:
            tld_parts_count = max(tld_parts_count, 2)
        
        # Calculate actual subdomains = total parts - TLD parts - domain name (1)
        # Minimum subdomain count is 0
        actual_subdomains = max(0, len(parts) - tld_parts_count - 1)
        
        return actual_subdomains
    
    @classmethod
    def _check_generic_kit(cls, url: str, html: str, soup: BeautifulSoup) -> tuple:
        """Check for generic phishing kit signatures."""
        score = 0.0
        signatures = []
        
        parsed = urlparse(url)
        
        # Check suspicious hosts
        for pattern in cls.GENERIC_KIT_SIGNATURES['suspicious_hosts']:
            if re.search(pattern, parsed.netloc, re.IGNORECASE):
                score += 0.3
                signatures.append(f"Suspicious hosting: {pattern}")
        
        # Check HTML patterns
        for pattern in cls.GENERIC_KIT_SIGNATURES['html_patterns']:
            if re.search(pattern, html, re.IGNORECASE | re.DOTALL):
                score += 0.15
                signatures.append(f"HTML pattern: {pattern[:25]}...")
        
        # Check JS patterns (credential harvesting)
        for pattern in cls.GENERIC_KIT_SIGNATURES['js_patterns']:
            if re.search(pattern, html, re.IGNORECASE):
                score += 0.2
                signatures.append(f"Suspicious JS: {pattern[:25]}...")
        
        # Check form fields
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            input_names = [inp.get('name', '').lower() for inp in inputs]
            input_types = [inp.get('type', '').lower() for inp in inputs]
            
            # Check for password field with suspicious form
            if 'password' in input_types:
                # Check if form action is suspicious
                action = form.get('action', '')
                if action and ('login' in action.lower() or 'verify' in action.lower()):
                    score += 0.2
                    signatures.append("Login form with suspicious action")
        
        return score, signatures


class WebScraper:
    """Scrapes screenshots, HTML, and DOM structure from URLs using Playwright (Async)"""
    
    def __init__(self, headless=True, timeout=30000):
        self.timeout = timeout  # Playwright uses milliseconds
        self.headless = headless
        self.playwright = None
        self.browser = None
        self.context = None
        self.response_headers = {}
    
    async def _init_browser(self):
        """Initialize Playwright browser"""
        if self.playwright is None:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=self.headless)
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                ignore_https_errors=True,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                extra_http_headers={
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                }
            )
            
    async def scrape_url(self, url: str) -> Dict[str, Any]:
        """
        Scrape all modalities from a URL including toolkit detection.
        
        Returns:
            Dictionary with:
            - url: The scraped URL
            - screenshot: PIL Image object
            - html: Raw HTML content
            - dom_structure: Extracted DOM features
            - toolkit_signatures: Detected phishing toolkit info
            - text_content: Extracted text from page
            - success: Boolean indicating success
        """
        # Initialize browser if not already done
        await self._init_browser()
        
        result = {
            'url': url,
            'screenshot': None,
            'html': None,
            'dom_structure': None,
            'toolkit_signatures': None,
            'text_content': None,
            'response_headers': {},
            'success': False
        }
        
        page = None
        
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Create new page
            page = await self.context.new_page()
            
            # Capture response headers
            response_headers = {}
            
            async def capture_response(response):
                if response.url == url or response.url == url.rstrip('/'):
                    for key, value in response.headers.items():
                        response_headers[key] = value
            
            page.on('response', capture_response)
            
            # Navigate to URL (Wait for DOMContentLoaded instead of NetworkIdle to prevent timeouts)
            response = await page.goto(url, timeout=30000, wait_until='domcontentloaded')
            
            # Capture headers from main response
            if response:
                for key, value in response.headers.items():
                    response_headers[key] = value
            
            result['response_headers'] = response_headers
            
            # Wait a bit for dynamic content
            await page.wait_for_timeout(2000)
            
            # Get screenshot
            screenshot_bytes = await page.screenshot(full_page=False)
            result['screenshot'] = Image.open(io.BytesIO(screenshot_bytes))
            
            # Get HTML
            result['html'] = await page.content()
            
            # Get text content (for AI detection)
            result['text_content'] = await page.evaluate('() => document.body.innerText')
            
            # Parse DOM structure (robust fallback)
            try:
                soup = BeautifulSoup(result['html'], 'lxml')
            except Exception:
                soup = BeautifulSoup(result['html'], 'html.parser')
                
            result['dom_structure'] = self._extract_dom_features(soup)
            
            # Detect phishing toolkit signatures
            result['toolkit_signatures'] = ToolkitSignatureDetector.detect_toolkit(
                url=url,
                html=result['html'],
                headers=response_headers,
                soup=soup
            )
            
            if result['toolkit_signatures']['detected']:
                toolkit_name = result['toolkit_signatures']['toolkit_name']
                logger.warning(f"TOOLKIT DETECTED: {toolkit_name} on {url}")
            
            result['success'] = True
            logger.info(f"Successfully scraped: {url}")
            
        except Exception as e:
            logger.error(f"Error scraping {url}: {str(e)}")
        
        finally:
            if page:
                await page.close()
        
        return result
    
    def _extract_dom_features(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract structural features from DOM"""
        # Extract form details for toolkit detection
        forms = soup.find_all('form')
        form_details = []
        for form in forms:
            inputs = form.find_all('input')
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get'),
                'input_names': [inp.get('name', '') for inp in inputs],
                'input_types': [inp.get('type', '') for inp in inputs],
            }
            form_details.append(form_info)
        
        return {
            'num_forms': len(soup.find_all('form')),
            'num_inputs': len(soup.find_all('input')),
            'num_links': len(soup.find_all('a')),
            'num_images': len(soup.find_all('img')),
            'num_scripts': len(soup.find_all('script')),
            'num_iframes': len(soup.find_all('iframe')),
            'has_login_form': bool(soup.find('input', {'type': 'password'})),
            'title': soup.title.string if soup.title else "",
            'meta_tags': len(soup.find_all('meta')),
            'form_details': form_details,  # Added for toolkit detection
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
