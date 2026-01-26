# 05_utils Folder Documentation

## Overview

The `05_utils/` folder contains utility modules used throughout the project. These are the "building blocks" that extract features, detect patterns, and scrape websites.

## Folder Structure

```
05_utils/
├── feature_extraction.py       # URL feature extractor
├── typosquatting_detector.py   # Brand impersonation detection
├── web_scraper.py              # Playwright-based web scraper
├── connectivity.py             # Internet connectivity checker (NEW)
├── mllm_transformer.py         # Qwen2.5 LLM integration
├── text_feature_generator.py   # Batch MLLM processing
├── data_preparation.py         # Dataset preprocessing
└── common_words.py             # Dictionary for gibberish detection
```

---

## 1. `feature_extraction.py` - URL Feature Extractor

Extracts 17+ features from URLs for ML classification.

### Class: `URLFeatureExtractor`

```python
class URLFeatureExtractor:
    """Extract handcrafted features from URLs"""
    
    @staticmethod
    def extract_features(url):
        features = {}
        
        # Parse URL
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Length features
        features['url_length'] = len(url)
        features['domain_length'] = len(extracted.domain)
        features['path_length'] = len(parsed.path)
        
        # Character counts
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        # ... more ...
        
        return features
```

### Features Extracted

| Feature | Description | Why It Matters |
|---------|-------------|----------------|
| `url_length` | Total URL length | Phishing URLs often very long |
| `domain_length` | Domain name length | Very short = suspicious |
| `path_length` | URL path length | Long paths = obfuscation |
| `num_dots` | Count of `.` | Many dots = subdomains |
| `num_hyphens` | Count of `-` | Many hyphens = suspicious |
| `is_https` | 1 if HTTPS, 0 if HTTP | No HTTPS = less secure |
| `is_ip_address` | 1 if IP used as domain | Using IP = hiding identity |
| `entropy` | Shannon entropy | High = random/generated |
| `is_random_domain` | 1 if gibberish domain | Random letters = DGA malware |
| `vowel_ratio` | Vowels / total letters | Unnatural ratio = generated |

### Vowel/Consonant Check (Lines 66-124)

This is the **static heuristic** that was causing false positives:

```python
# Calculate consonant clusters
consonants = "bcdfghjklmnpqrstvwxyz"
vowels_list = "aeiou"

for char in domain_text:
    if char in consonants:
        current_consecutive_consonants += 1
        max_consecutive_consonants = max(...)
    elif char in vowels_list:
        current_consecutive_vowels += 1
        max_consecutive_vowels = max(...)

# Flag as random if:
if max_consecutive_consonants >= 5:  # e.g., 'sqbqq'
    is_random = 1
elif max_consecutive_vowels >= 3:    # e.g., 'aeiou'
    is_random = 1
elif vowel_ratio < 0.15:             # Very few vowels
    is_random = 1
```

**The problem:** This flags legitimate but unusual domains as phishing.

**The solution:** In ONLINE mode, we ignore `is_random_domain` when we can validate the actual website content.

---

## 2. `typosquatting_detector.py` - Brand Impersonation Detection

Detects URLs that try to impersonate known brands.

### Detection Methods

1. **Faulty Extension** - `.pom` instead of `.com`
2. **Brand in Domain** - `paypal-secure.xyz`
3. **Levenshtein Similarity** - `paypall.com` (extra 'l')
4. **Homoglyph Substitution** - `paypa1.com` (1 instead of l)
5. **Subdomain Attack** - `paypal.malicious.com`

### Protected Brands

```python
PROTECTED_BRANDS = {
    # Financial
    'paypal': ['paypal.com'],
    'hdfc': ['hdfcbank.com', 'hdfc.com'],
    'icici': ['icicibank.com'],
    
    # Tech
    'google': ['google.com', 'gmail.com'],
    'microsoft': ['microsoft.com', 'outlook.com'],
    'amazon': ['amazon.com', 'amazon.in'],
    
    # E-commerce India
    'flipkart': ['flipkart.com'],
    'blinkit': ['blinkit.com'],
    'swiggy': ['swiggy.com'],
    # ... 50+ brands
}
```

### Usage

```python
detector = TyposquattingDetector()
result = detector.analyze("https://paypa1.com")

print(result)
# {
#   'is_typosquatting': True,
#   'impersonated_brand': 'paypal',
#   'detection_method': 'homoglyph_substitution',
#   'similarity_score': 0.95,
#   'risk_increase': 60
# }
```

---

## 3. `web_scraper.py` - Playwright Web Scraper

Scrapes websites to capture multimodal data (screenshot, HTML, DOM).

### Class: `WebScraper`

```python
class WebScraper:
    """Scrapes screenshots, HTML, and DOM structure using Playwright"""
    
    def __init__(self, headless=True, timeout=30000):
        self.timeout = timeout
        self.headless = headless
    
    async def scrape_url(self, url):
        # Launch browser
        browser = await playwright.chromium.launch(headless=True)
        
        # Navigate to URL
        await page.goto(url, timeout=30000)
        
        # Capture screenshot
        screenshot_bytes = await page.screenshot()
        
        # Get HTML
        html = await page.content()
        
        # Extract DOM features
        dom_structure = self._extract_dom_features(html)
        
        return {
            'screenshot': Image.open(io.BytesIO(screenshot_bytes)),
            'html': html,
            'dom_structure': dom_structure,
            'success': True
        }
```

### DOM Features Extracted

```python
def _extract_dom_features(self, soup):
    return {
        'num_forms': len(soup.find_all('form')),
        'num_inputs': len(soup.find_all('input')),
        'num_links': len(soup.find_all('a')),
        'num_images': len(soup.find_all('img')),
        'num_scripts': len(soup.find_all('script')),
        'num_iframes': len(soup.find_all('iframe')),
        'has_login_form': bool(soup.find('input', {'type': 'password'})),
        'title': soup.title.string if soup.title else "",
    }
```

---

## 4. `connectivity.py` - Internet Connectivity Checker (NEW)

Checks if internet is available for web scraping.

### Functions

```python
def check_internet_connection(timeout=2.0) -> bool:
    """
    Check if internet is available by pinging DNS servers.
    
    Returns True if online, False if offline.
    """
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=timeout)
        return True
    except OSError:
        return False
```

### ConnectivityMonitor Class

```python
class ConnectivityMonitor:
    """Monitors connectivity with caching."""
    
    def __init__(self, check_interval=30):
        self.check_interval = check_interval
        self._is_online = check_internet_connection()
    
    @property
    def is_online(self) -> bool:
        """Check if online, refresh if needed."""
        if time_since_last_check > self.check_interval:
            self._is_online = check_internet_connection()
        return self._is_online
```

---

## 5. `mllm_transformer.py` - LLM Integration

Uses Qwen2.5-3B to generate human-readable explanations.

```python
class MLLMFeatureTransformer:
    def __init__(self, model_name="Qwen/Qwen2.5-3B-Instruct"):
        # Load with 4-bit quantization for 4GB VRAM
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=quantization_config,
            device_map="auto"
        )
    
    def transform_to_text(self, metadata):
        prompt = f"""
        Analyze this website for phishing indicators:
        URL: {metadata['url']}
        Features: {metadata['url_features']}
        DOM: {metadata.get('html_summary', 'N/A')}
        """
        
        response = self.model.generate(prompt)
        return response
```

---

## 6. `common_words.py` - Dictionary

Contains common English words to distinguish real words from gibberish.

```python
COMMON_WORDS = {
    'the', 'of', 'and', 'a', 'to', 'in', 'is', 'you',
    'google', 'facebook', 'amazon', 'paypal',
    'login', 'account', 'verify', 'secure',
    # ... 600+ words
}
```

**Usage:** If a domain is a real word (like "apple"), it's not flagged as random even if it has unusual letter patterns.

---

## How Utils Connect to Service

```
PhishingDetectionService
         │
         ├── URLFeatureExtractor (feature_extraction.py)
         │   └── Extracts 17+ features from URL
         │
         ├── TyposquattingDetector (typosquatting_detector.py)
         │   └── Detects brand impersonation
         │
         ├── WebScraper (web_scraper.py)
         │   └── Scrapes website content
         │
         ├── ConnectivityMonitor (connectivity.py)
         │   └── Checks internet availability
         │
         └── MLLMFeatureTransformer (mllm_transformer.py)
             └── Generates explanations
```

---

*This documentation explains the `05_utils/` folder for beginners.*
