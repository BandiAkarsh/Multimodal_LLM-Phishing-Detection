"""
URL Extraction Utility

Shared module for extracting URLs from text content.
Used by scan_email.py, imap_scanner.py, and other modules.
"""

import re
from typing import List, Set
from urllib.parse import urlparse

# URL pattern that matches most common URL formats
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+',
    re.IGNORECASE
)

# Pattern for cleaning trailing punctuation
TRAILING_PUNCT = re.compile(r'[.,;:!?)>\]]+$')


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text content.
    
    Args:
        text: Raw text content to search
        
    Returns:
        List of unique URLs found
    """
    if not text:
        return []
    
    urls = URL_PATTERN.findall(text)
    
    # Clean and deduplicate
    cleaned = set()
    for url in urls:
        # Remove trailing punctuation
        url = TRAILING_PUNCT.sub('', url)
        # Add protocol if missing
        if url.startswith('www.'):
            url = 'https://' + url
        cleaned.add(url)
    
    return list(cleaned)


def extract_urls_from_html(html: str) -> List[str]:
    """
    Extract URLs from HTML content, including href attributes.
    
    Args:
        html: HTML content
        
    Returns:
        List of unique URLs found
    """
    if not html:
        return []
    
    urls = set()
    
    # Extract from href attributes
    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in href_pattern.findall(html):
        if match.startswith(('http://', 'https://', 'www.')):
            urls.add(match if not match.startswith('www.') else 'https://' + match)
    
    # Also extract from plain text
    text_urls = extract_urls_from_text(html)
    urls.update(text_urls)
    
    return list(urls)


def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid and reachable format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL is valid format
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize a URL for comparison.
    
    Args:
        url: URL to normalize
        
    Returns:
        Normalized URL
    """
    if not url:
        return url
    
    # Add protocol if missing
    if url.startswith('www.'):
        url = 'https://' + url
    elif not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    # Lowercase the domain
    parsed = urlparse(url)
    normalized = f"{parsed.scheme}://{parsed.netloc.lower()}{parsed.path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized
