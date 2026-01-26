"""
Internet Connectivity Checker Utility

This module provides functions to check if the system has an active internet
connection. This is crucial for the phishing detection system because:

1. When ONLINE: The system performs full web scraping to analyze actual website
   content, which is more accurate than static URL analysis.

2. When OFFLINE: The system falls back to static URL feature analysis (entropy,
   vowel/consonant patterns, etc.) which is less accurate but still useful.

The connectivity check is fast (< 2 seconds) and uses reliable endpoints
(Cloudflare DNS, Google DNS) to minimize false negatives.
"""

import socket
import asyncio
from typing import Tuple
import time


# Reliable endpoints for connectivity testing
# Using DNS servers because they're always up and respond quickly
CONNECTIVITY_ENDPOINTS = [
    ("1.1.1.1", 53),      # Cloudflare DNS (Primary)
    ("8.8.8.8", 53),      # Google DNS (Fallback 1)
    ("208.67.222.222", 53),  # OpenDNS (Fallback 2)
]

# HTTP endpoints for more thorough testing
HTTP_ENDPOINTS = [
    "https://www.google.com",
    "https://www.cloudflare.com",
    "https://www.microsoft.com",
]

# Cache for connectivity status
_connectivity_cache = {
    'is_online': None,
    'last_check': 0,
    'cache_duration': 30  # Recheck every 30 seconds
}


def check_internet_connection(timeout: float = 2.0, use_cache: bool = True) -> bool:
    """
    Check if internet connection is available.
    
    This function attempts to connect to reliable DNS servers to determine
    if the system has internet access. It uses a socket connection to DNS
    port 53, which is faster than HTTP requests.
    
    Args:
        timeout: Maximum time in seconds to wait for connection (default: 2.0)
        use_cache: Whether to use cached result if recent (default: True)
    
    Returns:
        bool: True if internet is available, False otherwise
    
    Example:
        >>> if check_internet_connection():
        ...     print("Online - will use web scraping")
        ... else:
        ...     print("Offline - will use static analysis")
    """
    # Check cache first
    if use_cache:
        current_time = time.time()
        if (_connectivity_cache['is_online'] is not None and 
            current_time - _connectivity_cache['last_check'] < _connectivity_cache['cache_duration']):
            return _connectivity_cache['is_online']
    
    # Try each endpoint until one succeeds
    for host, port in CONNECTIVITY_ENDPOINTS:
        try:
            # Create a socket connection to the DNS server
            # This is faster than HTTP because it doesn't require a full handshake
            socket.setdefaulttimeout(timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Connection successful - we're online
                _connectivity_cache['is_online'] = True
                _connectivity_cache['last_check'] = time.time()
                return True
                
        except (socket.error, socket.timeout, OSError):
            # This endpoint failed, try the next one
            continue
    
    # All endpoints failed - we're offline
    _connectivity_cache['is_online'] = False
    _connectivity_cache['last_check'] = time.time()
    return False


async def check_internet_connection_async(timeout: float = 2.0) -> bool:
    """
    Async version of internet connectivity check.
    
    This is useful when called from async contexts like the FastAPI service
    or async web scraping functions.
    
    Args:
        timeout: Maximum time in seconds to wait for connection
    
    Returns:
        bool: True if internet is available, False otherwise
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, check_internet_connection, timeout, True)


def get_connectivity_status() -> dict:
    """
    Get detailed connectivity status including cache information.
    
    Returns:
        dict: Connectivity status with details
        {
            'is_online': bool,
            'last_check': float (timestamp),
            'cache_age_seconds': float,
            'mode': 'online' or 'offline'
        }
    """
    is_online = check_internet_connection()
    current_time = time.time()
    
    return {
        'is_online': is_online,
        'last_check': _connectivity_cache['last_check'],
        'cache_age_seconds': current_time - _connectivity_cache['last_check'],
        'mode': 'online' if is_online else 'offline',
        'analysis_type': 'Full Multimodal Scraping' if is_online else 'Static URL Analysis'
    }


def clear_connectivity_cache():
    """
    Clear the connectivity cache to force a fresh check.
    
    Useful when network conditions change (e.g., WiFi reconnected).
    """
    _connectivity_cache['is_online'] = None
    _connectivity_cache['last_check'] = 0


def set_cache_duration(seconds: int):
    """
    Set how long connectivity status is cached.
    
    Args:
        seconds: Cache duration in seconds (default is 30)
    """
    _connectivity_cache['cache_duration'] = seconds


class ConnectivityMonitor:
    """
    A class for continuous connectivity monitoring.
    
    Useful for long-running services like imap_scanner.py that need
    to adapt to changing network conditions.
    
    Example:
        >>> monitor = ConnectivityMonitor()
        >>> if monitor.is_online:
        ...     result = await service.analyze_url_async(url)
        ... else:
        ...     result = service.analyze_url(url)  # Static fallback
    """
    
    def __init__(self, check_interval: int = 30):
        """
        Initialize the connectivity monitor.
        
        Args:
            check_interval: How often to check connectivity (seconds)
        """
        self.check_interval = check_interval
        self._is_online = check_internet_connection()
        self._last_check = time.time()
        self._status_changed_callback = None
    
    @property
    def is_online(self) -> bool:
        """Check if we're currently online, refreshing if needed."""
        current_time = time.time()
        if current_time - self._last_check >= self.check_interval:
            old_status = self._is_online
            self._is_online = check_internet_connection(use_cache=False)
            self._last_check = current_time
            
            # Notify if status changed
            if old_status != self._is_online and self._status_changed_callback:
                self._status_changed_callback(self._is_online)
        
        return self._is_online
    
    @property
    def mode(self) -> str:
        """Get current mode as string."""
        return 'online' if self.is_online else 'offline'
    
    def on_status_change(self, callback):
        """
        Register a callback for when connectivity status changes.
        
        Args:
            callback: Function that takes a bool (is_online) as argument
        """
        self._status_changed_callback = callback
    
    def force_refresh(self) -> bool:
        """Force an immediate connectivity check."""
        self._is_online = check_internet_connection(use_cache=False)
        self._last_check = time.time()
        return self._is_online


# Quick test when run directly
if __name__ == "__main__":
    print("Testing Internet Connectivity...")
    print("-" * 40)
    
    status = get_connectivity_status()
    
    if status['is_online']:
        print("[ONLINE] Internet connection is available")
        print(f"  Mode: {status['analysis_type']}")
    else:
        print("[OFFLINE] No internet connection detected")
        print(f"  Mode: {status['analysis_type']}")
    
    print("-" * 40)
    print("Connectivity checker is working correctly!")
