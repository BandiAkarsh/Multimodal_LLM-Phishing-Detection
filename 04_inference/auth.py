"""
Authentication & Authorization Module for Phishing Guard API

Provides JWT token-based authentication and API key authentication
for the FastAPI endpoints.

Features:
- JWT token generation and validation
- API key authentication (for service-to-service)
- Rate limiting per user/IP
- Secure token storage

Author: Phishing Guard Team
Version: 2.0.0
"""

import os
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Configuration
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))
API_KEYS_FILE = os.path.expanduser("~/.phishing_guard/api_keys.json")

# Security scheme
security = HTTPBearer()


class AuthManager:
    """
    Manages authentication for the Phishing Guard API.
    
    Supports:
    - JWT tokens (for user sessions)
    - API keys (for programmatic access)
    """
    
    def __init__(self):
        self.jwt_secret = JWT_SECRET
        self.api_keys = self._load_api_keys()
    
    def _load_api_keys(self) -> Dict[str, Dict]:
        """Load valid API keys from storage."""
        import json
        if os.path.exists(API_KEYS_FILE):
            try:
                with open(API_KEYS_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def create_token(self, user_id: str, additional_claims: Optional[Dict] = None) -> str:
        """
        Generate a JWT token for user authentication.
        
        Args:
            user_id: Unique user identifier
            additional_claims: Optional additional data to include in token
            
        Returns:
            str: JWT token
            
        Example:
            token = auth_manager.create_token("user@example.com")
        """
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,  # Subject (user ID)
            "iat": now,  # Issued at
            "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
            "jti": str(uuid.uuid4()),  # JWT ID (unique token identifier)
            "type": "access"
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, self.jwt_secret, algorithm=JWT_ALGORITHM)
        return token
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            dict: Decoded token payload
            
        Raises:
            HTTPException: If token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=[JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"}
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"}
            )
    
    def generate_api_key(self, name: str, description: str = "") -> str:
        """
        Generate a new API key for programmatic access.
        
        Args:
            name: Name/identifier for the API key
            description: Optional description
            
        Returns:
            str: The generated API key (save this - only shown once!)
        """
        # Generate secure random API key
        api_key = f"pg_{secrets.token_urlsafe(32)}"
        
        # Hash for storage (don't store plaintext)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store metadata
        self.api_keys[key_hash] = {
            "name": name,
            "description": description,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_used": None,
            "active": True
        }
        
        # Save to file
        self._save_api_keys()
        
        return api_key
    
    def verify_api_key(self, api_key: str) -> bool:
        """
        Verify an API key.
        
        Args:
            api_key: API key to verify
            
        Returns:
            bool: True if valid, False otherwise
        """
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if key_hash in self.api_keys:
            key_data = self.api_keys[key_hash]
            if key_data.get("active", False):
                # Update last used
                key_data["last_used"] = datetime.now(timezone.utc).isoformat()
                self._save_api_keys()
                return True
        
        return False
    
    def _save_api_keys(self):
        """Save API keys to storage."""
        import json
        os.makedirs(os.path.dirname(API_KEYS_FILE), exist_ok=True)
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(self.api_keys, f, indent=2)
        os.chmod(API_KEYS_FILE, 0o600)
    
    def revoke_api_key(self, key_hash: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key_hash: Hash of the API key to revoke
            
        Returns:
            bool: True if revoked, False if not found
        """
        if key_hash in self.api_keys:
            self.api_keys[key_hash]["active"] = False
            self._save_api_keys()
            return True
        return False


# Global auth manager instance
auth_manager = AuthManager()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    FastAPI dependency to get current authenticated user.
    
    Use this in route definitions:
        @app.get("/protected")
        async def protected_route(user: dict = Depends(get_current_user)):
            return {"message": f"Hello {user['sub']}"}
    """
    token = credentials.credentials
    return auth_manager.verify_token(token)


async def verify_api_key_auth(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    FastAPI dependency to verify API key authentication.
    
    Use this for service-to-service authentication:
        @app.post("/api/internal")
        async def internal_route(api_key: str = Depends(verify_api_key_auth)):
            return {"status": "ok"}
    """
    api_key = credentials.credentials
    
    if not auth_manager.verify_api_key(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    return api_key


class RateLimiter:
    """
    Simple in-memory rate limiter (no Redis needed).
    
    Tracks requests per key (IP or user) and enforces limits.
    """
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = {}  # key -> list of timestamps
    
    def is_allowed(self, key: str) -> bool:
        """
        Check if request is allowed for given key.
        
        Args:
            key: Identifier (IP address or user ID)
            
        Returns:
            bool: True if allowed, False if rate limited
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Clean old requests
        if key in self.requests:
            self.requests[key] = [
                ts for ts in self.requests[key] 
                if ts > window_start
            ]
        else:
            self.requests[key] = []
        
        # Check limit
        if len(self.requests[key]) >= self.max_requests:
            return False
        
        # Record request
        self.requests[key].append(now)
        return True
    
    def get_remaining(self, key: str) -> int:
        """Get remaining requests for key."""
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=self.window_seconds)
        
        if key in self.requests:
            recent = len([ts for ts in self.requests[key] if ts > window_start])
            return max(0, self.max_requests - recent)
        
        return self.max_requests


# Global rate limiter instance (in-memory, per-process)
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


async def rate_limit_check(request: Request):
    """
    FastAPI dependency for rate limiting.
    
    Usage:
        @app.post("/api/analyze", dependencies=[Depends(rate_limit_check)])
        async def analyze(...):
            ...
    """
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Check rate limit
    if not rate_limiter.is_allowed(client_ip):
        remaining = rate_limiter.get_remaining(client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in 60 seconds."
        )
    
    # Add rate limit headers to response (handled in middleware)
    request.state.rate_limit_remaining = rate_limiter.get_remaining(client_ip)


def demo():
    """Demonstrate authentication features."""
    print("=" * 60)
    print("Authentication & Authorization Demo")
    print("=" * 60)
    
    # Test JWT token
    print("\n[1] JWT Token Generation & Verification:")
    user_id = "user@example.com"
    token = auth_manager.create_token(user_id)
    print(f"Generated token: {token[:50]}...")
    
    try:
        payload = auth_manager.verify_token(token)
        print(f"✓ Token valid for user: {payload['sub']}")
        print(f"  Expires: {payload['exp']}")
    except Exception as e:
        print(f"✗ Token verification failed: {e}")
    
    # Test API key
    print("\n[2] API Key Generation & Verification:")
    api_key = auth_manager.generate_api_key("test-service", "Demo API key")
    print(f"Generated API key: {api_key}")
    
    is_valid = auth_manager.verify_api_key(api_key)
    print(f"✓ API key valid: {is_valid}")
    
    # Test rate limiter
    print("\n[3] Rate Limiting:")
    test_ip = "192.168.1.1"
    for i in range(5):
        allowed = rate_limiter.is_allowed(test_ip)
        remaining = rate_limiter.get_remaining(test_ip)
        print(f"  Request {i+1}: {'✓' if allowed else '✗'} (remaining: {remaining})")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    demo()
