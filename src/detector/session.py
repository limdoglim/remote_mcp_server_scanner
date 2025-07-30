"""
HTTP session management with SSL verification disabled and proper error handling.
"""

import aiohttp
import asyncio
import ssl
import warnings
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse
import logging

from .error_codes import ErrorCode, map_exception_to_error_code

logger = logging.getLogger(__name__)


class MCPSession:
    """HTTP session with disabled SSL verification and MCP-specific configurations."""
    
    def __init__(self, timeout: int = 5, proxy: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssl_context = self._create_ssl_context()
        
        # Log SSL verification bypass warning
        logger.warning(
            "SSL verification is globally disabled for this session. "
            "This is intentional but poses security risks."
        )
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with verification disabled."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Suppress SSL warnings but keep them in logs
        warnings.filterwarnings('ignore', message='Unverified HTTPS request')
        
        return context
    
    async def __aenter__(self):
        """Async context manager entry."""
        timeout = aiohttp.ClientTimeout(total=self.timeout, connect=self.timeout // 2)
        
        connector = aiohttp.TCPConnector(
            ssl=self._ssl_context,
            limit=100,
            limit_per_host=10,
            enable_cleanup_closed=True
        )
        
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': 'MCP-URL-Classifier/1.0 (Security Research Tool)',
                'Accept': 'text/html,application/json,*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
        )
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session:
            await self._session.close()
    
    async def head_request(self, url: str) -> Tuple[Optional[Dict[str, Any]], ErrorCode]:
        """
        Perform HEAD request to check if URL is accessible.
        
        Returns:
            Tuple of (response_info, error_code)
        """
        try:
            async with self._session.head(url, proxy=self.proxy) as response:
                headers = dict(response.headers)
                
                return {
                    'status': response.status,
                    'headers': headers,
                    'url': str(response.url),
                    'real_url': str(response.real_url) if response.real_url != response.url else None
                }, ErrorCode.SUCCESS
                
        except asyncio.TimeoutError:
            return None, ErrorCode.ERR_HTTP_TIMEOUT
        except aiohttp.ClientResponseError as e:
            if e.status == 429:
                return None, ErrorCode.ERR_HTTP_429
            elif 400 <= e.status < 500:
                return None, ErrorCode.ERR_HTTP_4XX
            elif 500 <= e.status < 600:
                return None, ErrorCode.ERR_HTTP_5XX
            else:
                return None, ErrorCode.ERR_UNKNOWN
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            logger.debug(f"HEAD request failed for {url}: {e}")
            return None, error_code
    
    async def get_request(self, url: str, max_size: int = 1024*1024) -> Tuple[Optional[Dict[str, Any]], ErrorCode]:
        """
        Perform GET request with content size limit.
        
        Args:
            url: Target URL
            max_size: Maximum content size in bytes (default 1MB)
            
        Returns:
            Tuple of (response_data, error_code)
        """
        try:
            async with self._session.get(url, proxy=self.proxy) as response:
                # Check content length
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) > max_size:
                    return None, ErrorCode.ERR_CONTENT_TOO_LARGE
                
                # Read content with size limit
                content = b""
                async for chunk in response.content.iter_chunked(8192):
                    content += chunk
                    if len(content) > max_size:
                        return None, ErrorCode.ERR_CONTENT_TOO_LARGE
                
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    text_content = content.decode('latin-1', errors='ignore')
                
                headers = dict(response.headers)
                
                return {
                    'status': response.status,
                    'headers': headers,
                    'content': text_content,
                    'content_length': len(content),
                    'url': str(response.url),
                    'real_url': str(response.real_url) if response.real_url != response.url else None
                }, ErrorCode.SUCCESS
                
        except asyncio.TimeoutError:
            return None, ErrorCode.ERR_HTTP_TIMEOUT
        except aiohttp.ClientResponseError as e:
            if e.status == 429:
                return None, ErrorCode.ERR_HTTP_429
            elif 400 <= e.status < 500:
                return None, ErrorCode.ERR_HTTP_4XX
            elif 500 <= e.status < 600:
                return None, ErrorCode.ERR_HTTP_5XX
            else:
                return None, ErrorCode.ERR_UNKNOWN
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            logger.debug(f"GET request failed for {url}: {e}")
            return None, error_code
    
    async def check_well_known_mcp(self, base_url: str) -> Tuple[Optional[Dict], ErrorCode]:
        """
        Check for MCP well-known metadata endpoint.
        
        Args:
            base_url: Base URL to check
            
        Returns:
            Tuple of (metadata_dict, error_code)
        """
        parsed = urlparse(base_url)
        well_known_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/mcp/metadata.json"
        
        response_data, error_code = await self.get_request(well_known_url, max_size=64*1024)  # 64KB limit
        
        if error_code != ErrorCode.SUCCESS:
            return None, error_code
        
        try:
            import json
            metadata = json.loads(response_data['content'])
            return metadata, ErrorCode.SUCCESS
        except json.JSONDecodeError:
            return None, ErrorCode.ERR_CONTENT_INVALID
        except Exception:
            return None, ErrorCode.ERR_UNKNOWN
    
    async def get_retry_after(self, url: str) -> Optional[int]:
        """Extract Retry-After header from 429 response."""
        try:
            async with self._session.head(url, proxy=self.proxy) as response:
                if response.status == 429:
                    retry_after = response.headers.get('Retry-After')
                    if retry_after and retry_after.isdigit():
                        return int(retry_after)
        except Exception:
            pass
        return None
