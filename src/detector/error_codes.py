"""
Error codes and retry policies for MCP URL classification.
"""

from enum import Enum
from typing import Dict, Optional, Tuple
import asyncio
import random


class ErrorCode(Enum):
    """Standardized error codes for URL classification."""
    
    # Success
    SUCCESS = "0000"
    
    # DNS errors (01xx)
    ERR_DNS_NXDOMAIN = "0101"
    ERR_DNS_TIMEOUT = "0102"
    ERR_DNS_SERVFAIL = "0103"
    
    # TCP errors (02xx)
    ERR_TCP_REFUSED = "0201"
    ERR_TCP_TIMEOUT = "0202"
    ERR_TCP_UNREACHABLE = "0203"
    
    # TLS errors (03xx)
    ERR_TLS_HANDSHAKE = "0301"
    ERR_TLS_CERT_VERIFY = "0302"
    ERR_TLS_PROTOCOL = "0303"
    
    # HTTP errors (04xx)
    ERR_HTTP_TIMEOUT = "0401"
    ERR_HTTP_429 = "0402"
    ERR_HTTP_4XX = "0403"
    ERR_HTTP_5XX = "0404"
    
    # Content errors (05xx)
    ERR_CONTENT_TOO_LARGE = "0501"
    ERR_CONTENT_INVALID = "0502"
    
    # LLM errors (06xx)
    ERR_LLM_TIMEOUT = "0601"
    ERR_LLM_UNAVAILABLE = "0602"
    ERR_LLM_INVALID_RESPONSE = "0603"
    
    # General errors (09xx)
    ERR_UNKNOWN = "0999"


class RetryPolicy:
    """Defines retry behavior for different error types."""
    
    RETRY_CONFIG = {
        ErrorCode.ERR_DNS_NXDOMAIN: {"max_retries": 3, "backoff": [0.5, 1.0, 2.0]},
        ErrorCode.ERR_DNS_TIMEOUT: {"max_retries": 3, "backoff": [0.5, 1.0, 2.0]},
        ErrorCode.ERR_TCP_REFUSED: {"max_retries": 3, "backoff": [0.5, 1.0, 2.0]},
        ErrorCode.ERR_TCP_TIMEOUT: {"max_retries": 2, "backoff": [1.0, 2.0]},
        ErrorCode.ERR_TLS_HANDSHAKE: {"max_retries": 1, "backoff": [0.5]},
        ErrorCode.ERR_HTTP_TIMEOUT: {"max_retries": 2, "backoff": [1.0, 2.0]},
        ErrorCode.ERR_HTTP_429: {"max_retries": 3, "backoff": "adaptive"},  # Use Retry-After header
        ErrorCode.ERR_HTTP_5XX: {"max_retries": 2, "backoff": [1.0, 3.0]},
        ErrorCode.ERR_LLM_TIMEOUT: {"max_retries": 1, "backoff": [0.5]},
        ErrorCode.ERR_LLM_UNAVAILABLE: {"max_retries": 1, "backoff": [2.0]},
    }
    
    @classmethod
    def should_retry(cls, error_code: ErrorCode, retry_count: int) -> bool:
        """Check if we should retry for the given error and retry count."""
        config = cls.RETRY_CONFIG.get(error_code)
        if not config:
            return False
        return retry_count < config["max_retries"]
    
    @classmethod
    async def wait_before_retry(cls, error_code: ErrorCode, retry_count: int, 
                              retry_after: Optional[int] = None) -> None:
        """Wait appropriate time before retry based on error type and count."""
        config = cls.RETRY_CONFIG.get(error_code)
        if not config:
            return
        
        if error_code == ErrorCode.ERR_HTTP_429 and retry_after:
            # Respect Retry-After header but cap at 30 seconds
            wait_time = min(retry_after, 30)
        elif config["backoff"] == "adaptive":
            # Exponential backoff with jitter for rate limiting
            wait_time = min(2 ** retry_count, 10) + random.uniform(0, 1)
        else:
            # Use predefined backoff times
            backoff_times = config["backoff"]
            if retry_count < len(backoff_times):
                wait_time = backoff_times[retry_count]
            else:
                wait_time = backoff_times[-1]
        
        await asyncio.sleep(wait_time)


def map_exception_to_error_code(exception: Exception) -> ErrorCode:
    """Map Python exceptions to standardized error codes."""
    exception_name = exception.__class__.__name__
    exception_str = str(exception).lower()
    
    # DNS errors
    if "nxdomain" in exception_str or "name or service not known" in exception_str:
        return ErrorCode.ERR_DNS_NXDOMAIN
    if "dns" in exception_str and "timeout" in exception_str:
        return ErrorCode.ERR_DNS_TIMEOUT
    if "servfail" in exception_str:
        return ErrorCode.ERR_DNS_SERVFAIL
    
    # TCP errors
    if "connection refused" in exception_str:
        return ErrorCode.ERR_TCP_REFUSED
    if "connection" in exception_str and "timeout" in exception_str:
        return ErrorCode.ERR_TCP_TIMEOUT
    if "unreachable" in exception_str:
        return ErrorCode.ERR_TCP_UNREACHABLE
    
    # TLS errors
    if "ssl" in exception_str or "tls" in exception_str:
        if "handshake" in exception_str:
            return ErrorCode.ERR_TLS_HANDSHAKE
        if "certificate" in exception_str or "cert" in exception_str:
            return ErrorCode.ERR_TLS_CERT_VERIFY
        return ErrorCode.ERR_TLS_PROTOCOL
    
    # HTTP errors
    if "timeout" in exception_str:
        return ErrorCode.ERR_HTTP_TIMEOUT
    
    # Specific exception types
    if exception_name in ["TimeoutError", "asyncio.TimeoutError"]:
        return ErrorCode.ERR_HTTP_TIMEOUT
    if exception_name in ["ConnectionRefusedError"]:
        return ErrorCode.ERR_TCP_REFUSED
    if exception_name in ["gaierror"]:
        return ErrorCode.ERR_DNS_NXDOMAIN
    
    return ErrorCode.ERR_UNKNOWN


class ErrorResult:
    """Container for error information with context."""
    
    def __init__(self, error_code: ErrorCode, message: str = "", 
                 retry_count: int = 0, context: Optional[Dict] = None):
        self.error_code = error_code
        self.message = message
        self.retry_count = retry_count
        self.context = context or {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "error_code": self.error_code.value,
            "message": self.message,
            "retry_count": self.retry_count,
            "context": self.context
        }
    
    def __str__(self) -> str:
        return f"{self.error_code.value}: {self.message}"
