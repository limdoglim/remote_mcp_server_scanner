"""
Rate limiting and throttling for concurrent URL processing.
"""

import asyncio
import time
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for controlling request frequency."""
    
    def __init__(self, max_requests: int = 10, time_window: float = 1.0):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Acquire permission to make a request (blocks if necessary)."""
        async with self._lock:
            now = time.time()
            
            # Remove old requests outside the time window
            self.requests = [req_time for req_time in self.requests 
                           if now - req_time < self.time_window]
            
            # If we're at the limit, wait until we can proceed
            if len(self.requests) >= self.max_requests:
                oldest_request = min(self.requests)
                wait_time = self.time_window - (now - oldest_request)
                if wait_time > 0:
                    logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                    await asyncio.sleep(wait_time)
                    return await self.acquire()  # Recursive call after waiting
            
            # Record this request
            self.requests.append(now)


class ConcurrencyLimiter:
    """Limits the number of concurrent operations."""
    
    def __init__(self, max_concurrent: int = 32):
        """
        Initialize concurrency limiter.
        
        Args:
            max_concurrent: Maximum number of concurrent operations
        """
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.max_concurrent = max_concurrent
        self.active_count = 0
        self._lock = asyncio.Lock()
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.semaphore.acquire()
        async with self._lock:
            self.active_count += 1
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        async with self._lock:
            self.active_count -= 1
        self.semaphore.release()
    
    @property
    def current_load(self) -> float:
        """Get current load as a ratio (0.0 to 1.0)."""
        return self.active_count / self.max_concurrent


class AdaptiveThrottler:
    """Adaptive throttling based on response times and error rates."""
    
    def __init__(self, 
                 target_response_time: float = 2.0,
                 max_error_rate: float = 0.1,
                 adjustment_factor: float = 0.1):
        """
        Initialize adaptive throttler.
        
        Args:
            target_response_time: Target average response time in seconds
            max_error_rate: Maximum acceptable error rate (0.0 to 1.0)
            adjustment_factor: How aggressively to adjust (0.0 to 1.0)
        """
        self.target_response_time = target_response_time
        self.max_error_rate = max_error_rate
        self.adjustment_factor = adjustment_factor
        
        self.response_times = []
        self.error_count = 0
        self.total_requests = 0
        self.current_delay = 0.0
        
        self._lock = asyncio.Lock()
    
    async def record_response(self, response_time: float, had_error: bool = False):
        """Record response time and error status."""
        async with self._lock:
            self.response_times.append(response_time)
            self.total_requests += 1
            
            if had_error:
                self.error_count += 1
            
            # Keep only recent measurements (last 100 requests)
            if len(self.response_times) > 100:
                self.response_times = self.response_times[-100:]
            
            # Adjust delay based on metrics
            self._adjust_delay()
    
    def _adjust_delay(self):
        """Adjust delay based on current metrics."""
        if len(self.response_times) < 10:
            return  # Need more data
        
        avg_response_time = sum(self.response_times) / len(self.response_times)
        error_rate = self.error_count / self.total_requests if self.total_requests > 0 else 0
        
        # Increase delay if response time is too high or error rate is too high
        if avg_response_time > self.target_response_time or error_rate > self.max_error_rate:
            increase = self.adjustment_factor * max(
                (avg_response_time - self.target_response_time) / self.target_response_time,
                (error_rate - self.max_error_rate) / self.max_error_rate
            )
            self.current_delay += increase
            self.current_delay = min(self.current_delay, 5.0)  # Cap at 5 seconds
        else:
            # Decrease delay if things are going well
            decrease = self.adjustment_factor * 0.5
            self.current_delay = max(0, self.current_delay - decrease)
    
    async def wait(self):
        """Wait according to current adaptive delay."""
        if self.current_delay > 0:
            await asyncio.sleep(self.current_delay)
    
    @property
    def current_metrics(self) -> Dict[str, float]:
        """Get current performance metrics."""
        if not self.response_times:
            return {"avg_response_time": 0, "error_rate": 0, "delay": self.current_delay}
        
        avg_response_time = sum(self.response_times) / len(self.response_times)
        error_rate = self.error_count / self.total_requests if self.total_requests > 0 else 0
        
        return {
            "avg_response_time": avg_response_time,
            "error_rate": error_rate,
            "delay": self.current_delay,
            "total_requests": self.total_requests
        }


class DomainThrottler:
    """Per-domain throttling to be respectful to individual servers."""
    
    def __init__(self, default_delay: float = 0.5):
        """
        Initialize domain throttler.
        
        Args:
            default_delay: Default delay between requests to same domain
        """
        self.default_delay = default_delay
        self.last_request_times: Dict[str, float] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
    
    def _get_domain_lock(self, domain: str) -> asyncio.Lock:
        """Get or create lock for domain."""
        if domain not in self._locks:
            self._locks[domain] = asyncio.Lock()
        return self._locks[domain]
    
    async def wait_for_domain(self, domain: str, custom_delay: Optional[float] = None):
        """Wait appropriate time before making request to domain."""
        delay = custom_delay or self.default_delay
        domain_lock = self._get_domain_lock(domain)
        
        async with domain_lock:
            last_request = self.last_request_times.get(domain, 0)
            now = time.time()
            
            time_since_last = now - last_request
            if time_since_last < delay:
                wait_time = delay - time_since_last
                logger.debug(f"Throttling domain {domain}: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
            
            self.last_request_times[domain] = time.time()
