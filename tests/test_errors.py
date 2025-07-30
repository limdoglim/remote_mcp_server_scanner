"""
Test error code handling and retry policies.
"""

import pytest
import asyncio
from src.detector.error_codes import (
    ErrorCode, RetryPolicy, map_exception_to_error_code, ErrorResult
)


class TestErrorCodes:
    """Test error code definitions and mapping."""
    
    def test_error_code_values(self):
        """Test that error codes have correct values."""
        assert ErrorCode.SUCCESS.value == "0000"
        assert ErrorCode.ERR_DNS_NXDOMAIN.value == "0101"
        assert ErrorCode.ERR_TCP_REFUSED.value == "0201"
        assert ErrorCode.ERR_TLS_HANDSHAKE.value == "0301"
        assert ErrorCode.ERR_HTTP_TIMEOUT.value == "0401"
        assert ErrorCode.ERR_LLM_TIMEOUT.value == "0601"
    
    def test_exception_mapping(self):
        """Test mapping of Python exceptions to error codes."""
        # DNS errors
        dns_error = Exception("nxdomain")
        assert map_exception_to_error_code(dns_error) == ErrorCode.ERR_DNS_NXDOMAIN
        
        # Connection errors
        conn_error = ConnectionRefusedError("Connection refused")
        assert map_exception_to_error_code(conn_error) == ErrorCode.ERR_TCP_REFUSED
        
        # Timeout errors
        timeout_error = Exception("connection timeout")
        assert map_exception_to_error_code(timeout_error) == ErrorCode.ERR_TCP_TIMEOUT
        
        # SSL errors
        ssl_error = Exception("ssl handshake failed")
        assert map_exception_to_error_code(ssl_error) == ErrorCode.ERR_TLS_HANDSHAKE
        
        # Unknown errors
        unknown_error = Exception("something unexpected")
        assert map_exception_to_error_code(unknown_error) == ErrorCode.ERR_UNKNOWN


class TestRetryPolicy:
    """Test retry policy logic."""
    
    def test_should_retry_logic(self):
        """Test retry decision logic."""
        # DNS errors should retry up to 3 times
        assert RetryPolicy.should_retry(ErrorCode.ERR_DNS_NXDOMAIN, 0) is True
        assert RetryPolicy.should_retry(ErrorCode.ERR_DNS_NXDOMAIN, 2) is True
        assert RetryPolicy.should_retry(ErrorCode.ERR_DNS_NXDOMAIN, 3) is False
        
        # TLS handshake should retry once
        assert RetryPolicy.should_retry(ErrorCode.ERR_TLS_HANDSHAKE, 0) is True
        assert RetryPolicy.should_retry(ErrorCode.ERR_TLS_HANDSHAKE, 1) is False
        
        # Unknown errors should not retry
        assert RetryPolicy.should_retry(ErrorCode.ERR_UNKNOWN, 0) is False
    
    @pytest.mark.asyncio
    async def test_backoff_timing(self):
        """Test retry backoff timing."""
        import time
        
        # Test DNS backoff
        start_time = time.time()
        await RetryPolicy.wait_before_retry(ErrorCode.ERR_DNS_NXDOMAIN, 0)
        elapsed = time.time() - start_time
        assert 0.4 <= elapsed <= 0.6  # Should wait ~0.5 seconds
        
        # Test with custom retry-after
        start_time = time.time()
        await RetryPolicy.wait_before_retry(ErrorCode.ERR_HTTP_429, 0, retry_after=1)
        elapsed = time.time() - start_time
        assert 0.9 <= elapsed <= 1.1  # Should wait ~1 second


class TestErrorResult:
    """Test ErrorResult container class."""
    
    def test_error_result_creation(self):
        """Test creating ErrorResult objects."""
        result = ErrorResult(
            error_code=ErrorCode.ERR_DNS_NXDOMAIN,
            message="Domain not found",
            retry_count=2,
            context={"domain": "example.com"}
        )
        
        assert result.error_code == ErrorCode.ERR_DNS_NXDOMAIN
        assert result.message == "Domain not found"
        assert result.retry_count == 2
        assert result.context["domain"] == "example.com"
    
    def test_error_result_serialization(self):
        """Test ErrorResult serialization."""
        result = ErrorResult(
            error_code=ErrorCode.ERR_HTTP_429,
            message="Rate limited",
            retry_count=1
        )
        
        data = result.to_dict()
        
        assert data["error_code"] == "0402"
        assert data["message"] == "Rate limited"
        assert data["retry_count"] == 1
        assert data["context"] == {}
    
    def test_error_result_string_representation(self):
        """Test ErrorResult string representation."""
        result = ErrorResult(
            error_code=ErrorCode.ERR_LLM_TIMEOUT,
            message="LLM request timed out"
        )
        
        str_repr = str(result)
        assert "0601" in str_repr
        assert "LLM request timed out" in str_repr


class TestErrorCodeIntegration:
    """Test error code integration with real scenarios."""
    
    def test_error_code_hierarchy(self):
        """Test error code categorization."""
        # DNS errors (01xx)
        dns_codes = [
            ErrorCode.ERR_DNS_NXDOMAIN,
            ErrorCode.ERR_DNS_TIMEOUT,
            ErrorCode.ERR_DNS_SERVFAIL
        ]
        
        for code in dns_codes:
            assert code.value.startswith("01")
        
        # TCP errors (02xx)
        tcp_codes = [
            ErrorCode.ERR_TCP_REFUSED,
            ErrorCode.ERR_TCP_TIMEOUT,
            ErrorCode.ERR_TCP_UNREACHABLE
        ]
        
        for code in tcp_codes:
            assert code.value.startswith("02")
        
        # TLS errors (03xx)
        tls_codes = [
            ErrorCode.ERR_TLS_HANDSHAKE,
            ErrorCode.ERR_TLS_CERT_VERIFY,
            ErrorCode.ERR_TLS_PROTOCOL
        ]
        
        for code in tls_codes:
            assert code.value.startswith("03")
    
    def test_comprehensive_error_mapping(self):
        """Test comprehensive error mapping scenarios."""
        test_cases = [
            # DNS related
            (Exception("Name or service not known"), ErrorCode.ERR_DNS_NXDOMAIN),
            (Exception("DNS timeout"), ErrorCode.ERR_DNS_TIMEOUT),
            (Exception("SERVFAIL"), ErrorCode.ERR_DNS_SERVFAIL),
            
            # Network related  
            (ConnectionRefusedError(), ErrorCode.ERR_TCP_REFUSED),
            (Exception("Network unreachable"), ErrorCode.ERR_TCP_UNREACHABLE),
            (Exception("Connection timeout"), ErrorCode.ERR_TCP_TIMEOUT),
            
            # SSL/TLS related
            (Exception("SSL handshake failure"), ErrorCode.ERR_TLS_HANDSHAKE),
            (Exception("Certificate verify failed"), ErrorCode.ERR_TLS_CERT_VERIFY),
            (Exception("TLS protocol error"), ErrorCode.ERR_TLS_PROTOCOL),
            
            # HTTP related
            (Exception("Request timeout"), ErrorCode.ERR_HTTP_TIMEOUT),
            
            # Timeout related
            (TimeoutError(), ErrorCode.ERR_HTTP_TIMEOUT),
        ]
        
        for exception, expected_code in test_cases:
            result_code = map_exception_to_error_code(exception)
            assert result_code == expected_code, f"Failed for {exception}: expected {expected_code}, got {result_code}"


@pytest.mark.asyncio
async def test_retry_policy_integration():
    """Test retry policy with realistic scenarios."""
    
    # Simulate DNS failure with retries
    errors_encountered = []
    
    for attempt in range(5):  # Try up to 5 times
        if RetryPolicy.should_retry(ErrorCode.ERR_DNS_NXDOMAIN, attempt):
            errors_encountered.append(attempt)
            await RetryPolicy.wait_before_retry(ErrorCode.ERR_DNS_NXDOMAIN, attempt)
        else:
            break
    
    # Should have retried 3 times (attempts 0, 1, 2)
    assert len(errors_encountered) == 3
    assert errors_encountered == [0, 1, 2]


if __name__ == '__main__':
    pytest.main([__file__])
