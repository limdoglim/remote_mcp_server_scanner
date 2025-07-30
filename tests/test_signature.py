"""
Test MCP signature detection functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from src.detector.signature import MCPSignatureDetector
from src.detector.session import MCPSession
from src.detector.error_codes import ErrorCode


@pytest.fixture
def mock_session():
    """Create a mock MCP session."""
    session = Mock(spec=MCPSession)
    session.check_well_known_mcp = AsyncMock()
    session.head_request = AsyncMock()
    session.get_request = AsyncMock()
    return session


@pytest.fixture
def signature_detector(mock_session):
    """Create signature detector with mock session."""
    return MCPSignatureDetector(mock_session)


class TestMCPSignatureDetector:
    """Test MCP signature detection."""
    
    def test_url_pattern_scanning(self, signature_detector):
        """Test URL pattern detection."""
        test_cases = [
            {
                'url': 'https://example.com/.well-known/mcp/metadata.json',
                'expected_server_patterns': 1,
                'expected_total': 1
            },
            {
                'url': 'https://example.com/docs/mcp/getting-started',
                'expected_intro_patterns': 1,
                'expected_total': 1
            },
            {
                'url': 'https://example.com/registry/servers',
                'expected_registry_patterns': 1,
                'expected_total': 1
            },
            {
                'url': 'https://example.com/normal/page',
                'expected_total': 0
            }
        ]
        
        for case in test_cases:
            result = asyncio.run(signature_detector.scan_url_patterns(case['url']))
            
            if 'expected_server_patterns' in case:
                assert result['server_patterns'] == case['expected_server_patterns']
            
            if 'expected_intro_patterns' in case:
                assert result['intro_patterns'] == case['expected_intro_patterns']
            
            if 'expected_registry_patterns' in case:
                assert result['registry_patterns'] == case['expected_registry_patterns']
            
            assert result['total_matches'] == case['expected_total']
    
    @pytest.mark.asyncio
    async def test_well_known_endpoint_success(self, signature_detector, mock_session):
        """Test successful well-known endpoint detection."""
        # Mock successful response
        mock_metadata = {
            'version': '1.0.0',
            'name': 'test-mcp-server',
            'description': 'Test MCP server'
        }
        mock_session.check_well_known_mcp.return_value = (mock_metadata, ErrorCode.SUCCESS)
        
        found, metadata, error_code = await signature_detector.check_well_known_endpoint('https://example.com')
        
        assert found is True
        assert metadata == mock_metadata
        assert error_code == ErrorCode.SUCCESS
    
    @pytest.mark.asyncio
    async def test_well_known_endpoint_not_found(self, signature_detector, mock_session):
        """Test well-known endpoint not found."""
        mock_session.check_well_known_mcp.return_value = (None, ErrorCode.ERR_HTTP_4XX)
        
        found, metadata, error_code = await signature_detector.check_well_known_endpoint('https://example.com')
        
        assert found is False
        assert metadata == {}
        assert error_code == ErrorCode.ERR_HTTP_4XX
    
    @pytest.mark.asyncio
    async def test_http_headers_detection(self, signature_detector, mock_session):
        """Test MCP header detection."""
        # Mock response with MCP headers
        mock_response = {
            'status': 200,
            'headers': {
                'MCP-Version': '1.0.0',
                'X-MCP-Server': 'test-server',
                'Content-Type': 'application/json'
            }
        }
        mock_session.head_request.return_value = (mock_response, ErrorCode.SUCCESS)
        
        mcp_headers, error_code = await signature_detector.check_http_headers('https://example.com')
        
        assert error_code == ErrorCode.SUCCESS
        assert 'MCP-Version' in mcp_headers
        assert 'X-MCP-Server' in mcp_headers
        assert 'Content-Type' not in mcp_headers  # Should not include non-MCP headers
    
    @pytest.mark.asyncio
    async def test_content_signature_scanning(self, signature_detector, mock_session):
        """Test content signature scanning."""
        # Mock HTML content with MCP references
        mock_content = '''
        <html>
        <head>
            <title>MCP Server Documentation</title>
            <meta name="description" content="Model Context Protocol server implementation">
            <meta name="mcp-version" content="1.0">
        </head>
        <body>
            <h1>Model Context Protocol</h1>
            <p>This is an MCP server implementation.</p>
            <a href="/.well-known/mcp/metadata.json">MCP Metadata</a>
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "SoftwareApplication",
                "name": "MCP Server"
            }
            </script>
        </body>
        </html>
        '''
        
        mock_response = {
            'status': 200,
            'content': mock_content,
            'content_length': len(mock_content)
        }
        mock_session.get_request.return_value = (mock_response, ErrorCode.SUCCESS)
        
        signatures, error_code = await signature_detector.scan_content_signatures('https://example.com')
        
        assert error_code == ErrorCode.SUCCESS
        assert signatures['meta_tag_matches'] > 0
        assert signatures['content_pattern_matches'] > 0
        assert signatures['link_references'] > 0
        assert signatures['total_score'] > 0
    
    @pytest.mark.asyncio
    async def test_comprehensive_scan(self, signature_detector, mock_session):
        """Test comprehensive signature scanning."""
        # Mock all components
        mock_session.check_well_known_mcp.return_value = ({
            'version': '1.0.0',
            'name': 'test-server'
        }, ErrorCode.SUCCESS)
        
        mock_session.head_request.return_value = ({
            'status': 200,
            'headers': {'MCP-Version': '1.0.0'}
        }, ErrorCode.SUCCESS)
        
        mock_session.get_request.return_value = ({
            'status': 200,
            'content': '<html><title>MCP Server</title></html>'
        }, ErrorCode.SUCCESS)
        
        with patch.object(signature_detector, 'check_dns_records', return_value=([], ErrorCode.SUCCESS)):
            results, error_code = await signature_detector.comprehensive_scan('https://example.com')
        
        assert error_code == ErrorCode.SUCCESS
        assert results['well_known_found'] is True
        assert len(results['mcp_headers']) > 0
        assert results['total_signature_score'] > 0
    
    def test_validate_mcp_metadata(self, signature_detector):
        """Test MCP metadata validation."""
        # Valid metadata
        valid_metadata = {
            'version': '1.0.0',
            'name': 'test-server',
            'description': 'Test MCP server'
        }
        assert signature_detector._validate_mcp_metadata(valid_metadata) is True
        
        # Invalid metadata - missing required field
        invalid_metadata = {
            'description': 'Test MCP server'
        }
        assert signature_detector._validate_mcp_metadata(invalid_metadata) is False
        
        # Invalid metadata - bad version format
        bad_version_metadata = {
            'version': 'invalid-version',
            'name': 'test-server'
        }
        assert signature_detector._validate_mcp_metadata(bad_version_metadata) is False


@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling in signature detection."""
    # Test with unreachable URL
    session = MCPSession(timeout=1)
    detector = MCPSignatureDetector(session)
    
    async with session:
        # This should handle connection errors gracefully
        results, error_code = await detector.comprehensive_scan('https://nonexistent.invalid')
        
        assert error_code != ErrorCode.SUCCESS
        assert results['total_signature_score'] == 0


if __name__ == '__main__':
    pytest.main([__file__])
