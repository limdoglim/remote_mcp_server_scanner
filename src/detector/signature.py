"""
MCP signature detection and URL pattern analysis.
"""

import re
import asyncio
import dns.resolver
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
import logging

from .session import MCPSession
from .error_codes import ErrorCode

logger = logging.getLogger(__name__)


class MCPSignatureDetector:
    """Detects MCP-specific signatures and patterns in URLs and content."""
    
    # Known MCP server path patterns
    MCP_SERVER_PATTERNS = [
        r'/\.well-known/mcp/',
        r'/mcp/',
        r'/api/mcp',
        r'/server/mcp',
        r'/_mcp',
        r'/context',
        r'/tools',
        r'/resources'
    ]
    
    # MCP registry patterns
    MCP_REGISTRY_PATTERNS = [
        r'/registry',
        r'/servers',
        r'/directory',
        r'/catalog',
        r'/marketplace'
    ]
    
    # MCP introduction/documentation patterns
    MCP_INTRO_PATTERNS = [
        r'/docs?/mcp',
        r'/guide/mcp',
        r'/tutorial/mcp',
        r'/getting-started',
        r'/introduction',
        r'/overview'
    ]
    
    # Known MCP-related headers
    MCP_HEADERS = [
        'mcp-version',
        'x-mcp-version',
        'mcp-server',
        'x-mcp-server',
        'model-context-protocol'
    ]
    
    # HTML meta tags and content patterns
    MCP_META_PATTERNS = [
        r'model\s+context\s+protocol',
        r'mcp\s+server',
        r'mcp\s+client',
        r'\.well-known/mcp',
        r'modelcontextprotocol',
        r'@modelcontextprotocol'
    ]
    
    def __init__(self, session: MCPSession):
        self.session = session
        self._dns_resolver = dns.resolver.Resolver()
        self._dns_resolver.timeout = 2
        self._dns_resolver.lifetime = 5
    
    async def scan_url_patterns(self, url: str) -> Dict[str, int]:
        """
        Scan URL for MCP-related patterns.
        
        Returns:
            Dict with pattern match scores
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        fragment = parsed.fragment.lower()
        
        full_url = f"{path}?{query}#{fragment}".lower()
        
        scores = {
            'server_patterns': 0,
            'registry_patterns': 0,
            'intro_patterns': 0,
            'total_matches': 0
        }
        
        # Check server patterns
        for pattern in self.MCP_SERVER_PATTERNS:
            if re.search(pattern, full_url):
                scores['server_patterns'] += 1
                scores['total_matches'] += 1
        
        # Check registry patterns
        for pattern in self.MCP_REGISTRY_PATTERNS:
            if re.search(pattern, full_url):
                scores['registry_patterns'] += 1
                scores['total_matches'] += 1
        
        # Check intro patterns
        for pattern in self.MCP_INTRO_PATTERNS:
            if re.search(pattern, full_url):
                scores['intro_patterns'] += 1
                scores['total_matches'] += 1
        
        return scores
    
    async def check_well_known_endpoint(self, url: str) -> Tuple[bool, Dict, ErrorCode]:
        """
        Check for MCP well-known metadata endpoint.
        
        Returns:
            Tuple of (found, metadata, error_code)
        """
        metadata, error_code = await self.session.check_well_known_mcp(url)
        
        if error_code != ErrorCode.SUCCESS:
            return False, {}, error_code
        
        if metadata:
            # Validate MCP metadata structure
            is_valid = self._validate_mcp_metadata(metadata)
            return is_valid, metadata, ErrorCode.SUCCESS
        
        return False, {}, ErrorCode.SUCCESS
    
    def _validate_mcp_metadata(self, metadata: Dict) -> bool:
        """Validate that metadata follows MCP specification."""
        required_fields = ['version', 'name']
        optional_fields = ['description', 'author', 'license', 'repository']
        
        # Check required fields
        for field in required_fields:
            if field not in metadata:
                return False
        
        # Check version format
        version = metadata.get('version', '')
        if not re.match(r'^\d+\.\d+(\.\d+)?', version):
            return False
        
        return True
    
    async def check_http_headers(self, url: str) -> Tuple[Dict[str, str], ErrorCode]:
        """
        Check HTTP headers for MCP-related information.
        
        Returns:
            Tuple of (mcp_headers, error_code)
        """
        response_info, error_code = await self.session.head_request(url)
        
        if error_code != ErrorCode.SUCCESS:
            return {}, error_code
        
        mcp_headers = {}
        headers = response_info.get('headers', {})
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if any(mcp_header in header_lower for mcp_header in self.MCP_HEADERS):
                mcp_headers[header_name] = header_value
        
        return mcp_headers, ErrorCode.SUCCESS
    
    async def check_dns_records(self, url: str) -> Tuple[List[str], ErrorCode]:
        """
        Check DNS TXT records for MCP service discovery.
        
        Returns:
            Tuple of (mcp_records, error_code)
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                return [], ErrorCode.ERR_DNS_NXDOMAIN
            
            # Check for _mcp._tcp TXT records
            mcp_records = []
            try:
                records = self._dns_resolver.resolve(f"_mcp._tcp.{hostname}", 'TXT')
                for record in records:
                    txt_data = record.to_text().strip('"')
                    if 'mcp' in txt_data.lower():
                        mcp_records.append(txt_data)
            except Exception:
                pass  # TXT records are optional
            
            return mcp_records, ErrorCode.SUCCESS
            
        except Exception as e:
            from .error_codes import map_exception_to_error_code
            error_code = map_exception_to_error_code(e)
            return [], error_code
    
    async def scan_content_signatures(self, url: str) -> Tuple[Dict[str, int], ErrorCode]:
        """
        Scan page content for MCP-related signatures.
        
        Returns:
            Tuple of (signature_scores, error_code)
        """
        response_data, error_code = await self.session.get_request(url, max_size=512*1024)  # 512KB limit
        
        if error_code != ErrorCode.SUCCESS:
            return {}, error_code
        
        content = response_data.get('content', '').lower()
        
        scores = {
            'meta_tag_matches': 0,
            'content_pattern_matches': 0,
            'link_references': 0,
            'json_ld_matches': 0,
            'total_score': 0
        }
        
        # Check meta tags
        meta_patterns = [
            r'<meta[^>]*name=["\']mcp[^>]*>',
            r'<meta[^>]*property=["\']mcp[^>]*>',
            r'<meta[^>]*content=["\'][^"\']*mcp[^"\']*["\'][^>]*>'
        ]
        
        for pattern in meta_patterns:
            matches = re.findall(pattern, content)
            scores['meta_tag_matches'] += len(matches)
        
        # Check content patterns
        for pattern in self.MCP_META_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            scores['content_pattern_matches'] += len(matches)
        
        # Check for MCP-related links
        link_patterns = [
            r'href=["\'][^"\']*mcp[^"\']*["\']',
            r'href=["\'][^"\']*\.well-known/mcp[^"\']*["\']',
            r'href=["\'][^"\']*modelcontextprotocol[^"\']*["\']'
        ]
        
        for pattern in link_patterns:
            matches = re.findall(pattern, content)
            scores['link_references'] += len(matches)
        
        # Check JSON-LD structured data
        json_ld_pattern = r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>'
        json_matches = re.findall(json_ld_pattern, content, re.DOTALL)
        
        for json_content in json_matches:
            if 'mcp' in json_content.lower() or 'modelcontextprotocol' in json_content.lower():
                scores['json_ld_matches'] += 1
        
        # Calculate total score
        scores['total_score'] = (
            scores['meta_tag_matches'] * 3 +
            scores['content_pattern_matches'] * 2 +
            scores['link_references'] * 1 +
            scores['json_ld_matches'] * 4
        )
        
        return scores, ErrorCode.SUCCESS
    
    async def comprehensive_scan(self, url: str) -> Tuple[Dict[str, any], ErrorCode]:
        """
        Perform comprehensive MCP signature scanning.
        
        Returns:
            Tuple of (scan_results, final_error_code)
        """
        results = {
            'url': url,
            'url_patterns': {},
            'well_known_found': False,
            'well_known_metadata': {},
            'mcp_headers': {},
            'dns_records': [],
            'content_signatures': {},
            'total_signature_score': 0
        }
        
        errors = []
        
        # URL pattern analysis (always works)
        results['url_patterns'] = await self.scan_url_patterns(url)
        
        # Well-known endpoint check
        well_known_found, metadata, error_code = await self.check_well_known_endpoint(url)
        results['well_known_found'] = well_known_found
        results['well_known_metadata'] = metadata
        if error_code != ErrorCode.SUCCESS:
            errors.append(error_code)
        
        # HTTP headers check
        mcp_headers, error_code = await self.check_http_headers(url)
        results['mcp_headers'] = mcp_headers
        if error_code != ErrorCode.SUCCESS:
            errors.append(error_code)
        
        # DNS records check
        dns_records, error_code = await self.check_dns_records(url)
        results['dns_records'] = dns_records
        if error_code != ErrorCode.SUCCESS:
            errors.append(error_code)
        
        # Content signatures
        content_signatures, error_code = await self.scan_content_signatures(url)
        results['content_signatures'] = content_signatures
        if error_code != ErrorCode.SUCCESS:
            errors.append(error_code)
        
        # Calculate total signature score
        score = 0
        if well_known_found:
            score += 10  # Strong indicator
        score += len(mcp_headers) * 3
        score += len(dns_records) * 2
        score += results['url_patterns']['total_matches'] * 2
        score += content_signatures.get('total_score', 0)
        
        results['total_signature_score'] = score
        
        # Return the most relevant error code or success
        final_error = errors[-1] if errors else ErrorCode.SUCCESS
        
        return results, final_error
