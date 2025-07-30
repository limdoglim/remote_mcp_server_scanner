"""
Context parsing for HTML content and TLS certificate analysis.
"""

import re
import ssl
import socket
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import logging
from html.parser import HTMLParser

from .error_codes import ErrorCode

logger = logging.getLogger(__name__)


class MCPHTMLParser(HTMLParser):
    """Custom HTML parser to extract MCP-related information."""
    
    def __init__(self):
        super().__init__()
        self.meta_tags = []
        self.link_tags = []
        self.script_tags = []
        self.title = ""
        self.description = ""
        self.current_tag = None
        self.current_attrs = {}
    
    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        """Handle start tags and extract relevant information."""
        self.current_tag = tag
        self.current_attrs = dict(attrs)
        
        if tag == 'meta':
            self.meta_tags.append(dict(attrs))
        elif tag == 'link':
            self.link_tags.append(dict(attrs))
        elif tag == 'script':
            self.script_tags.append(dict(attrs))
    
    def handle_data(self, data: str):
        """Handle text data within tags."""
        if self.current_tag == 'title':
            self.title += data.strip()
        elif (self.current_tag == 'meta' and 
              self.current_attrs.get('name') == 'description'):
            self.description += data.strip()
    
    def get_mcp_indicators(self) -> Dict[str, Any]:
        """Extract MCP-related indicators from parsed HTML."""
        indicators = {
            'meta_mcp': [],
            'link_mcp': [],
            'script_mcp': [],
            'title_mcp': False,
            'description_mcp': False,
            'total_score': 0
        }
        
        # Check meta tags
        for meta in self.meta_tags:
            content = meta.get('content', '').lower()
            name = meta.get('name', '').lower()
            property_val = meta.get('property', '').lower()
            
            if any(term in content + name + property_val for term in [
                'mcp', 'model context protocol', 'modelcontextprotocol'
            ]):
                indicators['meta_mcp'].append(meta)
                indicators['total_score'] += 3
        
        # Check link tags
        for link in self.link_tags:
            href = link.get('href', '').lower()
            rel = link.get('rel', '').lower()
            
            if any(term in href + rel for term in [
                'mcp', 'well-known/mcp', 'modelcontextprotocol'
            ]):
                indicators['link_mcp'].append(link)
                indicators['total_score'] += 2
        
        # Check script tags
        for script in self.script_tags:
            src = script.get('src', '').lower()
            if any(term in src for term in [
                'mcp', 'modelcontextprotocol'
            ]):
                indicators['script_mcp'].append(script)
                indicators['total_score'] += 1
        
        # Check title and description
        title_lower = self.title.lower()
        desc_lower = self.description.lower()
        
        if any(term in title_lower for term in [
            'mcp', 'model context protocol', 'modelcontextprotocol'
        ]):
            indicators['title_mcp'] = True
            indicators['total_score'] += 4
        
        if any(term in desc_lower for term in [
            'mcp', 'model context protocol', 'modelcontextprotocol'
        ]):
            indicators['description_mcp'] = True
            indicators['total_score'] += 3
        
        return indicators


class MCPContextParser:
    """Parse and analyze context from web content and certificates."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def parse_html_content(self, content: str) -> Dict[str, Any]:
        """
        Parse HTML content for MCP-related context.
        
        Args:
            content: HTML content string
            
        Returns:
            Dict with parsed context information
        """
        try:
            parser = MCPHTMLParser()
            parser.feed(content)
            
            indicators = parser.get_mcp_indicators()
            
            # Additional pattern matching
            additional_patterns = self._extract_additional_patterns(content)
            
            return {
                'html_indicators': indicators,
                'additional_patterns': additional_patterns,
                'total_context_score': indicators['total_score'] + additional_patterns['score']
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing HTML content: {e}")
            return {
                'html_indicators': {'total_score': 0},
                'additional_patterns': {'score': 0},
                'total_context_score': 0
            }
    
    def _extract_additional_patterns(self, content: str) -> Dict[str, Any]:
        """Extract additional MCP-related patterns from content."""
        patterns = {
            'api_endpoints': [],
            'config_snippets': [],
            'code_examples': [],
            'score': 0
        }
        
        content_lower = content.lower()
        
        # API endpoint patterns
        api_patterns = [
            r'/api/v\d+/mcp',
            r'/mcp/v\d+',
            r'\.well-known/mcp',
            r'/context/',
            r'/tools/',
            r'/resources/'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content_lower)
            patterns['api_endpoints'].extend(matches)
            patterns['score'] += len(matches) * 2
        
        # Configuration snippets
        config_patterns = [
            r'"mcp[_-]?server"',
            r'"modelcontextprotocol"',
            r'mcp[_-]?config',
            r'mcp[_-]?client'
        ]
        
        for pattern in config_patterns:
            matches = re.findall(pattern, content_lower)
            patterns['config_snippets'].extend(matches)
            patterns['score'] += len(matches) * 1
        
        # Code examples with MCP
        code_patterns = [
            r'import.*mcp',
            r'from.*mcp.*import',
            r'class.*mcp.*server',
            r'def.*mcp.*'
        ]
        
        for pattern in code_patterns:
            matches = re.findall(pattern, content_lower)
            patterns['code_examples'].extend(matches)
            patterns['score'] += len(matches) * 3
        
        return patterns
    
    async def analyze_tls_certificate(self, hostname: str, port: int = 443) -> Tuple[Dict[str, Any], ErrorCode]:
        """
        Analyze TLS certificate for MCP-related information.
        
        Args:
            hostname: Target hostname
            port: Target port (default 443)
            
        Returns:
            Tuple of (certificate_info, error_code)
        """
        try:
            # Create SSL context that doesn't verify certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            
            if not cert:
                return {}, ErrorCode.ERR_TLS_CERT_VERIFY
            
            cert_info = self._analyze_certificate_content(cert)
            return cert_info, ErrorCode.SUCCESS
            
        except socket.timeout:
            return {}, ErrorCode.ERR_TCP_TIMEOUT
        except ConnectionRefusedError:
            return {}, ErrorCode.ERR_TCP_REFUSED
        except ssl.SSLError as e:
            if 'handshake failure' in str(e).lower():
                return {}, ErrorCode.ERR_TLS_HANDSHAKE
            else:
                return {}, ErrorCode.ERR_TLS_PROTOCOL
        except Exception as e:
            from .error_codes import map_exception_to_error_code
            error_code = map_exception_to_error_code(e)
            return {}, error_code
    
    def _analyze_certificate_content(self, cert: Dict) -> Dict[str, Any]:
        """Analyze certificate content for MCP-related information."""
        cert_analysis = {
            'subject': cert.get('subject', []),
            'issuer': cert.get('issuer', []),
            'sans': cert.get('subjectAltName', []),
            'mcp_indicators': {
                'ou_contains_mcp': False,
                'cn_contains_mcp': False,
                'san_contains_mcp': False,
                'score': 0
            }
        }
        
        # Check subject for MCP references
        subject_str = str(cert_analysis['subject']).lower()
        if 'mcp' in subject_str or 'modelcontextprotocol' in subject_str:
            cert_analysis['mcp_indicators']['ou_contains_mcp'] = True
            cert_analysis['mcp_indicators']['score'] += 2
        
        # Check common name
        for item in cert_analysis['subject']:
            for field, value in item:
                if field == 'commonName' and value:
                    if 'mcp' in value.lower() or 'modelcontextprotocol' in value.lower():
                        cert_analysis['mcp_indicators']['cn_contains_mcp'] = True
                        cert_analysis['mcp_indicators']['score'] += 3
        
        # Check Subject Alternative Names
        for san_type, san_value in cert_analysis['sans']:
            if san_value and ('mcp' in san_value.lower() or 
                            'modelcontextprotocol' in san_value.lower()):
                cert_analysis['mcp_indicators']['san_contains_mcp'] = True
                cert_analysis['mcp_indicators']['score'] += 2
        
        return cert_analysis
    
    def determine_url_category_hints(self, url: str, content: str) -> Dict[str, float]:
        """
        Analyze URL and content to provide category hints.
        
        Args:
            url: Target URL
            content: Page content
            
        Returns:
            Dict with category probability hints
        """
        hints = {
            'mcp_server': 0.0,
            'mcp_intro': 0.0,
            'mcp_registry': 0.0,
            'unknown': 0.0
        }
        
        url_lower = url.lower()
        content_lower = content.lower()
        
        # Server indicators
        server_indicators = [
            ('/.well-known/mcp', 0.8),
            ('/api/mcp', 0.6),
            ('/server', 0.3),
            ('github.com', 0.2)  # Many MCP servers on GitHub
        ]
        
        for indicator, weight in server_indicators:
            if indicator in url_lower:
                hints['mcp_server'] += weight
        
        # Check for actual server implementation patterns in content
        server_content_patterns = [
            ('class.*server.*mcp', 0.7),
            ('mcp.*server.*implementation', 0.6),
            ('async def.*mcp', 0.4),
            ('tools.*list', 0.3),
            ('resources.*list', 0.3)
        ]
        
        for pattern, weight in server_content_patterns:
            if re.search(pattern, content_lower):
                hints['mcp_server'] += weight
        
        # Introduction/documentation indicators
        intro_indicators = [
            ('/docs', 0.5),
            ('/guide', 0.5),
            ('/tutorial', 0.6),
            ('/getting-started', 0.7),
            ('/introduction', 0.8),
            ('/overview', 0.6)
        ]
        
        for indicator, weight in intro_indicators:
            if indicator in url_lower:
                hints['mcp_intro'] += weight
        
        # Check for documentation content patterns
        intro_content_patterns = [
            ('getting started', 0.6),
            ('introduction to mcp', 0.8),
            ('model context protocol.*guide', 0.7),
            ('what is mcp', 0.8),
            ('how to.*mcp', 0.5)
        ]
        
        for pattern, weight in intro_content_patterns:
            if re.search(pattern, content_lower):
                hints['mcp_intro'] += weight
        
        # Registry indicators
        registry_indicators = [
            ('/registry', 0.8),
            ('/servers', 0.6),
            ('/directory', 0.6),
            ('/catalog', 0.5),
            ('/marketplace', 0.7)
        ]
        
        for indicator, weight in registry_indicators:
            if indicator in url_lower:
                hints['mcp_registry'] += weight
        
        # Check for registry content patterns
        registry_content_patterns = [
            ('list.*servers', 0.6),
            ('available.*mcp.*servers', 0.8),
            ('server.*directory', 0.7),
            ('browse.*servers', 0.6)
        ]
        
        for pattern, weight in registry_content_patterns:
            if re.search(pattern, content_lower):
                hints['mcp_registry'] += weight
        
        # Normalize probabilities
        total = sum(hints.values())
        if total > 0:
            for key in hints:
                hints[key] = min(hints[key] / total, 1.0)
        else:
            hints['unknown'] = 1.0
        
        return hints
