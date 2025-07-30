"""
Main MCP URL detector that orchestrates the 7-stage detection pipeline.
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import logging
import socket

from .session import MCPSession
from .signature import MCPSignatureDetector
from .context_parser import MCPContextParser
from .llm import MCPLLMClassifier
from .decision import MCPDecisionAggregator
from .error_codes import ErrorCode, RetryPolicy, map_exception_to_error_code, ErrorResult

logger = logging.getLogger(__name__)


class MCPDetector:
    """Main detector class that orchestrates the 7-stage detection pipeline."""
    
    def __init__(self, 
                 timeout: int = 5,
                 proxy: Optional[str] = None,
                 ollama_base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 prompt_template_file: Optional[str] = None,
                 enable_llm: bool = True):
        """
        Initialize MCP detector.
        
        Args:
            timeout: Request timeout in seconds
            proxy: HTTP proxy URL
            ollama_base_url: Ollama API base URL
            enable_llm: Whether to enable LLM classification
        """
        self.timeout = timeout
        self.proxy = proxy
        self.enable_llm = enable_llm
        
        # Initialize components
        self.session = MCPSession(timeout=timeout, proxy=proxy)
        self.signature_detector = MCPSignatureDetector(self.session)
        self.context_parser = MCPContextParser()
        self.decision_aggregator = MCPDecisionAggregator()
        
        if enable_llm:
            self.llm_classifier = MCPLLMClassifier(
                base_url=ollama_base_url,
                model=model,
                prompt_template_file=prompt_template_file,
                timeout=min(timeout, 10)
            )
        else:
            self.llm_classifier = None
    
    async def detect(self, url: str) -> Dict[str, Any]:
        """
        Perform complete 7-stage MCP detection pipeline.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            Complete detection results with classification and metadata
        """
        start_time = time.time()
        results = {
            'url': url,
            'pipeline_stages': {},
            'final_classification': {},
            'elapsed_ms': 0,
            'retry_count': 0,
            'error_codes': []
        }
        
        try:
            # Stage 1: Pre-flight checks
            pre_flight_result, error_code = await self._stage_1_pre_flight(url)
            results['pipeline_stages']['pre_flight'] = pre_flight_result
            if error_code != ErrorCode.SUCCESS:
                results['error_codes'].append(error_code)
                if self._is_critical_error(error_code):
                    return self._finalize_results(results, start_time, error_code)
            
            # Stage 2: TLS layer analysis
            tls_result, error_code = await self._stage_2_tls_layer(url)
            results['pipeline_stages']['tls_layer'] = tls_result
            if error_code != ErrorCode.SUCCESS:
                results['error_codes'].append(error_code)
                # Try HTTP fallback for HTTPS failures
                if error_code in [ErrorCode.ERR_TLS_HANDSHAKE, ErrorCode.ERR_TLS_CERT_VERIFY]:
                    http_url = url.replace('https://', 'http://')
                    if http_url != url:
                        logger.info(f"Trying HTTP fallback for {url}")
                        tls_result, error_code = await self._stage_2_tls_layer(http_url)
                        results['pipeline_stages']['tls_layer_fallback'] = tls_result
                        if error_code != ErrorCode.SUCCESS:
                            results['error_codes'].append(error_code)
            
            # Stage 3: Signature scan
            signature_result, error_code = await self._stage_3_signature_scan(url)
            results['pipeline_stages']['signature_scan'] = signature_result
            if error_code != ErrorCode.SUCCESS:
                results['error_codes'].append(error_code)
            
            # Stage 4: Context parsing
            context_result, error_code = await self._stage_4_context_parse(url)
            results['pipeline_stages']['context_parse'] = context_result
            if error_code != ErrorCode.SUCCESS:
                results['error_codes'].append(error_code)
            
            # Stage 5: LLM classification (if enabled)
            llm_result = {}
            if self.enable_llm and self.llm_classifier:
                llm_result, error_code = await self._stage_5_llm_classify(url, context_result)
                results['pipeline_stages']['llm_classify'] = llm_result
                if error_code != ErrorCode.SUCCESS:
                    results['error_codes'].append(error_code)
            
            # Stage 6: Decision aggregation
            decision_result = await self._stage_6_decision_aggregate(
                url, signature_result, context_result, llm_result, results['error_codes']
            )
            results['pipeline_stages']['decision_aggregate'] = decision_result
            results['final_classification'] = decision_result
            
            return self._finalize_results(results, start_time, ErrorCode.SUCCESS)
            
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            logger.error(f"Unexpected error in detection pipeline for {url}: {e}")
            results['error_codes'].append(error_code)
            return self._finalize_results(results, start_time, error_code)
    
    async def _stage_1_pre_flight(self, url: str) -> Tuple[Dict[str, Any], ErrorCode]:
        """Stage 1: DNS lookup and basic connectivity check."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if not hostname:
                return {}, ErrorCode.ERR_DNS_NXDOMAIN
            
            # DNS lookup
            try:
                socket.gethostbyname(hostname)
            except socket.gaierror:
                return {}, ErrorCode.ERR_DNS_NXDOMAIN
            
            # Basic port connectivity check
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result != 0:
                    return {}, ErrorCode.ERR_TCP_REFUSED
                
            except socket.timeout:
                return {}, ErrorCode.ERR_TCP_TIMEOUT
            except Exception:
                return {}, ErrorCode.ERR_TCP_UNREACHABLE
            
            return {
                'hostname': hostname,
                'port': port,
                'dns_resolved': True,
                'port_reachable': True
            }, ErrorCode.SUCCESS
            
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            return {}, error_code
    
    async def _stage_2_tls_layer(self, url: str) -> Tuple[Dict[str, Any], ErrorCode]:
        """Stage 2: TLS/HTTP layer analysis."""
        try:
            response_info, error_code = await self.session.head_request(url)
            
            if error_code == ErrorCode.SUCCESS and response_info:
                return {
                    'status_code': response_info['status'],
                    'headers': response_info['headers'],
                    'redirected': response_info.get('real_url') != response_info.get('url'),
                    'final_url': response_info.get('real_url', response_info.get('url'))
                }, ErrorCode.SUCCESS
            else:
                return {}, error_code
                
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            return {}, error_code
    
    async def _stage_3_signature_scan(self, url: str) -> Tuple[Dict[str, Any], ErrorCode]:
        """Stage 3: MCP signature scanning."""
        try:
            signature_results, error_code = await self.signature_detector.comprehensive_scan(url)
            return signature_results, error_code
                
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            return {}, error_code
    
    async def _stage_4_context_parse(self, url: str) -> Tuple[Dict[str, Any], ErrorCode]:
        """Stage 4: Context parsing from content and certificates."""
        context_results = {}
        final_error = ErrorCode.SUCCESS
        
        try:
            # Get page content for parsing
            response_data, error_code = await self.session.get_request(url)
            
            if error_code == ErrorCode.SUCCESS and response_data:
                content = response_data.get('content', '')
                
                # Parse HTML content
                html_context = await self.context_parser.parse_html_content(content)
                context_results.update(html_context)
                
                # Extract category hints
                category_hints = self.context_parser.determine_url_category_hints(url, content)
                context_results['category_hints'] = category_hints
                
                # Store content for LLM analysis
                context_results['raw_content'] = {
                    'content': content[:2000],  # Limit size
                    'title': self._extract_title(content),
                    'description': self._extract_description(content)
                }
            else:
                final_error = error_code
            
            # Analyze TLS certificate (for HTTPS URLs)
            if url.startswith('https://'):
                parsed = urlparse(url)
                if parsed.hostname:
                    cert_info, cert_error = await self.context_parser.analyze_tls_certificate(
                        parsed.hostname, parsed.port or 443
                    )
                    if cert_error == ErrorCode.SUCCESS:
                        context_results['certificate_info'] = cert_info
                    else:
                        if final_error == ErrorCode.SUCCESS:
                            final_error = cert_error
            
            return context_results, final_error
                
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            return context_results, error_code
    
    async def _stage_5_llm_classify(self, url: str, context_data: Dict[str, Any]) -> Tuple[Dict[str, Any], ErrorCode]:
        """Stage 5: LLM-based classification."""
        if not self.llm_classifier:
            return {}, ErrorCode.ERR_LLM_UNAVAILABLE
        
        try:
            # Prepare content data for LLM
            raw_content = context_data.get('raw_content', {})
            
            llm_result, error_code = await self.llm_classifier.classify_with_retry(
                url, raw_content, max_retries=1
            )
            
            return llm_result, error_code
            
        except Exception as e:
            error_code = map_exception_to_error_code(e)
            return {}, error_code
    
    async def _stage_6_decision_aggregate(self, 
                                        url: str,
                                        signature_results: Dict[str, Any],
                                        context_results: Dict[str, Any],
                                        llm_results: Dict[str, Any],
                                        error_codes: List[ErrorCode]) -> Dict[str, Any]:
        """Stage 6: Aggregate all results into final decision."""
        try:
            decision = self.decision_aggregator.aggregate_decision(
                url, signature_results, context_results, llm_results, error_codes
            )
            return decision
            
        except Exception as e:
            logger.error(f"Error in decision aggregation: {e}")
            return {
                'url': url,
                'final_label': 'unknown',
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _extract_title(self, content: str) -> str:
        """Extract title from HTML content."""
        import re
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()[:200]  # Limit length
        return ""
    
    def _extract_description(self, content: str) -> str:
        """Extract description from HTML meta tags."""
        import re
        desc_match = re.search(
            r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']',
            content, re.IGNORECASE
        )
        if desc_match:
            return desc_match.group(1).strip()[:300]  # Limit length
        return ""
    
    def _is_critical_error(self, error_code: ErrorCode) -> bool:
        """Check if error is critical enough to stop pipeline."""
        critical_errors = [
            ErrorCode.ERR_DNS_NXDOMAIN,
            ErrorCode.ERR_TCP_REFUSED,
            ErrorCode.ERR_TCP_UNREACHABLE
        ]
        return error_code in critical_errors
    
    def _finalize_results(self, results: Dict[str, Any], start_time: float, final_error: ErrorCode) -> Dict[str, Any]:
        """Finalize results with timing and error information."""
        elapsed_ms = int((time.time() - start_time) * 1000)
        results['elapsed_ms'] = elapsed_ms
        
        # Ensure we have a final classification
        if 'final_classification' not in results or not results['final_classification']:
            results['final_classification'] = {
                'url': results['url'],
                'final_label': 'unknown',
                'confidence': 0.0,
                'total_score': 0,
                'reasoning': ['Pipeline failed due to errors'],
                'error_codes': [ec.value for ec in results.get('error_codes', [])],
                'metadata': {}
            }
        
        # Add final error if not already present
        if final_error != ErrorCode.SUCCESS and final_error not in results.get('error_codes', []):
            results['error_codes'].append(final_error)
            results['final_classification']['error_codes'] = [ec.value for ec in results['error_codes']]
        
        return results
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass
