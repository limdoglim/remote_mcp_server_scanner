"""
Decision aggregation for MCP URL classification.
"""

from typing import Dict, List, Optional, Tuple, Any
import logging

from .error_codes import ErrorCode

logger = logging.getLogger(__name__)


class MCPDecisionAggregator:
    """Aggregates multiple signals to make final URL classification decision."""
    
    # Scoring weights for different detection methods
    SCORING_WEIGHTS = {
        'well_known_found': 10,      # Strong MCP server indicator
        'mcp_headers': 5,            # HTTP headers with MCP info
        'dns_records': 3,            # DNS TXT records
        'url_patterns': 2,           # URL path patterns
        'content_signatures': 1,     # Content-based signatures
        'certificate_mcp': 3,        # TLS certificate references
        'html_context': 2,           # HTML meta tags and content
        'llm_classification': 3      # LLM-based classification
    }
    
    # Minimum scores for classification
    CLASSIFICATION_THRESHOLDS = {
        'mcp_server': 8,
        'mcp_intro': 5,
        'mcp_registry': 5,
        'unknown': 0
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def aggregate_decision(self, 
                          url: str,
                          signature_results: Dict[str, Any],
                          context_results: Dict[str, Any],
                          llm_results: Dict[str, Any],
                          error_codes: List[ErrorCode]) -> Dict[str, Any]:
        """
        Aggregate all detection results into a final classification decision.
        
        Args:
            url: Target URL
            signature_results: Results from signature detection
            context_results: Results from context parsing
            llm_results: Results from LLM classification
            error_codes: List of error codes encountered
            
        Returns:
            Final classification decision with confidence and reasoning
        """
        decision = {
            'url': url,
            'final_label': 'unknown',
            'confidence': 0.0,
            'scores': self._calculate_component_scores(
                signature_results, context_results, llm_results
            ),
            'total_score': 0,
            'reasoning': [],
            'error_codes': [ec.value for ec in error_codes],
            'metadata': {
                'signature_score': signature_results.get('total_signature_score', 0),
                'context_score': context_results.get('total_context_score', 0),
                'llm_confidence': llm_results.get('confidence', 0.0),
                'llm_category': llm_results.get('category', 'unknown')
            }
        }
        
        # Calculate total score
        total_score = sum(decision['scores'].values())
        decision['total_score'] = total_score
        
        # Determine final classification
        final_label, confidence = self._determine_final_classification(
            decision['scores'], llm_results, total_score
        )
        
        decision['final_label'] = final_label
        decision['confidence'] = confidence
        
        # Generate reasoning
        decision['reasoning'] = self._generate_reasoning(
            decision['scores'], llm_results, error_codes
        )
        
        return decision
    
    def _calculate_component_scores(self, 
                                  signature_results: Dict[str, Any],
                                  context_results: Dict[str, Any],
                                  llm_results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate weighted scores for each detection component."""
        scores = {}
        
        # Well-known endpoint score
        if signature_results.get('well_known_found', False):
            scores['well_known'] = self.SCORING_WEIGHTS['well_known_found']
        else:
            scores['well_known'] = 0
        
        # HTTP headers score
        mcp_headers = signature_results.get('mcp_headers', {})
        scores['headers'] = len(mcp_headers) * self.SCORING_WEIGHTS['mcp_headers']
        
        # DNS records score
        dns_records = signature_results.get('dns_records', [])
        scores['dns'] = len(dns_records) * self.SCORING_WEIGHTS['dns_records']
        
        # URL patterns score
        url_patterns = signature_results.get('url_patterns', {})
        pattern_score = url_patterns.get('total_matches', 0) * self.SCORING_WEIGHTS['url_patterns']
        scores['url_patterns'] = pattern_score
        
        # Content signatures score
        content_sigs = signature_results.get('content_signatures', {})
        content_score = content_sigs.get('total_score', 0) * self.SCORING_WEIGHTS['content_signatures']
        scores['content_signatures'] = content_score
        
        # Certificate score
        cert_score = 0
        if 'certificate_info' in context_results:
            cert_info = context_results['certificate_info']
            mcp_indicators = cert_info.get('mcp_indicators', {})
            cert_score = mcp_indicators.get('score', 0) * self.SCORING_WEIGHTS['certificate_mcp']
        scores['certificate'] = cert_score
        
        # HTML context score
        html_indicators = context_results.get('html_indicators', {})
        html_score = html_indicators.get('total_score', 0) * self.SCORING_WEIGHTS['html_context']
        scores['html_context'] = html_score
        
        # LLM classification score
        llm_confidence = llm_results.get('confidence', 0.0)
        llm_score = llm_confidence * self.SCORING_WEIGHTS['llm_classification']
        scores['llm'] = llm_score
        
        return scores
    
    def _determine_final_classification(self, 
                                      scores: Dict[str, float],
                                      llm_results: Dict[str, Any],
                                      total_score: float) -> Tuple[str, float]:
        """Determine final classification and confidence."""
        
        # Get LLM classification as a starting point
        llm_category = llm_results.get('category', 'unknown')
        llm_confidence = llm_results.get('confidence', 0.0)
        
        # If we have strong signature-based evidence, it takes precedence
        if scores.get('well_known', 0) > 0:
            # Strong MCP server evidence
            return 'mcp_server', min(0.95, 0.7 + llm_confidence * 0.25)
        
        # Check if total score meets thresholds for different categories
        classification_scores = {
            'mcp_server': self._calculate_category_score(scores, 'mcp_server'),
            'mcp_intro': self._calculate_category_score(scores, 'mcp_intro'),
            'mcp_registry': self._calculate_category_score(scores, 'mcp_registry')
        }
        
        # Find highest scoring category that meets threshold
        best_category = 'unknown'
        best_score = 0
        
        for category, score in classification_scores.items():
            threshold = self.CLASSIFICATION_THRESHOLDS[category]
            if score >= threshold and score > best_score:
                best_category = category
                best_score = score
        
        # If LLM agrees with best category, boost confidence
        if llm_category == best_category and llm_confidence > 0.5:
            confidence = min(0.9, 0.6 + llm_confidence * 0.3)
        elif best_category != 'unknown':
            # Moderate confidence based on signature strength
            confidence = min(0.8, 0.4 + (best_score / 20))
        else:
            # Low confidence for unknown
            confidence = max(0.1, llm_confidence * 0.5)
        
        return best_category, confidence
    
    def _calculate_category_score(self, scores: Dict[str, float], category: str) -> float:
        """Calculate score for a specific category based on evidence weights."""
        
        if category == 'mcp_server':
            # Server indicators: well-known, headers, DNS, certificates
            return (scores.get('well_known', 0) + 
                   scores.get('headers', 0) + 
                   scores.get('dns', 0) + 
                   scores.get('certificate', 0) +
                   scores.get('url_patterns', 0) * 0.5)
        
        elif category == 'mcp_intro':
            # Documentation indicators: content, HTML context, URL patterns
            return (scores.get('content_signatures', 0) + 
                   scores.get('html_context', 0) + 
                   scores.get('url_patterns', 0) +
                   scores.get('llm', 0))
        
        elif category == 'mcp_registry':
            # Registry indicators: URL patterns, content, HTML context
            return (scores.get('url_patterns', 0) + 
                   scores.get('content_signatures', 0) + 
                   scores.get('html_context', 0) +
                   scores.get('llm', 0) * 0.8)
        
        return 0
    
    def _generate_reasoning(self, 
                          scores: Dict[str, float],
                          llm_results: Dict[str, Any],
                          error_codes: List[ErrorCode]) -> List[str]:
        """Generate human-readable reasoning for the classification."""
        reasoning = []
        
        # Strong positive indicators
        if scores.get('well_known', 0) > 0:
            reasoning.append("Found MCP well-known metadata endpoint")
        
        if scores.get('headers', 0) > 0:
            reasoning.append("MCP-related HTTP headers detected")
        
        if scores.get('dns', 0) > 0:
            reasoning.append("MCP DNS service records found")
        
        if scores.get('certificate', 0) > 0:
            reasoning.append("TLS certificate contains MCP references")
        
        # Content-based indicators
        if scores.get('content_signatures', 0) > 2:
            reasoning.append("Strong MCP content signatures detected")
        elif scores.get('content_signatures', 0) > 0:
            reasoning.append("Some MCP content signatures detected")
        
        if scores.get('html_context', 0) > 2:
            reasoning.append("HTML contains MCP-related metadata")
        
        if scores.get('url_patterns', 0) > 0:
            reasoning.append("URL patterns suggest MCP relevance")
        
        # LLM analysis
        llm_category = llm_results.get('category', 'unknown')
        llm_confidence = llm_results.get('confidence', 0.0)
        llm_reasoning = llm_results.get('reasoning', '')
        
        if llm_confidence > 0.7:
            reasoning.append(f"LLM analysis strongly suggests: {llm_category}")
        elif llm_confidence > 0.4:
            reasoning.append(f"LLM analysis suggests: {llm_category}")
        
        if llm_reasoning:
            reasoning.append(f"LLM reasoning: {llm_reasoning}")
        
        # Error conditions
        critical_errors = [
            ErrorCode.ERR_DNS_NXDOMAIN,
            ErrorCode.ERR_TCP_REFUSED,
            ErrorCode.ERR_HTTP_4XX,
            ErrorCode.ERR_HTTP_5XX
        ]
        
        if any(ec in error_codes for ec in critical_errors):
            reasoning.append("Limited analysis due to connectivity issues")
        
        if ErrorCode.ERR_LLM_TIMEOUT in error_codes:
            reasoning.append("LLM analysis timed out")
        
        if ErrorCode.ERR_LLM_UNAVAILABLE in error_codes:
            reasoning.append("LLM analysis unavailable")
        
        # Default if no reasoning found
        if not reasoning:
            reasoning.append("Insufficient evidence for classification")
        
        return reasoning
    
    def validate_decision(self, decision: Dict[str, Any]) -> bool:
        """Validate that decision contains all required fields."""
        required_fields = [
            'url', 'final_label', 'confidence', 'scores', 
            'total_score', 'reasoning', 'error_codes', 'metadata'
        ]
        
        for field in required_fields:
            if field not in decision:
                self.logger.error(f"Missing required field '{field}' in decision")
                return False
        
        # Validate confidence range
        confidence = decision.get('confidence', 0)
        if not 0.0 <= confidence <= 1.0:
            self.logger.error(f"Invalid confidence value: {confidence}")
            return False
        
        # Validate label
        valid_labels = ['mcp_server', 'mcp_intro', 'mcp_registry', 'unknown']
        if decision.get('final_label') not in valid_labels:
            self.logger.error(f"Invalid label: {decision.get('final_label')}")
            return False
        
        return True
