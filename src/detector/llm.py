"""
LLM integration for MCP URL classification using Ollama API.
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, Optional, Tuple, Any
import logging
import os

from .error_codes import ErrorCode

logger = logging.getLogger(__name__)


class MCPLLMClassifier:
    """LLM-based classifier using Ollama API for MCP URL categorization."""
    
    def __init__(self, 
                 base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 timeout: int = 10,
                 prompt_template_file: Optional[str] = None):
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.3")
        self.timeout = timeout
        
        # Load custom prompt template if provided
        self.classification_prompt = self._load_prompt_template(
            prompt_template_file or os.getenv("PROMPT_TEMPLATE_FILE")
        )
    
    def _load_prompt_template(self, template_file: Optional[str]) -> str:
        """Load prompt template from file or use default."""
        default_prompt = """
You are an expert at analyzing web content to classify URLs related to Model Context Protocol (MCP).

Analyze the following content and classify it into one of these categories:
1. mcp_server - Actual MCP server implementations (code repositories, running servers)
2. mcp_intro - Documentation, tutorials, or introduction pages about MCP
3. mcp_registry - Directories or registries listing MCP servers
4. unknown - Content not related to MCP or unclear classification

Content to analyze:
URL: {url}
Title: {title}
Description: {description}
Content snippet: {content_snippet}

Respond with ONLY a JSON object in this exact format:
{{"category": "mcp_server|mcp_intro|mcp_registry|unknown", "confidence": 0.0-1.0, "reasoning": "brief explanation"}}
"""
        
        if template_file:
            try:
                import os
                # Support both absolute and relative paths
                if not os.path.isabs(template_file):
                    # Relative to project root
                    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                    template_file = os.path.join(project_root, template_file)
                
                with open(template_file, 'r', encoding='utf-8') as f:
                    custom_prompt = f.read().strip()
                    if custom_prompt:
                        logger.info(f"Loaded custom prompt template from {template_file}")
                        return custom_prompt
                    else:
                        logger.warning(f"Custom prompt template file {template_file} is empty, using default")
            except FileNotFoundError:
                logger.warning(f"Custom prompt template file {template_file} not found, using default")
            except Exception as e:
                logger.warning(f"Error loading custom prompt template: {e}, using default")
        
        return default_prompt
    
    async def classify_url(self, 
                          url: str, 
                          content_data: Dict[str, Any]) -> Tuple[Dict[str, Any], ErrorCode]:
        """
        Classify URL using LLM analysis.
        
        Args:
            url: Target URL
            content_data: Parsed content data including title, description, content
            
        Returns:
            Tuple of (classification_result, error_code)
        """
        try:
            # Prepare content snippet
            content_snippet = self._prepare_content_snippet(content_data)
            
            # Format prompt
            prompt = self.classification_prompt.format(
                url=url,
                title=content_data.get('title', 'N/A'),
                description=content_data.get('description', 'N/A'),
                content_snippet=content_snippet
            )
            
            # Make API request
            result, error_code = await self._call_ollama_api(prompt)
            
            if error_code != ErrorCode.SUCCESS:
                return {}, error_code
            
            # Parse and validate response
            classification = self._parse_llm_response(result)
            
            if not classification:
                return {}, ErrorCode.ERR_LLM_INVALID_RESPONSE
            
            return classification, ErrorCode.SUCCESS
            
        except Exception as e:
            logger.error(f"LLM classification error for {url}: {e}")
            return {}, ErrorCode.ERR_LLM_UNAVAILABLE
    
    def _prepare_content_snippet(self, content_data: Dict[str, Any]) -> str:
        """Prepare a relevant content snippet for LLM analysis."""
        content = content_data.get('content', '')
        
        # Limit content size to avoid context length issues
        max_content_length = 2000
        
        if len(content) <= max_content_length:
            return content
        
        # Try to extract the most relevant parts
        # Look for MCP-related sections first
        mcp_keywords = ['mcp', 'model context protocol', 'modelcontextprotocol', 
                       'server', 'client', 'tools', 'resources']
        
        best_snippet = ""
        best_score = 0
        
        # Split content into chunks and score them
        chunk_size = max_content_length // 2
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i + max_content_length]
            score = sum(chunk.lower().count(keyword) for keyword in mcp_keywords)
            
            if score > best_score:
                best_score = score
                best_snippet = chunk
        
        return best_snippet if best_snippet else content[:max_content_length]
    
    async def _call_ollama_api(self, prompt: str) -> Tuple[Optional[str], ErrorCode]:
        """Make API call to Ollama."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,  # Low temperature for consistent classification
                        "num_predict": 200,  # Limit response length
                    }
                }
                
                async with session.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        return result.get('response', ''), ErrorCode.SUCCESS
                    elif response.status == 404:
                        logger.error(f"Ollama model '{self.model}' not found")
                        return None, ErrorCode.ERR_LLM_UNAVAILABLE
                    else:
                        logger.error(f"Ollama API error: {response.status}")
                        return None, ErrorCode.ERR_LLM_UNAVAILABLE
                        
        except asyncio.TimeoutError:
            logger.error("Ollama API timeout")
            return None, ErrorCode.ERR_LLM_TIMEOUT
        except aiohttp.ClientError as e:
            logger.error(f"Ollama API connection error: {e}")
            return None, ErrorCode.ERR_LLM_UNAVAILABLE
        except Exception as e:
            logger.error(f"Unexpected Ollama API error: {e}")
            return None, ErrorCode.ERR_LLM_UNAVAILABLE
    
    def _parse_llm_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse and validate LLM response."""
        try:
            # Extract JSON from response
            response = response.strip()
            
            # Try to find JSON object in response
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                logger.error("No JSON object found in LLM response")
                return None
            
            json_str = response[start_idx:end_idx]
            result = json.loads(json_str)
            
            # Validate required fields
            required_fields = ['category', 'confidence']
            for field in required_fields:
                if field not in result:
                    logger.error(f"Missing required field '{field}' in LLM response")
                    return None
            
            # Validate category
            valid_categories = ['mcp_server', 'mcp_intro', 'mcp_registry', 'unknown']
            if result['category'] not in valid_categories:
                logger.error(f"Invalid category '{result['category']}' in LLM response")
                return None
            
            # Validate confidence
            try:
                confidence = float(result['confidence'])
                if not 0.0 <= confidence <= 1.0:
                    logger.error(f"Invalid confidence value: {confidence}")
                    return None
                result['confidence'] = confidence
            except (ValueError, TypeError):
                logger.error("Invalid confidence format in LLM response")
                return None
            
            # Add reasoning if available
            if 'reasoning' not in result:
                result['reasoning'] = "No reasoning provided"
            
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in LLM response: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            return None
    
    async def health_check(self) -> bool:
        """Check if Ollama API is available and model is loaded."""
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Check if API is available
                async with session.get(f"{self.base_url}/api/tags") as response:
                    if response.status != 200:
                        return False
                    
                    tags_data = await response.json()
                    models = [model['name'] for model in tags_data.get('models', [])]
                    
                    # Check if our model is available
                    return self.model in models
                    
        except Exception as e:
            logger.debug(f"Ollama health check failed: {e}")
            return False
    
    async def classify_with_retry(self, 
                                url: str, 
                                content_data: Dict[str, Any],
                                max_retries: int = 1) -> Tuple[Dict[str, Any], ErrorCode]:
        """
        Classify with retry on timeout (with reduced content).
        
        Args:
            url: Target URL
            content_data: Content data
            max_retries: Maximum retry attempts
            
        Returns:
            Tuple of (classification_result, error_code)
        """
        for attempt in range(max_retries + 1):
            result, error_code = await self.classify_url(url, content_data)
            
            if error_code == ErrorCode.SUCCESS:
                return result, error_code
            
            if error_code == ErrorCode.ERR_LLM_TIMEOUT and attempt < max_retries:
                # Reduce content size for retry
                original_content = content_data.get('content', '')
                if len(original_content) > 500:
                    content_data = content_data.copy()
                    content_data['content'] = original_content[:len(original_content)//2]
                    logger.info(f"Retrying LLM classification with reduced content for {url}")
                    continue
            
            return result, error_code
        
        return {}, error_code
