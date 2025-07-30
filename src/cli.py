"""
Command-line interface for MCP URL classifier.
"""

import asyncio
import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse
import logging

import click
from dotenv import load_dotenv

from .detector import MCPDetector
from .utils.logger import setup_logger, silence_noisy_loggers
from .utils.throttler import ConcurrencyLimiter, DomainThrottler


# Load environment variables
load_dotenv()

# Default configuration
DEFAULT_CONCURRENCY = int(os.getenv("DEFAULT_CONCURRENCY", "32"))
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "128"))
DEFAULT_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "5"))


@click.command()
@click.option('--url', '-u', help='Single URL to classify')
@click.option('--list', '-l', help='Comma-separated list of URLs')
@click.option('--file', '-f', type=click.Path(exists=True), help='File containing URLs (one per line)')
@click.option('--output', '-o', default='results.csv', help='Output CSV file (default: results.csv)')
@click.option('--json', 'json_output', is_flag=True, help='Also save results as JSON')
@click.option('--concurrency', '-c', default=DEFAULT_CONCURRENCY, 
              help=f'Number of concurrent requests (default: {DEFAULT_CONCURRENCY}, max: {MAX_CONCURRENCY})')
@click.option('--timeout', '-t', default=DEFAULT_TIMEOUT, 
              help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--no-llm', is_flag=True, help='Disable LLM classification')
@click.option('--model', help='Ollama model to use (default: llama3.3)')
@click.option('--prompt', help='Custom prompt template file')
@click.option('--proxy', help='HTTP proxy URL')
@click.version_option(version='1.0.0', prog_name='mcp-classify')
def main(url: Optional[str], 
         list: Optional[str], 
         file: Optional[str],
         output: str,
         json_output: bool,
         concurrency: int,
         timeout: int,
         debug: bool,
         no_llm: bool,
         model: Optional[str],
         prompt: Optional[str],
         proxy: Optional[str]):
    """
    MCP URL Classifier - Classify URLs into MCP-related categories.
    
    Categories:
    - mcp_server: Actual MCP server implementations
    - mcp_intro: Documentation and introduction pages about MCP
    - mcp_registry: MCP server registries and directories  
    - unknown: URLs that don't fit the above categories
    """
    
    # Setup logging
    logger = setup_logger(debug=debug)
    if not debug:
        silence_noisy_loggers()
    
    # Validate concurrency
    if concurrency > MAX_CONCURRENCY:
        logger.warning(f"Concurrency {concurrency} exceeds maximum {MAX_CONCURRENCY}, using {MAX_CONCURRENCY}")
        concurrency = MAX_CONCURRENCY
    
    # Collect URLs
    urls = []
    
    if url:
        urls.append(url)
    
    if list:
        urls.extend([u.strip() for u in list.split(',') if u.strip()])
    
    if file:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                urls.extend(file_urls)
        except Exception as e:
            logger.error(f"Error reading file {file}: {e}")
            sys.exit(1)
    
    if not urls:
        logger.error("No URLs provided. Use --url, --list, or --file to specify URLs.")
        sys.exit(1)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)
    
    logger.info(f"Starting classification of {len(unique_urls)} URLs with concurrency {concurrency}")
    
    # Run classification
    try:
        results = asyncio.run(
            classify_urls(
                unique_urls, 
                concurrency=concurrency,
                timeout=timeout,
                enable_llm=not no_llm,
                model=model,
                prompt=prompt,
                proxy=proxy,
                debug=debug
            )
        )
        
        # Save results
        save_results(results, output, json_output, logger)
        
        # Print summary
        print_summary(results, logger)
        
    except KeyboardInterrupt:
        logger.info("Classification interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


async def classify_urls(urls: List[str],
                       concurrency: int = 32,
                       timeout: int = 5,
                       enable_llm: bool = True,
                       model: Optional[str] = None,
                       prompt: Optional[str] = None,
                       proxy: Optional[str] = None,
                       debug: bool = False) -> List[dict]:
    """
    Classify multiple URLs concurrently.
    
    Args:
        urls: List of URLs to classify
        concurrency: Number of concurrent requests
        timeout: Request timeout in seconds
        enable_llm: Whether to enable LLM classification
        proxy: HTTP proxy URL
        debug: Whether debug mode is enabled
        
    Returns:
        List of classification results
    """
    logger = logging.getLogger(__name__)
    
    # Initialize throttling
    concurrency_limiter = ConcurrencyLimiter(concurrency)
    domain_throttler = DomainThrottler(default_delay=0.5)
    
    # Initialize detector
    detector = MCPDetector(
        timeout=timeout,
        proxy=proxy,
        enable_llm=enable_llm,
        model=model,
        prompt_template_file=prompt
    )
    
    # Check LLM availability if enabled
    if enable_llm and detector.llm_classifier:
        llm_available = await detector.llm_classifier.health_check()
        if not llm_available:
            logger.warning("LLM (Ollama) is not available. Classification will proceed without LLM analysis.")
    
    results = []
    
    async def classify_single_url(url: str) -> dict:
        """Classify a single URL with throttling."""
        start_time = time.time()
        
        try:
            # Parse domain for throttling
            parsed = urlparse(url)
            domain = parsed.netloc
            
            async with concurrency_limiter:
                # Domain-specific throttling
                await domain_throttler.wait_for_domain(domain)
                
                # Perform classification with session management
                async with detector.session:
                    result = await detector.detect(url)
                
                elapsed = time.time() - start_time
                logger.info(f"Classified {url} -> {result['final_classification']['final_label']} "
                          f"(confidence: {result['final_classification']['confidence']:.2f}, "
                          f"time: {elapsed:.1f}s)")
                
                return result
                
        except Exception as e:
            logger.error(f"Error classifying {url}: {e}")
            return {
                'url': url,
                'final_classification': {
                    'url': url,
                    'final_label': 'unknown',
                    'confidence': 0.0,
                    'total_score': 0,
                    'reasoning': [f'Classification failed: {str(e)}'],
                    'error_codes': ['0999'],
                    'metadata': {}
                },
                'elapsed_ms': int((time.time() - start_time) * 1000),
                'error_codes': ['0999']
            }
    
    # Execute classifications concurrently
    logger.info(f"Starting concurrent classification with {concurrency} workers")
    tasks = [classify_single_url(url) for url in urls]
    
    # Use asyncio.as_completed for progress tracking
    completed = 0
    total = len(tasks)
    
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
        completed += 1
        
        if completed % max(1, total // 10) == 0 or completed == total:
            logger.info(f"Progress: {completed}/{total} ({100*completed/total:.1f}%)")
    
    return results


def save_results(results: List[dict], 
                csv_file: str, 
                save_json: bool, 
                logger: logging.Logger):
    """Save results to CSV and optionally JSON."""
    
    # Prepare CSV data
    csv_data = []
    for result in results:
        classification = result.get('final_classification', {})
        
        row = {
            'url': result.get('url', ''),
            'label': classification.get('final_label', 'unknown'),
            'confidence': f"{classification.get('confidence', 0.0):.3f}",
            'error_code': ','.join(classification.get('error_codes', [])) or '0000',
            'retry_count': result.get('retry_count', 0),
            'elapsed_ms': result.get('elapsed_ms', 0),
            'notes': '; '.join(classification.get('reasoning', []))[:200]  # Limit length
        }
        csv_data.append(row)
    
    # Save CSV
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['url', 'label', 'confidence', 'error_code', 'retry_count', 'elapsed_ms', 'notes']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_data)
        
        logger.info(f"Results saved to {csv_file}")
        
    except Exception as e:
        logger.error(f"Error saving CSV file: {e}")
    
    # Save JSON if requested
    if save_json:
        json_file = csv_file.replace('.csv', '.json')
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Detailed results saved to {json_file}")
            
        except Exception as e:
            logger.error(f"Error saving JSON file: {e}")


def print_summary(results: List[dict], logger: logging.Logger):
    """Print classification summary."""
    
    total = len(results)
    if total == 0:
        return
    
    # Count by category
    categories = {}
    error_count = 0
    total_time = 0
    
    for result in results:
        classification = result.get('final_classification', {})
        label = classification.get('final_label', 'unknown')
        
        categories[label] = categories.get(label, 0) + 1
        
        if classification.get('error_codes'):
            error_count += 1
        
        total_time += result.get('elapsed_ms', 0)
    
    # Print summary
    print("\n" + "="*60)
    print("CLASSIFICATION SUMMARY")
    print("="*60)
    print(f"Total URLs processed: {total}")
    print(f"Average time per URL: {total_time/total/1000:.1f}s")
    print(f"URLs with errors: {error_count} ({100*error_count/total:.1f}%)")
    print()
    
    print("Category Distribution:")
    for category, count in sorted(categories.items()):
        percentage = 100 * count / total
        print(f"  {category:12}: {count:4} ({percentage:5.1f}%)")
    
    print("="*60)


if __name__ == '__main__':
    main()
