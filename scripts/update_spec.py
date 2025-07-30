#!/usr/bin/env python3
"""
Update MCP specification from official repository.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


async def update_mcp_spec():
    """Update MCP specification from GitHub repository."""
    
    # Configuration
    mcp_repo_url = os.getenv("MCP_SPEC_REPO", "https://github.com/modelcontextprotocol/registry.git")
    cache_dir = Path(__file__).parent.parent / "cache"
    spec_dir = cache_dir / "mcp_spec"
    
    try:
        # Create cache directory if it doesn't exist
        cache_dir.mkdir(exist_ok=True)
        
        if spec_dir.exists():
            logger.info(f"Updating existing MCP specification in {spec_dir}")
            # Pull latest changes
            result = subprocess.run(
                ["git", "pull"],
                cwd=spec_dir,
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("Successfully updated MCP specification")
        else:
            logger.info(f"Cloning MCP specification repository to {spec_dir}")
            # Clone repository
            result = subprocess.run(
                ["git", "clone", mcp_repo_url, str(spec_dir)],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("Successfully cloned MCP specification repository")
        
        # Update detection rules based on latest spec
        await update_detection_rules(spec_dir)
        
        logger.info("MCP specification update completed successfully")
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Git command failed: {e}")
        logger.error(f"stdout: {e.stdout}")
        logger.error(f"stderr: {e.stderr}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


async def update_detection_rules(spec_dir: Path):
    """Update detection rules based on MCP specification."""
    
    logger.info("Analyzing MCP specification for detection patterns...")
    
    # Look for server implementations in the registry
    servers_dir = spec_dir / "servers"
    if servers_dir.exists():
        server_patterns = set()
        registry_patterns = set()
        
        # Analyze server entries
        for server_file in servers_dir.glob("*.json"):
            try:
                import json
                with open(server_file, 'r', encoding='utf-8') as f:
                    server_data = json.load(f)
                
                # Extract patterns from server metadata
                if 'repository' in server_data:
                    repo_url = server_data['repository']
                    if 'github.com' in repo_url:
                        server_patterns.add('github.com')
                
                if 'homepage' in server_data:
                    homepage = server_data['homepage']
                    # Extract domain patterns
                    from urllib.parse import urlparse
                    parsed = urlparse(homepage)
                    if parsed.netloc:
                        server_patterns.add(parsed.netloc)
                
            except Exception as e:
                logger.warning(f"Error processing {server_file}: {e}")
        
        logger.info(f"Found {len(server_patterns)} server patterns")
        
        # Update pattern files
        patterns_dir = Path(__file__).parent.parent / "src" / "detector" / "patterns"
        patterns_dir.mkdir(exist_ok=True)
        
        # Save updated patterns
        patterns_file = patterns_dir / "mcp_patterns.py"
        with open(patterns_file, 'w', encoding='utf-8') as f:
            f.write('# Auto-generated MCP detection patterns\n')
            f.write('# Generated from MCP specification repository\n\n')
            f.write(f'SERVER_DOMAINS = {list(server_patterns)}\n')
            f.write(f'REGISTRY_PATTERNS = {list(registry_patterns)}\n')
        
        logger.info(f"Updated detection patterns in {patterns_file}")
    
    else:
        logger.warning("No servers directory found in MCP specification")


if __name__ == "__main__":
    asyncio.run(update_mcp_spec())
