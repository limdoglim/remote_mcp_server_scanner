"""
Logging configuration for MCP URL classifier.
"""

import logging
import sys
from typing import Optional
import os


def setup_logger(name: str = "mcp_classifier", 
                level: Optional[str] = None,
                debug: bool = False) -> logging.Logger:
    """
    Set up logger with appropriate formatting and level.
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        debug: Whether to enable debug mode
        
    Returns:
        Configured logger instance
    """
    # Determine log level
    if debug:
        log_level = logging.DEBUG
    elif level:
        log_level = getattr(logging, level.upper(), logging.INFO)
    else:
        log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)
    
    # Create formatter
    if debug:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Log SSL warning at startup
    if not debug:
        logger.warning(
            "SSL verification is disabled globally for this application. "
            "This is intentional but poses security risks in production."
        )
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger instance by name."""
    return logging.getLogger(name)


class LogContext:
    """Context manager for temporary log level changes."""
    
    def __init__(self, logger: logging.Logger, level: int):
        self.logger = logger
        self.new_level = level
        self.old_level = logger.level
    
    def __enter__(self):
        self.logger.setLevel(self.new_level)
        return self.logger
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.setLevel(self.old_level)


def silence_noisy_loggers():
    """Silence overly verbose third-party loggers."""
    noisy_loggers = [
        'aiohttp.access',
        'aiohttp.client',
        'aiohttp.internal',
        'urllib3.connectionpool',
        'httpx',
        'asyncio'
    ]
    
    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)
