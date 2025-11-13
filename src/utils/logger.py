"""
Logger utility for GlitchForge
"""

import logging
import sys
from pathlib import Path
from typing import Optional

def get_logger(name: str, log_file: Optional[Path] = None, level: str = "INFO") -> logging.Logger:
    """
    Get or create a logger
    
    Args:
        name: Logger name (usually __name__)
        log_file: Optional path to log file
        level: Log level
    
    Returns:
        logging.Logger
    """
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(getattr(logging, level.upper()))
        
        formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
    
    return logger

def setup_logger(name: str, log_file: Optional[Path] = None, level: str = "INFO") -> logging.Logger:
    """Alias for get_logger"""
    return get_logger(name, log_file, level)
