"""
GlitchForge Logger Utility
Provides centralized logging with color-coded console output and file logging
"""
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color codes for different log levels"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        # Add color to levelname
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
        return super().format(record)


class GlitchForgeLogger:
    """Centralized logger for GlitchForge"""
    
    def __init__(self, name: str = "GlitchForge", log_dir: Optional[Path] = None):
        """
        Initialize logger
        
        Args:
            name: Logger name
            log_dir: Directory for log files (default: ./logs)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers
        if self.logger.handlers:
            return
        
        # Create log directory
        if log_dir is None:
            log_dir = Path(__file__).parent.parent.parent / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Console handler with colors
        # Fix for Windows encoding issues
        import io
        console_handler = logging.StreamHandler(io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8'))
        console_handler.setLevel(logging.INFO)
        console_format = ColoredFormatter(
            '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler (detailed logs)
        log_file = log_dir / f'glitchforge_{datetime.now().strftime("%Y%m%d")}.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(filename)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
    
    def get_logger(self):
        """Return the configured logger"""
        return self.logger
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)


# Global logger instance
_logger_instance = None

def get_logger(name: str = "GlitchForge") -> GlitchForgeLogger:
    """
    Get or create logger instance
    
    Args:
        name: Logger name
        
    Returns:
        GlitchForgeLogger instance
    """
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = GlitchForgeLogger(name)
    return _logger_instance


if __name__ == "__main__":
    # Test the logger
    logger = get_logger("TestLogger")
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")