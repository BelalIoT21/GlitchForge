"""
Logger utility for GlitchForge
"""

import logging
import sys
from pathlib import Path
from typing import Optional


class FlushStreamHandler(logging.StreamHandler):
    """Stream handler that flushes after every emit"""
    def emit(self, record):
        super().emit(record)
        self.flush()


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

        # Use flush handler to ensure output appears immediately
        console_handler = FlushStreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        # Prevent propagation to root logger (avoid duplicate logs)
        logger.propagate = False

    return logger

def setup_logger(name: str, log_file: Optional[Path] = None, level: str = "INFO") -> logging.Logger:
    """Alias for get_logger"""
    return get_logger(name, log_file, level)
