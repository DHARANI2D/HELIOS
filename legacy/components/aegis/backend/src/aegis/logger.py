import logging
import sys

def setup_logging(level: str = "INFO"):
    """Set up specialized structured logging for AEGIS."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger("aegis")
    logger.info("AEGIS Logging Infrastructure Initialized")
    return logger

logger = setup_logging()
