import logging
import os

from logging.handlers import RotatingFileHandler


def setup_logger(
    name: str = "client",
    log_file: str = "logs/client.log"
) -> logging.Logger:

    """
    Set up and return a logger that writes to:
    - log file
    - console

    Features:
    - automatic logs folder creation
    - rotating log files
    - duplicate handler protection
    """

    os.makedirs(os.path.dirname(log_file), exist_ok=True)


    logger = logging.getLogger(name)

    logger.setLevel(logging.DEBUG)


    if logger.handlers:
        return logger
    
    # Formatter:
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # =====================================================
    # Rotating file handler
    # =====================================================

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=1024 * 1024,   # 1MB
        backupCount=3,
        encoding="utf-8"
    )

    file_handler.setLevel(logging.DEBUG)

    file_handler.setFormatter(formatter)


    console_handler = logging.StreamHandler()

    console_handler.setLevel(logging.WARNING)

    console_handler.setFormatter(formatter)

     
    # Add handlers to logger
    logger.addHandler(file_handler)

    logger.addHandler(console_handler)

    logger.info("Logger u inicializua me sukses.")

    return logger