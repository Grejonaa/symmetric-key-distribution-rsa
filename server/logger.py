import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger() -> logging.Logger:
    """
    Initializes and configures the SERVER logger.

    Features:
    ----------
    - Logs written to file and console
    - Rotating log files (max 1MB each, 3 backups)
    - Automatic logs/ directory creation
    - Safe duplicate-handler prevention
    - Structured logging format

    Returns:
    --------
    logging.Logger
        Configured server logger instance

    Raises:
    -------
    None (all internal errors are handled safely)
    """

    logger_name = "server"
    log_file = "logs/server.log"

    try:
        # Ensure logs directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    except Exception as e:
        # Fallback if filesystem fails
        logging.basicConfig(level=logging.ERROR)
        logging.error(f"Failed to create logs directory: {e}")

    # Create logger instance
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate handlers (very important in imports)
    if logger.handlers:
        return logger

    try:
        # ---------------- FORMATTER ----------------
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # ---------------- FILE HANDLER ----------------
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=1024 * 1024,  # 1MB per file
            backupCount=3,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        # ---------------- CONSOLE HANDLER ----------------
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        # ---------------- ATTACH HANDLERS ----------------
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        logger.info("Server logger initialized successfully.")

    except Exception as e:
        # If logging setup fails, fallback to basic logging
        logging.basicConfig(level=logging.ERROR)
        logging.error(f"Logger initialization failed: {e}")

    return logger