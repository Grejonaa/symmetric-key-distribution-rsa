import logging
import os

def setup_logger(name: str = "client", log_file: str = "logs/client.log") -> logging.Logger:
    """
    Set up and return a logger that writes to both a file and the console.

    Args:
        name:     Logger name (default 'client').
        log_file: Path to the log file (default 'logs/client.log').
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Shmang shtimin e duplicate handlers nese thirret me shume se 1 here
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s  [%(levelname)s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler – debug output-i
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Console handler – vetem warnings (per UI clean)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger