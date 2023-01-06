"""
for log outputs.

refers:
    - https://qiita.com/shotakaha/items/0fa2db1dc8253c83e2bb
    - https://docs.python.org/ja/3/howto/logging-cookbook.html#logging-cookbook
"""
from logging import getLogger, StreamHandler, FileHandler, DEBUG, Formatter


def setup_logger(name: str, logfile: str):
    """
    TBD :
        - make config file
        - re-make this function.

    Args:
        name (str) :
            name for each logger.
        logfile (str) :
            file path for saving log information.

    Returns:
        logger
    """
    logger = getLogger(name)
    logger.setLevel(DEBUG)

    # create console handler with debug log level
    sh = StreamHandler()
    sh.setLevel(DEBUG)
    sh_fomatter = Formatter("%(asctime)s - %(levelname)s - %(message)s")
    sh.setFormatter(sh_fomatter)

    # create file handler with debug log level.
    fh = FileHandler(logfile)
    fh.setLevel(DEBUG)
    fh_formatter = Formatter(
        "%(asctime)s - %(levelname)s - " "%(filename)s - %(funcName)s - %(message)s"
    )
    fh.setFormatter(fh_formatter)

    # register handler into logger
    logger.addHandler(sh)
    logger.addHandler(fh)

    return logger


if __name__ == "__main__":
    logger = setup_logger(__name__, "/home/src/log/test_log.log")
    logger.debug("hello logging")
