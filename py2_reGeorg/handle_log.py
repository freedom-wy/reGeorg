import logging.config
from log_config import log_conf

logging.config.dictConfig(log_conf)
logger = logging.getLogger("w_regeorg")

if __name__ == '__main__':
    logger.debug("debug")
