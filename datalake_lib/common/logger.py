import logging

logger = logging.getLogger("OCD_DTL")

DEBUG_FORMAT = '%(name)s:%(levelname)-4s %(message)s'
INFO_FORMAT = '%(message)s'


def configure_logging(loglevel: int):
    handler = logging.StreamHandler()

    if loglevel == logging.DEBUG:
        formatter = logging.Formatter(DEBUG_FORMAT)
    else:
        formatter = logging.Formatter(INFO_FORMAT)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(loglevel)
