import logging


def config_rootlogger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    # handler = logging.FileHandler()
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname).1s %(name)s :: %(message)s")
    )
    logger.addHandler(handler)
