import logging


def raise_error(logger: logging.Logger, msg: str):
    logger.error(msg)
    raise RuntimeError(msg)