import logging


def raise_error(logger: logging.Logger, msg: str, e: Exception = None):
    logger.error(f"{msg}. Details: '{str(e)}'")
    raise RuntimeError(msg)