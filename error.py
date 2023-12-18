import logging


def raise_error(logger: logging.Logger, msg: str, e: Exception = None):
    msg = f"{msg}. Details: '{str(e)}'"
    logger.error(msg)
    if e is not None:
        raise e
    else:
        raise RuntimeError(msg)