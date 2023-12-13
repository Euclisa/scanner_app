import shodan
import json
import logging
from error import raise_error


class Shodan:

    def __init__(self, api_key: str):
        logger = logging.getLogger('Shodan')
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()  # Output logs to console
        handler.setLevel(logging.DEBUG)  # Set the desired logging level for this handler
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        self.api = shodan.Shodan(api_key)


    def ip_info(ip_addr: str):
        return self.api.host(ip_addr)