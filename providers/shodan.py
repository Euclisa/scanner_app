import json
import logging
import requests

class Shodan:

    def __init__(self):
        self.logger = logging.getLogger('Shodan')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()  # Output logs to console
        handler.setLevel(logging.DEBUG)  # Set the desired logging level for this handler
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)


    def ip_info(self, ip_addr: str):
        return requests.get(f"https://internetdb.shodan.io/{ip_addr}").json()


if __name__ == "__main__":
    sh = SShodan()
    print(sh.ip_info("185.146.232.243"))