import requests
import json
import logging
from error import raise_error

class Onionoo:

    API_URL = "https://onionoo.torproject.org"
    VITAL_FIELDS = ["nickname",
        "fingerprint",
        "or_addresses",
        #"exit_addresses",
        "last_seen",
        "last_changed_address_or_port",
        "first_seen",
        "running",
        #"flags",
        "country",
        "verified_host_names",
        "unverified_host_names",
        "contact"
    ]

    def __init__(self):
        self.logger = logging.getLogger('Onionoo')
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()  # Output logs to console
        handler.setLevel(logging.DEBUG)  # Set the desired logging level for this handler
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @staticmethod
    def _sanitize_relays(relays):
        sanitized_relays = []
        for relay in relays:
            vital_data = dict()
            for vit_field in Onionoo.VITAL_FIELDS:
                if vit_field in relay:
                    vital_data[vit_field] = relay[vit_field]
            or_addr_split = [addr.split(':') for addr in vital_data['or_addresses']]
            vital_data['or_addr'] = or_addr_split[0][0]
            vital_data['or_port'] = int(or_addr_split[0][1])
            vital_data.pop('or_addresses')
            sanitized_relays.append(vital_data)
        
        return sanitized_relays
    

    @staticmethod
    def _relays_by_url(url: str):
        resp = requests.get(url)

        if resp.status_code != 200:
            raise_error(logger,f"Failed to retrieve data. Status code: {resp.status_code}")

        relays = json.loads(resp.content.decode('utf-8'))['relays']
        relays = Onionoo._sanitize_relays(relays)

        return relays
        

    @staticmethod
    def ip_details(ip_addr: str):
        rq_str = f"{Onionoo.API_URL}/details?search={ip_addr}"
        
        return Onionoo._relays_by_url(rq_str)
    

    @staticmethod
    def details():
        rq_str = f"{Onionoo.API_URL}/details?limit=4"

        return Onionoo._relays_by_url(rq_str)

