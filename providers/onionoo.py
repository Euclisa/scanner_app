import requests
import json
import logging
from error import raise_error

logger = logging.getLogger('Onionoo')
logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()  # Output logs to console
handler.setLevel(logging.DEBUG)  # Set the desired logging level for this handler

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

class Onionoo:

    API_URL = "https://onionoo.torproject.org"
    VITAL_FIELDS = ["nickname",
        "fingerprint",
        "or_addresses",
        "exit_addresses",
        "last_seen",
        "last_changed_address_or_port",
        "first_seen",
        "running",
        "flags",
        "country",
        "verified_host_names",
        "unverified_host_names",
        "contact"
    ]

    @staticmethod
    def _sanitize_relays(relays):
        sanitized_relays = []
        for relay in relays:
            vital_data = {key: relay.get(key) for key in Onionoo.VITAL_FIELDS}
            or_addr_split = [addr.split(':') for addr in vital_data['or_addresses']]
            vital_data['or_addresses'] = or_addr_split
            sanitized_relays.append(vital_data)
        
        return sanitized_relays
    

    @staticmethod
    def _relays_by_url(url: str):
        resp = requests.get(url)

        if resp.status_code != 200:
            raise_error(logger,f"Failed to retrieve data. Status code: {resp.status_code}")

        relays = json.loads(resp.content.decode('utf-8'))['relays']
        relays = Onionoo._sanitize_relays(resp_json)

        return relays
        

    @staticmethod
    def ip_details(ip_addr: str):
        rq_str = f"{Onionoo.API_URL}/details?search={ip_addr}"
        
        return Onionoo._relays_by_url(rq_str)
    

    @staticmethod
    def details():
        rq_str = f"{Onionoo.API_URL}/details"

        return Onionoo._relays_by_url(rq_str)

