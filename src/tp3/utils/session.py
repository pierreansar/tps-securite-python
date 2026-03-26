import re

import requests

from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self._http_session = requests.Session()
        self._response = None

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url, self._http_session)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = self.captcha_value

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        data = {"captcha": self.captcha_value}
        self._response = self._http_session.post(self.url, data=data)
        logger.info(
            f"Captcha soumis : {self.captcha_value!r} "
            f"(status {self._response.status_code})"
        )

    def process_response(self):
        """
        Processes the response.
        Returns True si un flag a été trouvé, False sinon.
        """
        if self._response is None:
            return False

        text = self._response.text

        # Cherche un flag au format ESGI{...}
        match = re.search(r"ESGI\{[^}]+\}", text)
        if match:
            self.valid_flag = match.group(0)
            logger.info(f"Flag trouvé : {self.valid_flag}")
            return True

        # Indicateurs génériques de succès avec extraction du flag
        if re.search(r"success|correct|well done|bravo|congrat", text, re.IGNORECASE):
            flag_match = re.search(
                r"flag\s*[=:]\s*([A-Za-z0-9_{}\-]+)", text, re.IGNORECASE
            )
            if flag_match:
                self.valid_flag = flag_match.group(1)
                logger.info(f"Flag trouvé : {self.valid_flag}")
                return True

        logger.info("Captcha incorrect ou flag introuvable, nouvelle tentative...")
        return False

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
