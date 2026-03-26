import io
import re

import pytesseract
import requests
from PIL import Image, ImageEnhance, ImageFilter

from src.tp3.utils.config import logger


class Captcha:
    def __init__(self, url, session=None):
        self.url = url
        self.image = None
        self.value = ""
        self._session = session or requests.Session()

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        Télécharge la page HTML, trouve l'image captcha et la charge avec Pillow.
        """
        response = self._session.get(self.url)
        response.raise_for_status()

        # Cherche l'URL de l'image captcha dans le HTML
        html = response.text
        match = re.search(
            r'<img[^>]+src=["\']([^"\']*captcha[^"\']*)["\']', html, re.IGNORECASE
        )
        if not match:
            match = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', html)

        if not match:
            logger.warning("Aucune image captcha trouvée dans la page")
            return

        img_url = match.group(1)

        # Construire l'URL absolue si relative
        if img_url.startswith("//"):
            img_url = "http:" + img_url
        elif img_url.startswith("/"):
            parts = self.url.split("/")
            base = parts[0] + "//" + parts[2]
            img_url = base + img_url
        elif not img_url.startswith("http"):
            img_url = self.url.rstrip("/") + "/" + img_url

        img_response = self._session.get(img_url)
        img_response.raise_for_status()
        self.image = Image.open(io.BytesIO(img_response.content))
        logger.info(f"Image captcha capturée depuis {img_url}")

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        Utilise Pillow pour prétraiter l'image et pytesseract pour l'OCR.
        """
        if self.image is None:
            logger.warning("Aucune image à résoudre")
            return

        # Prétraitement de l'image pour améliorer l'OCR
        img = self.image.convert("L")  # Niveaux de gris
        img = ImageEnhance.Contrast(img).enhance(2.0)  # Augmenter le contraste
        img = img.filter(ImageFilter.SHARPEN)  # Accentuer les contours

        # OCR avec pytesseract (mode ligne simple, caractères alphanumériques)
        config = (
            "--psm 7 "
            "-c tessedit_char_whitelist="
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        )
        raw = pytesseract.image_to_string(img, config=config)
        self.value = raw.strip()
        logger.info(f"Captcha résolu : {self.value!r}")

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
