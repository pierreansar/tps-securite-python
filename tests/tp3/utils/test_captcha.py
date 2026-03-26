import io
from unittest.mock import MagicMock, patch

from PIL import Image

from src.tp3.utils.captcha import Captcha


def make_png_bytes():
    """Crée une image PNG en mémoire pour les tests."""
    buf = io.BytesIO()
    Image.new("RGB", (100, 30), color="white").save(buf, format="PNG")
    buf.seek(0)
    return buf.read()


def test_captcha_init():
    # Given
    url = "http://example.com/captcha"

    # When
    captcha = Captcha(url)

    # Then
    assert captcha.url == url
    assert captcha.image is None
    assert captcha.value == ""


def test_capture_finds_image():
    # Given
    captcha = Captcha("http://example.com/captcha")
    html = '<html><body><form><img src="/captcha.png"><input></form></body></html>'

    mock_html = MagicMock()
    mock_html.text = html
    mock_img = MagicMock()
    mock_img.content = make_png_bytes()

    # When
    with patch.object(captcha._session, "get", side_effect=[mock_html, mock_img]):
        captcha.capture()

    # Then
    assert captcha.image is not None
    assert isinstance(captcha.image, Image.Image)


def test_capture_no_image_tag():
    # Given
    captcha = Captcha("http://example.com/captcha")
    html = "<html><body><p>No image here</p></body></html>"

    mock_html = MagicMock()
    mock_html.text = html

    # When
    with patch.object(captcha._session, "get", return_value=mock_html):
        captcha.capture()

    # Then — aucune image trouvée, pas d'exception
    assert captcha.image is None


def test_solve_with_image():
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.image = Image.new("RGB", (100, 30), color="white")

    # When
    with patch("pytesseract.image_to_string", return_value="ABC123\n"):
        captcha.solve()

    # Then
    assert captcha.value == "ABC123"


def test_solve_strips_whitespace():
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.image = Image.new("RGB", (100, 30), color="white")

    # When
    with patch("pytesseract.image_to_string", return_value="  XY9\n "):
        captcha.solve()

    # Then
    assert captcha.value == "XY9"


def test_solve_without_image():
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.image = None

    # When
    captcha.solve()

    # Then — pas d'exception, valeur reste vide
    assert captcha.value == ""


def test_get_value():
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
