from unittest.mock import MagicMock, patch

from src.tp3.utils.session import Session


def test_session_init():
    # Given
    url = "http://example.com/captcha"

    # When
    session = Session(url)

    # Then
    assert session.url == url
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


def test_prepare_request():
    # Given
    session = Session("http://example.com/captcha")
    mock_captcha = MagicMock()
    mock_captcha.get_value.return_value = "ABC123"

    # When
    with patch("src.tp3.utils.session.Captcha", return_value=mock_captcha):
        session.prepare_request()

    # Then
    assert session.captcha_value == "ABC123"
    assert session.flag_value == "ABC123"


def test_submit_request():
    # Given
    session = Session("http://example.com/captcha")
    session.captcha_value = "ABC123"
    mock_response = MagicMock()
    mock_response.status_code = 200

    # When
    with patch.object(session._http_session, "post", return_value=mock_response):
        session.submit_request()

    # Then
    assert session._response is mock_response


def test_process_response_esgi_flag():
    # Given
    session = Session("http://example.com/captcha")
    mock_response = MagicMock()
    mock_response.text = "Bravo ! ESGI{captcha_solved_42}"
    session._response = mock_response

    # When
    result = session.process_response()

    # Then
    assert result is True
    assert session.valid_flag == "ESGI{captcha_solved_42}"


def test_process_response_generic_success():
    # Given
    session = Session("http://example.com/captcha")
    mock_response = MagicMock()
    mock_response.text = "Correct! flag = MY_FLAG_123"
    session._response = mock_response

    # When
    result = session.process_response()

    # Then
    assert result is True
    assert session.valid_flag == "MY_FLAG_123"


def test_process_response_wrong_captcha():
    # Given
    session = Session("http://example.com/captcha")
    mock_response = MagicMock()
    mock_response.text = "Wrong captcha, please try again."
    session._response = mock_response

    # When
    result = session.process_response()

    # Then
    assert result is False
    assert session.valid_flag == ""


def test_process_response_no_response():
    # Given
    session = Session("http://example.com/captcha")

    # When
    result = session.process_response()

    # Then
    assert result is False


def test_get_flag():
    # Given
    session = Session("http://example.com/captcha")
    session.valid_flag = "FLAG123"

    # When
    result = session.get_flag()

    # Then
    assert result == "FLAG123"
