from unittest.mock import patch

from src.tp1.utils.lib import hello_world, choose_interface


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_choose_interface_returns_selected_interface():
    """Simule un utilisateur qui choisit la première interface disponible."""
    with (
        patch("src.tp1.utils.lib.scapy.get_if_list", return_value=["en0", "lo0"]),
        patch("builtins.input", return_value="0"),
    ):
        result = choose_interface()

    assert result == "en0"


def test_choose_interface_invalid_then_valid():
    """Simule une saisie invalide puis un choix correct."""
    with (
        patch("src.tp1.utils.lib.scapy.get_if_list", return_value=["en0", "lo0"]),
        # "abc" est invalide, "1" sélectionne lo0
        patch("builtins.input", side_effect=["abc", "1"]),
    ):
        result = choose_interface()

    assert result == "lo0"
