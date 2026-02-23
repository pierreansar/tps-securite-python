from unittest.mock import MagicMock, patch

import scapy.all as scapy

from src.tp1.utils.capture import Capture


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_capture() -> Capture:
    """Crée une instance de Capture sans déclencher choose_interface."""
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0"):
        return Capture()


def make_tcp_packet(payload: str = "") -> scapy.Packet:
    """Crée un paquet TCP/IP avec un payload Raw optionnel."""
    pkt = scapy.IP(src="192.168.1.10", dst="192.168.1.1") / scapy.TCP()
    if payload:
        pkt = pkt / scapy.Raw(load=payload.encode())
    return pkt


def make_arp_reply(ip: str, mac: str) -> scapy.Packet:
    """Crée un paquet ARP reply (op=2)."""
    return scapy.ARP(op=2, psrc=ip, hwsrc=mac)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def test_capture_init():
    capture = make_capture()

    assert capture.interface == "eth0"
    assert capture.summary == ""
    assert capture.alerts == []
    assert capture.protocols == {}
    assert capture.arp_table == {}


# ---------------------------------------------------------------------------
# capture_traffic
# ---------------------------------------------------------------------------

def test_capture_traffic_calls_sniff():
    """capture_traffic ouvre un PcapWriter et appelle scapy.sniff."""
    capture = make_capture()

    mock_writer = MagicMock()
    mock_writer.__enter__ = MagicMock(return_value=mock_writer)
    mock_writer.__exit__ = MagicMock(return_value=False)

    with (
        patch("src.tp1.utils.capture.scapy.PcapWriter", return_value=mock_writer),
        patch("src.tp1.utils.capture.scapy.sniff") as mock_sniff,
    ):
        capture.capture_traffic()

    mock_sniff.assert_called_once_with(
        iface="eth0", prn=capture.analyse, store=False
    )


# ---------------------------------------------------------------------------
# analyse — comptage des protocoles
# ---------------------------------------------------------------------------

def test_analyse_counts_protocol():
    capture = make_capture()
    pkt = make_tcp_packet()

    capture.analyse(pkt)

    proto = pkt.lastlayer().name
    assert capture.protocols[proto] == 1


def test_analyse_increments_protocol_count():
    capture = make_capture()
    pkt = make_tcp_packet()

    capture.analyse(pkt)
    capture.analyse(pkt)

    proto = pkt.lastlayer().name
    assert capture.protocols[proto] == 2


# ---------------------------------------------------------------------------
# analyse — détection injection SQL
# ---------------------------------------------------------------------------

def test_analyse_detects_sql_injection():
    capture = make_capture()
    pkt = make_tcp_packet(payload="GET /?id=1 UNION SELECT * FROM users HTTP/1.1")

    capture.analyse(pkt)

    assert len(capture.alerts) == 1
    assert "[SQL INJECTION]" in capture.alerts[0]
    assert "192.168.1.10" in capture.alerts[0]


def test_analyse_no_alert_on_clean_packet():
    capture = make_capture()
    pkt = make_tcp_packet(payload="GET / HTTP/1.1\r\nHost: example.com\r\n")

    capture.analyse(pkt)

    assert capture.alerts == []


def test_analyse_detects_various_sql_patterns():
    patterns = [
        "DROP TABLE users",
        "INSERT INTO users VALUES (1)",
        "SELECT * FROM orders",
        "' OR 1=1 --",
        "admin';--",
    ]
    for payload in patterns:
        capture = make_capture()
        pkt = make_tcp_packet(payload=payload)
        capture.analyse(pkt)
        assert len(capture.alerts) == 1, f"Aucune alerte pour le payload : {payload!r}"


# ---------------------------------------------------------------------------
# analyse — détection ARP spoofing
# ---------------------------------------------------------------------------

def test_analyse_learns_arp_entry():
    capture = make_capture()
    pkt = make_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:ff")

    capture.analyse(pkt)

    assert capture.arp_table["10.0.0.1"] == "aa:bb:cc:dd:ee:ff"
    assert capture.alerts == []


def test_analyse_detects_arp_spoofing():
    capture = make_capture()
    # Premier reply : on apprend l'entrée
    capture.analyse(make_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:ff"))
    # Deuxième reply : même IP, MAC différente → spoofing
    capture.analyse(make_arp_reply("10.0.0.1", "11:22:33:44:55:66"))

    assert len(capture.alerts) == 1
    assert "[ARP SPOOFING]" in capture.alerts[0]


def test_analyse_no_arp_alert_same_mac():
    capture = make_capture()
    capture.analyse(make_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:ff"))
    capture.analyse(make_arp_reply("10.0.0.1", "aa:bb:cc:dd:ee:ff"))

    assert capture.alerts == []


# ---------------------------------------------------------------------------
# sort_network_protocols
# ---------------------------------------------------------------------------

def test_sort_network_protocols_empty():
    capture = make_capture()
    assert capture.sort_network_protocols() == ""


def test_sort_network_protocols_ordered():
    capture = make_capture()
    capture.protocols = {"UDP": 5, "TCP": 20, "ARP": 2}

    result = capture.sort_network_protocols()
    lines = result.splitlines()

    assert lines[0].startswith("TCP")
    assert lines[1].startswith("UDP")
    assert lines[2].startswith("ARP")


# ---------------------------------------------------------------------------
# get_all_protocols
# ---------------------------------------------------------------------------

def test_get_all_protocols_empty():
    capture = make_capture()
    assert capture.get_all_protocols() == ""


def test_get_all_protocols_contains_all():
    capture = make_capture()
    capture.protocols = {"TCP": 3, "DNS": 7}

    result = capture.get_all_protocols()

    assert "TCP: 3 packets" in result
    assert "DNS: 7 packets" in result


# ---------------------------------------------------------------------------
# get_summary / gen_summary
# ---------------------------------------------------------------------------

def test_get_summary_returns_stored_summary():
    capture = make_capture()
    capture.summary = "mon résumé"

    assert capture.get_summary() == "mon résumé"


def test_gen_summary_no_alerts():
    capture = make_capture()
    capture.protocols = {"TCP": 10}

    result = capture.gen_summary()

    assert "=== Résumé IDS ===" in result
    assert "TCP: 10 packets" in result
    assert "Aucune menace détectée" in result
    assert capture.summary == result


def test_gen_summary_with_alerts():
    capture = make_capture()
    capture.alerts = ["[SQL INJECTION] src=1.2.3.4 | payload='UNION SELECT'"]

    result = capture.gen_summary()

    assert "⚠ Alertes (1)" in result
    assert "[SQL INJECTION]" in result
