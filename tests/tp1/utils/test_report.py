from unittest.mock import MagicMock, mock_open, patch

from src.tp1.utils.report import Report


def make_report(protocols: dict | None = None, alerts: list | None = None) -> Report:
    """Crée un Report avec un Capture mocké."""
    capture = MagicMock()
    capture.protocols = protocols or {}
    capture.alerts = alerts or []
    summary = "=== Resume IDS ===\n[OK] Aucune menace detectee."
    return Report(capture, "test.pdf", summary)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def test_report_init():
    report = make_report()

    assert report.filename == "test.pdf"
    assert report.title == "Rapport IDS - Analyse du trafic reseau"
    assert report.array == ""
    assert report.graph == ""


# ---------------------------------------------------------------------------
# concat_report
# ---------------------------------------------------------------------------

def test_concat_report_contains_all_parts():
    report = make_report()
    report.array = "tableau"
    report.graph = "graphe"

    result = report.concat_report()

    assert report.title in result
    assert report.summary in result
    assert "tableau" in result
    assert "graphe" in result


# ---------------------------------------------------------------------------
# generate("array")
# ---------------------------------------------------------------------------

def test_generate_array_empty_protocols():
    report = make_report(protocols={})
    report.generate("array")

    assert report.array == ""


def test_generate_array_with_protocols():
    report = make_report(protocols={"TCP": 50, "UDP": 20, "ARP": 5})
    report.generate("array")

    assert "TCP" in report.array
    assert "UDP" in report.array
    assert "ARP" in report.array
    assert "TOTAL" in report.array
    # TCP doit apparaître en premier (tri décroissant)
    assert report.array.index("TCP") < report.array.index("UDP")


def test_generate_array_total_is_correct():
    report = make_report(protocols={"TCP": 10, "UDP": 5})
    report.generate("array")

    assert "15" in report.array


# ---------------------------------------------------------------------------
# generate("graph")
# ---------------------------------------------------------------------------

def test_generate_graph_empty_protocols():
    report = make_report(protocols={})
    report.generate("graph")

    assert report.graph == ""


def test_generate_graph_with_protocols():
    report = make_report(protocols={"TCP": 30, "UDP": 10})

    with patch("src.tp1.utils.report.pygal.HorizontalBar") as mock_chart_cls:
        mock_chart = MagicMock()
        mock_chart.render.return_value = b"<svg>...</svg>"
        mock_chart_cls.return_value = mock_chart

        report.generate("graph")

    assert report.graph == "<svg>...</svg>"
    mock_chart.add.assert_any_call("TCP", 30)
    mock_chart.add.assert_any_call("UDP", 10)


def test_generate_invalid_param():
    report = make_report()
    # Ne doit pas lever d'exception
    report.generate("invalid")
    assert report.array == ""
    assert report.graph == ""


# ---------------------------------------------------------------------------
# save
# ---------------------------------------------------------------------------

def test_save_writes_to_file():
    report = make_report(protocols={"TCP": 5})
    report.generate("array")

    with (
        patch("builtins.open", mock_open()) as mock_file,
        patch("src.tp1.utils.report.weasyprint.HTML") as mock_wp,
    ):
        report.save("out.html")

    mock_file.assert_called_once_with("out.html", "w", encoding="utf-8")
    mock_wp.assert_called_once_with(filename="out.html")
    mock_wp.return_value.write_pdf.assert_called_once_with("out.pdf")


def test_save_content_contains_title_and_summary():
    report = make_report()
    report.graph = "<svg>...</svg>"

    with (
        patch("builtins.open", mock_open()) as mock_file,
        patch("src.tp1.utils.report.weasyprint.HTML"),
    ):
        report.save("out.html")

    written = mock_file().write.call_args[0][0]
    assert report.title in written
    assert report.summary in written
    assert "<!DOCTYPE html>" in written
