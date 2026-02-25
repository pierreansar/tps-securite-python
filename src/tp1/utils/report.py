from tp1.utils.capture import Capture

import pygal
import weasyprint


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport IDS - Analyse du trafic reseau"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title + "\n\n"
        content += self.summary + "\n\n"
        content += self.array
        content += self.graph
        return content

    def save(self, filename: str) -> None:
        """
        Sauvegarde le rapport au format HTML.
        """
        alerts_html = ""
        if self.capture.alerts:
            items = "\n".join(f"<li><code>{a}</code></li>" for a in self.capture.alerts)
            alerts_html = f"<h2>&#x26A0; Alertes ({len(self.capture.alerts)})</h2><ul>{items}</ul>"
        else:
            alerts_html = "<h2>Alertes</h2><p>&#x2713; Aucune menace detectee.</p>"

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>{self.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; color: #222; }}
        h1 {{ color: #1a1a2e; border-bottom: 2px solid #e63946; padding-bottom: 8px; }}
        h2 {{ color: #457b9d; margin-top: 30px; }}
        pre {{ background: #f4f4f4; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 13px; }}
        li {{ margin: 4px 0; }}
        li code {{ background: #fff0f0; color: #c0392b; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>{self.title}</h1>

    <h2>Resume</h2>
    <pre>{self.summary}</pre>

    {alerts_html}

    <h2>Protocoles captures</h2>
    <pre>{self.array if self.array else "Aucun protocole enregistre."}</pre>

    <h2>Distribution des protocoles</h2>
    {self.graph if self.graph else "<p>Aucun graphique disponible.</p>"}

</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        # Conversion HTML → PDF
        pdf_filename = filename.rsplit(".", 1)[0] + ".pdf"
        weasyprint.HTML(filename=filename).write_pdf(pdf_filename)

    def generate(self, param: str) -> None:
        """
        Génère le graphique (param='graph') ou le tableau (param='array').
        """
        if param == "graph":
            self._generate_graph()
        elif param == "array":
            self._generate_array()

    def _generate_graph(self) -> None:
        """
        Génère un graphique en barres (pygal) inline en SVG.
        """
        protocols = self.capture.protocols
        if not protocols:
            self.graph = ""
            return

        bar_chart = pygal.HorizontalBar(title="Distribution des protocoles")
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            bar_chart.add(proto, count)

        self.graph = bar_chart.render().decode("utf-8")

    def _generate_array(self) -> None:
        """
        Génère un tableau texte des protocoles capturés avec leur nombre de paquets.
        """
        protocols = self.capture.protocols
        if not protocols:
            self.array = ""
            return

        col_w = 20
        header = f"{'Protocole':<{col_w}} {'Paquets':>10}"
        sep = "-" * (col_w + 12)
        rows = [header, sep]

        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            rows.append(f"{proto:<{col_w}} {count:>10}")

        rows.append(sep)
        rows.append(f"{'TOTAL':<{col_w}} {sum(protocols.values()):>10}")

        self.array = "\n".join(rows) + "\n"


