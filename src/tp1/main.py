from pathlib import Path

from src.tp1.utils.capture import Capture
from src.tp1.utils.config import logger
from src.tp1.utils.report import Report

REPORT_DIR = Path(__file__).parent / "report"


def main():
    logger.info("Starting TP1")

    capture = Capture()
    capture.capture_traffic()   # bloque jusqu'au Ctrl+C, analyse chaque paquet à la volée grâce à prn=self.analyse
    summary = capture._gen_summary()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    filename = str(REPORT_DIR / "report.html")
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
