"""
Vexor PDF Report Generator
"""
from pathlib import Path
from vexor.reports.html import HTMLReport


class PDFReport:
    def __init__(self, title: str = "Vexor Security Report"):
        self.title = title

    async def generate(self, output_path: str, findings: list = None, target: str = "") -> str:
        # Generate HTML first
        html_path = output_path.replace(".pdf", "_temp.html")
        html_report = HTMLReport(title=self.title)
        await html_report.generate(html_path, findings=findings, target=target)

        try:
            from weasyprint import HTML
            HTML(filename=html_path).write_pdf(output_path)
            Path(html_path).unlink(missing_ok=True)
        except ImportError:
            # Fallback: save as HTML if weasyprint not available
            import shutil
            shutil.move(html_path, output_path.replace(".pdf", ".html"))
            return output_path.replace(".pdf", ".html")

        return output_path
