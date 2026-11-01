"""
Report Exporter CLI wrapper for CipherFlux Labs.
Exports security assessment deliverables in PDF, JSON, CSV, and Markdown formats.
"""
import os
import json
from pathlib import Path
from typing import Optional, Dict, Any

from backend.reporting.report_generator import report_generator
from backend.models.schemas import ScanResponse
from ..storage.history_store import history_store
from ..storage.config_store import config_store

class ReportExporter:
    @staticmethod
    def export_report(
        scan: ScanResponse,
        format_type: str = "pdf",
        output_dir: Optional[str] = None,
    ) -> str:
        """
        Export scan results into specified format and return file path.
        Supported formats: pdf, json, csv, md / markdown.
        """
        fmt = format_type.lower().strip()
        if fmt == "markdown":
            fmt = "md"

        if output_dir is None:
            output_dir = config_store.get("output_directory", str(Path.home() / "cipherflux-reports"))

        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        report_data = report_generator.generate_detailed_report(scan)
        scan_id = scan.scanId

        if fmt == "pdf":
            filename = f"cipherflux-report-{scan_id}.pdf"
            file_dest = out_path / filename
            pdf_bytes = report_generator.render_pdf_report(report_data)
            with open(file_dest, "wb") as f:
                f.write(pdf_bytes)
            return str(file_dest)

        elif fmt == "csv":
            filename = f"cipherflux-report-{scan_id}.csv"
            file_dest = out_path / filename
            csv_str = report_generator.render_csv_report(report_data)
            with open(file_dest, "w", encoding="utf-8") as f:
                f.write(csv_str)
            return str(file_dest)

        elif fmt == "md":
            filename = f"cipherflux-report-{scan_id}.md"
            file_dest = out_path / filename
            md_str = report_generator.render_markdown_report(report_data)
            with open(file_dest, "w", encoding="utf-8") as f:
                f.write(md_str)
            return str(file_dest)

        elif fmt == "json":
            filename = f"cipherflux-report-{scan_id}.json"
            file_dest = out_path / filename
            with open(file_dest, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            return str(file_dest)

        else:
            raise ValueError(f"Unsupported report format '{format_type}'. Use pdf, json, csv, or md.")

report_exporter = ReportExporter()
