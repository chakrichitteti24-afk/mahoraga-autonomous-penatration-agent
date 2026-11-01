import pytest
import io
import os
import json
from rich.console import Console

from cipherflux.cli.banner import render_banner, VERSION
from cipherflux.cli.diagnostics import SystemDiagnostics
from cipherflux.cli.main import build_parser, main
from cipherflux.reporting.exporter import ReportExporter
from backend.storage.memory_store import scan_store

def test_banner_plain_rendering():
    buf = io.StringIO()
    console = Console(file=buf, no_color=True)
    render_banner(console, plain=True)
    output = buf.getvalue()
    assert "CIPHERFLUX LABS" in output
    assert VERSION in output
    assert "ADVANCED VULNERABILITY SCANNER" in output
    assert "READY" in output

def test_system_diagnostics_all_pass():
    results = SystemDiagnostics.run_all_checks()
    assert len(results) >= 10

    # Ensure zero FAILs
    fails = [r for r in results if r.status == "FAIL"]
    assert len(fails) == 0, f"Expected 0 diagnostic failures, found: {[f.check_name + ': ' + f.details for f in fails]}"

    # Verify that safe policy checks are explicitly flagged as NOT_IMPLEMENTED
    not_impl = [r for r in results if r.status == "NOT_IMPLEMENTED"]
    assert any("Exploitation" in r.check_name for r in not_impl)
    assert any("Denial of Service" in r.check_name for r in not_impl)

def test_cli_parser_arguments():
    parser = build_parser()

    # doctor
    args = parser.parse_args(["doctor"])
    assert args.subcommand == "doctor"

    # scan with options
    args = parser.parse_args(["scan", "https://app.lab", "--profile", "quick", "--export", "pdf"])
    assert args.subcommand == "scan"
    assert args.target == "https://app.lab"
    assert args.profile == "quick"
    assert args.export == "pdf"

    # cve query
    args = parser.parse_args(["cve", "--query", "lodash"])
    assert args.subcommand == "cve"
    assert args.query == "lodash"

    # rules
    args = parser.parse_args(["rules", "--search", "injection"])
    assert args.subcommand == "rules"
    assert args.search == "injection"

def test_cli_targets_list_command(capsys):
    ret = main(["--json", "targets", "list"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert len(data) >= 1

def test_cli_cve_search_command(capsys):
    ret = main(["--json", "cve", "--query", "axios"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert isinstance(data, list)
    assert any("CVE-2021-3749" in item["cve"] for item in data)

def test_report_exporter_outputs_all_formats(tmp_path):
    baseline = scan_store.get_scan("scan-demo-baseline")
    assert baseline is not None

    for fmt in ["pdf", "md", "csv", "json"]:
        out_file = ReportExporter.export_report(baseline, format_type=fmt, output_dir=str(tmp_path))
        assert out_file is not None
        assert os.path.exists(out_file)
        assert os.path.getsize(out_file) > 0
