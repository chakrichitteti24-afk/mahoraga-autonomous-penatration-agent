import pytest
from backend.scanners.sast_scanner import SASTScanner
from backend.scanners.sca_scanner import SCAScanner
from backend.agent.security_agent import SecurityAgent
from backend.models.schemas import SeverityLevel

def test_sast_catches_sql_injection():
    scanner = SASTScanner()
    vulnerable_code = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
"""
    findings = scanner.scan_code_snippet(vulnerable_code, language="python")
    assert any(f.cweId == "CWE-89" for f in findings), "Expected SQL injection detection (CWE-89)"

def test_sast_catches_hardcoded_aws_key():
    scanner = SASTScanner()
    vulnerable_code = """
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""
    findings = scanner.scan_code_snippet(vulnerable_code, language="python")
    assert any(f.cweId == "CWE-798" for f in findings), "Expected hardcoded secret detection (CWE-798)"

def test_sast_catches_command_injection():
    scanner = SASTScanner()
    vulnerable_code = """
import os
def ping(host):
    os.system("ping -c 1 " + host)
"""
    findings = scanner.scan_code_snippet(vulnerable_code, language="python")
    assert any(f.cweId == "CWE-78" for f in findings), "Expected command injection detection (CWE-78)"

def test_sca_catches_vulnerable_npm_package():
    scanner = SCAScanner()
    manifest = """{
      "dependencies": {
        "lodash": "4.17.15"
      }
    }"""
    findings = scanner.scan_npm_manifest(manifest)
    assert any("CVE-2021-23337" in str(f.cweId) for f in findings), "Expected lodash prototype pollution finding"

def test_agent_answers_leadership_query():
    agent = SecurityAgent()
    scanner = SASTScanner()
    test_code = "SECRET_KEY = 'AKIA1111111111111111'"
    findings = scanner.scan_code_snippet(test_code)
    response = agent.process_query("Summarize attack vectors for leadership", active_findings=findings)
    assert "leadership" in response.reasoningVector.lower() or "ciso" in response.reasoningVector.lower() or "strategic" in response.reasoningVector.lower()
    assert response.simulatedAgentResponse != ""

def test_report_generator_structured_and_markdown():
    from backend.reporting.report_generator import ReportGenerator
    from backend.storage.memory_store import scan_store

    gen = ReportGenerator()
    baseline = scan_store.get_scan("scan-demo-baseline")
    assert baseline is not None

    report = gen.generate_detailed_report(baseline)
    assert "metadata" in report
    assert "executiveSummary" in report
    assert "findingsDossiers" in report
    assert len(report["findingsDossiers"]) == 3
    assert report["executiveSummary"]["riskScore"] > 0
    assert report["executiveSummary"]["postureGrade"] != ""

    # Test Markdown rendering
    md = gen.render_markdown_report(report)
    assert "# 🛡️ Mahoraga AI Security Audit Report" in md
    assert "## 1. Executive Summary" in md
    assert "## 3. Deep-Dive Vulnerability Dossiers" in md
    assert "## 4. Remediation Roadmap" in md
