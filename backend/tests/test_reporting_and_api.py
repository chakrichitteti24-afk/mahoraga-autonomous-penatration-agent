import pytest
from backend.reporting.report_generator import ReportGenerator
from backend.storage.memory_store import scan_store
from backend.core.false_positive_engine import rule_registry
from backend.models.schemas import SeverityLevel, VerificationStatus

def test_report_generation_all_21_attributes():
    gen = ReportGenerator()
    baseline = scan_store.get_scan("scan-demo-baseline")
    assert baseline is not None
    report = gen.generate_detailed_report(baseline)

    # 1. Verify Top-Level Report Structure
    assert "metadata" in report
    assert "executiveSummary" in report
    assert "riskBreakdown" in report
    assert "findingsDossiers" in report
    assert "remediationPlan" in report

    # 2. Verify all 21 Standard Finding Attributes in Dossiers
    dossiers = report["findingsDossiers"]
    assert len(dossiers) >= 3

    required_21_fields = [
        "vulnerabilityTitle",       # 1
        "findingId",                # 2
        "affectedAsset",            # 3
        "affectedUrl",              # 4
        "httpMethod",               # 5
        "affectedParameter",        # 6
        "category",                 # 7
        "owaspCategory",            # 8
        "cweId",                    # 9
        "cveId",                    # 10
        "severity",                 # 11
        "cvss",                     # 12
        "confidence",               # 13
        "verificationStatus",       # 14
        "description",              # 15
        "evidence",                 # 16
        "reproductionSteps",        # 17
        "impact",                   # 18
        "remediation",              # 19
        "references",               # 20
        "detectionTimestamp",       # 21
    ]

    for dossier in dossiers:
        for field in required_21_fields:
            assert field in dossier, f"Missing required 21-attribute field: '{field}'"
        assert dossier["cvss"]["score"] != ""
        assert len(dossier["reproductionSteps"]) > 0
        assert len(dossier["references"]) > 0

def test_markdown_report_rendering():
    gen = ReportGenerator()
    baseline = scan_store.get_scan("scan-demo-baseline")
    report = gen.generate_detailed_report(baseline)
    md = gen.render_markdown_report(report)

    assert "# 🛡️" in md
    assert "CipherFlux Labs" in md or "Mahoraga AI" in md
    assert "## 1. Executive Summary" in md
    assert "## 2. Risk Metrics & Severity Breakdown" in md
    assert "## 3. Deep-Dive Vulnerability Dossiers" in md
    assert "## 4. Remediation Roadmap" in md

def test_csv_report_export():
    gen = ReportGenerator()
    baseline = scan_store.get_scan("scan-demo-baseline")
    report = gen.generate_detailed_report(baseline)
    csv_text = gen.render_csv_report(report)

    assert "Finding ID,Title,Severity,CVSS Score" in csv_text
    assert "Permissive Cross-Origin Resource Sharing" in csv_text
    assert "CWE-942" in csv_text

def test_pdf_report_export_via_reportlab():
    gen = ReportGenerator()
    baseline = scan_store.get_scan("scan-demo-baseline")
    report = gen.generate_detailed_report(baseline)
    pdf_bytes = gen.render_pdf_report(report)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000, "PDF should contain valid styling, tables, and binary streams"
    assert pdf_bytes.startswith(b"%PDF-"), "Generated document must be a valid PDF binary"

def test_finding_suppression_with_audit_trail():
    latest = scan_store.get_latest_scan()
    assert latest is not None
    target_finding = latest.findings[0]

    suppressed = scan_store.suppress_finding(
        finding_id=target_finding.id,
        justification="Verified sandbox test environment; accepted business risk.",
        operator_name="lead_appsec_engineer",
    )
    assert suppressed is not None
    assert suppressed.suppressed is True
    assert "lead_appsec_engineer" in suppressed.suppressionJustification
    assert "Accepted business risk" in suppressed.suppressionJustification or "accepted business risk" in suppressed.suppressionJustification

def test_rule_catalog_compliance():
    rules = rule_registry.to_models()
    assert len(rules) >= 8
    for r in rules:
        assert r.ruleId != ""
        assert r.ruleName != ""
        assert r.detectionLogic != ""
        assert r.requiredEvidence != ""
        assert r.verificationLogic != ""
        assert r.falsePositiveConditions != ""
        assert r.remediationGuidance != ""
        assert len(r.references) > 0
