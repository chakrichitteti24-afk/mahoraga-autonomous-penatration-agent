import pytest
import asyncio
from backend.core.safety import SecurityScopeEnforcer
from backend.core.risk_engine import RiskEngine
from backend.core.false_positive_engine import FalsePositiveEngine, rule_registry
from backend.core.verification_engine import VerificationEngine
from backend.models.schemas import SecurityFinding, SeverityLevel, VerificationStatus

def test_scope_enforcer_blocks_cloud_metadata():
    is_safe, msg = SecurityScopeEnforcer.validate_target_safety("http://169.254.169.254/latest/meta-data")
    assert not is_safe
    assert "metadata" in msg.lower()

def test_scope_enforcer_blocks_google_metadata():
    is_safe, msg = SecurityScopeEnforcer.validate_target_safety("http://metadata.google.internal")
    assert not is_safe

def test_sensitive_data_redactor():
    raw_text = "aws_key = AKIAIOSFODNN7EXAMPLE and secret = password123456"
    redacted = SecurityScopeEnforcer.redact_sensitive_string(raw_text)
    assert "AKIA****************" in redacted
    assert "secret: [REDACTED_SECRET]" in redacted
    assert "password123456" not in redacted

def test_jwt_redaction():
    token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
    redacted = SecurityScopeEnforcer.redact_sensitive_string(token)
    assert "Bearer [REDACTED_JWT_TOKEN]" in redacted
    assert "doNotLeakThisSignature" not in redacted

def test_risk_engine_normalized_scoring():
    findings = [
        SecurityFinding(
            id="f1",
            title="Critical SQL Injection",
            severity=SeverityLevel.CRITICAL,
            category="Injection",
            targetScope="db.internal",
            cvss="9.8",
            description="desc",
            remediationSummary="rem",
            verificationStatus=VerificationStatus.CONFIRMED,
        ),
        SecurityFinding(
            id="f2",
            title="High Command Injection",
            severity=SeverityLevel.HIGH,
            category="Injection",
            targetScope="app.internal",
            cvss="8.8",
            description="desc",
            remediationSummary="rem",
            verificationStatus=VerificationStatus.CONFIRMED,
        ),
    ]
    summary = RiskEngine.calculate_scan_summary(findings, 2.5)
    assert summary.totalFindings == 2
    assert summary.confirmedCount == 2
    assert summary.criticalCount == 1
    assert summary.highCount == 1
    assert summary.riskScore > 50.0  # Two confirmed critical/high vulnerabilities yield significant risk
    assert "RISK" in RiskEngine.get_posture_grade(summary.riskScore)

def test_fp_engine_deduplication():
    engine = FalsePositiveEngine()
    f1 = SecurityFinding(
        id="f1", title="SQLi", severity=SeverityLevel.CRITICAL, category="Injection",
        targetScope="host/api:1", cweId="CWE-89", cvss="9.0", description="d", remediationSummary="r"
    )
    f2 = SecurityFinding(
        id="f2", title="SQLi", severity=SeverityLevel.CRITICAL, category="Injection",
        targetScope="host/api:1", cweId="CWE-89", cvss="9.0", description="d", remediationSummary="r"
    )
    deduped = engine.deduplicate([f1, f2])
    assert len(deduped) == 1

def test_fp_engine_suppression():
    engine = FalsePositiveEngine()
    f = SecurityFinding(
        id="f1", title="Test Finding", severity=SeverityLevel.LOW, category="Info",
        targetScope="app", cvss="3.0", description="d", remediationSummary="r"
    )
    suppressed = engine.suppress_finding(f, "Accepted business risk for test cluster", "security_engineer")
    assert suppressed.suppressed is True
    assert "Accepted business risk" in suppressed.suppressionJustification
    assert "SUPPRESSED" in suppressed.statusBadge

def test_verification_engine_secret_real_vs_mock():
    engine = VerificationEngine()
    # Mock token
    mock_finding = SecurityFinding(
        id="f1", title="Secret", severity=SeverityLevel.HIGH, category="Secrets & Credentials",
        targetScope="test.py", cvss="8.0", description="d", remediationSummary="r",
        codeSnippet="API_KEY = 'test_key_sample_12345'",
        cweId="CWE-798"
    )
    engine._verify_sast_secret(mock_finding)
    assert mock_finding.verificationStatus == VerificationStatus.POTENTIAL

    # Real high-entropy token
    real_finding = SecurityFinding(
        id="f2", title="Secret", severity=SeverityLevel.HIGH, category="Secrets & Credentials",
        targetScope="prod.py", cvss="8.0", description="d", remediationSummary="r",
        codeSnippet="API_KEY = 'd41d8cd98f00b204e9800998ecf8427e'",
        cweId="CWE-798"
    )
    engine._verify_sast_secret(real_finding)
    assert real_finding.verificationStatus == VerificationStatus.CONFIRMED

def test_rule_registry_contains_core_rules():
    rules = rule_registry.list_all()
    assert len(rules) >= 8
    rule_ids = [r.rule_id for r in rules]
    assert "CFL-SQLI-001" in rule_ids
    assert "CFL-XSS-001" in rule_ids
    assert "CFL-CORS-001" in rule_ids
    assert "CFL-TLS-001" in rule_ids
    assert "CFL-SCA-001" in rule_ids
