import pytest
import tempfile
import uuid

from cipherflux.storage.history_store import HistoryStore
from backend.models.schemas import ScanResponse, ScanSummary, ScanType, SecurityFinding, SeverityLevel, VerificationStatus

@pytest.fixture
def temp_history_store():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = HistoryStore(data_dir=tmpdir)
        yield store

def test_history_save_and_retrieve(temp_history_store):
    finding = SecurityFinding(
        id="f-1",
        title="Test Insecure Header",
        severity=SeverityLevel.LOW,
        category="Frontend Integrity",
        targetScope="target.lab",
        cvss="3.5",
        cweId="CWE-1021",
        description="Missing header test",
        remediationSummary="Fix header",
        verificationStatus=VerificationStatus.CONFIRMED,
    )
    summary = ScanSummary(totalFindings=1, confirmedCount=1, riskScore=15.0, durationSeconds=0.5)
    scan = ScanResponse(
        scanId="scan-test-hist-1",
        target="target.lab",
        scanType=ScanType.ENDPOINT,
        status="COMPLETED",
        summary=summary,
        findings=[finding],
        executiveSummary="Test Executive Summary",
    )

    temp_history_store.save_scan(scan)
    listed = temp_history_store.list_scans()
    assert len(listed) == 1
    assert listed[0]["scanId"] == "scan-test-hist-1"

    retrieved = temp_history_store.get_scan("scan-test-hist-1")
    assert retrieved is not None
    assert retrieved.findings[0].title == "Test Insecure Header"

def test_history_compare_scans(temp_history_store):
    f_persistent = SecurityFinding(
        id="f-p",
        title="Persistent Vulnerability",
        severity=SeverityLevel.HIGH,
        category="Injection",
        targetScope="target.lab/query",
        cvss="7.5",
        cweId="CWE-89",
        description="Persistent flaw",
        remediationSummary="Remediate",
        verificationStatus=VerificationStatus.CONFIRMED,
    )
    f_resolved = SecurityFinding(
        id="f-r",
        title="Resolved Vulnerability",
        severity=SeverityLevel.MEDIUM,
        category="Headers",
        targetScope="target.lab",
        cvss="5.0",
        cweId="CWE-319",
        description="Resolved flaw",
        remediationSummary="Fixed",
        verificationStatus=VerificationStatus.CONFIRMED,
    )
    f_new = SecurityFinding(
        id="f-n",
        title="Newly Discovered Vulnerability",
        severity=SeverityLevel.CRITICAL,
        category="Access Control",
        targetScope="target.lab/admin",
        cvss="9.0",
        cweId="CWE-284",
        description="New flaw",
        remediationSummary="Fix immediately",
        verificationStatus=VerificationStatus.CONFIRMED,
    )

    # Scan A (older): has persistent and resolved
    scan_a = ScanResponse(
        scanId="scan-older",
        target="target.lab",
        scanType=ScanType.FULL,
        status="COMPLETED",
        summary=ScanSummary(totalFindings=2, confirmedCount=2, riskScore=40.0),
        findings=[f_persistent, f_resolved],
        executiveSummary="Older scan executive summary",
    )

    # Scan B (newer): has persistent and new (resolved is gone)
    scan_b = ScanResponse(
        scanId="scan-newer",
        target="target.lab",
        scanType=ScanType.FULL,
        status="COMPLETED",
        summary=ScanSummary(totalFindings=2, confirmedCount=2, riskScore=60.0),
        findings=[f_persistent, f_new],
        executiveSummary="Newer scan executive summary",
    )

    temp_history_store.save_scan(scan_a)
    temp_history_store.save_scan(scan_b)

    cmp_res = temp_history_store.compare_scans("scan-older", "scan-newer")
    assert cmp_res["persistentFindingsCount"] == 1
    assert cmp_res["resolvedFindingsCount"] == 1
    assert cmp_res["newFindingsCount"] == 1
    assert cmp_res["riskDelta"] == 20.0
