from typing import Dict, List, Optional
from datetime import datetime

from ..models.schemas import (
    ScanResponse,
    ScanType,
    ScanSummary,
    SecurityFinding,
    SeverityLevel,
    VerificationStatus,
    SubsystemStatusModel,
)

class MemoryStore:
    def __init__(self):
        self.scans: Dict[str, ScanResponse] = {}
        self._seed_default_scan()

    def _seed_default_scan(self):
        """Seed baseline demonstration scan matching CipherFlux Labs dashboard."""
        default_findings = [
            SecurityFinding(
                id="finding-cors-live",
                title="Permissive Cross-Origin Resource Sharing (CORS) Policy",
                severity=SeverityLevel.HIGH,
                category="API Security",
                targetScope="api.preview-cluster.internal/v2/auth",
                affectedUrl="https://api.preview-cluster.internal/v2/auth",
                cvss="7.4",
                cvssVersion="3.1",
                cweId="CWE-942",
                owaspCategory="A01:2021-Broken Access Control",
                lineNumber=42,
                codeSnippet="Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                description="The authentication cluster reflects wildcard origins while permitting credentials. Malicious sites can issue cross-origin requests to exfiltrate user session tokens.",
                remediationSummary="Restrict Access-Control-Allow-Origin from wildcard reflection to explicitly verified domain whitelists.",
                remediationCode="// Enforce strict origin whitelist\nconst ALLOWED_ORIGINS = ['https://app.cipherflux.internal'];\nif (ALLOWED_ORIGINS.includes(req.headers.origin)) {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n}",
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="VERIFIED (LIVE PROBE)",
                confidence=0.99,
                evidence={"originReflected": "*", "credentialsPermitted": True},
            ),
            SecurityFinding(
                id="finding-hsts-live",
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity=SeverityLevel.MEDIUM,
                category="Cryptographic Posture",
                targetScope="gateway-ingress.preview-cluster.internal",
                affectedUrl="https://gateway-ingress.preview-cluster.internal",
                cvss="5.3",
                cvssVersion="3.1",
                cweId="CWE-319",
                owaspCategory="A05:2021-Security Misconfiguration",
                description="Ingress gateway edge does not send Strict-Transport-Security header. Browsers may establish initial connections over HTTP, exposing users to SSL-stripping attacks.",
                remediationSummary="Add Strict-Transport-Security with a minimum max-age of 31536000 seconds (1 year) and includeSubDomains.",
                remediationCode="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="VERIFIED (LIVE PROBE)",
                confidence=1.0,
            ),
            SecurityFinding(
                id="finding-csp-live",
                title="Missing Content-Security-Policy (CSP) Header",
                severity=SeverityLevel.MEDIUM,
                category="Frontend Integrity",
                targetScope="app.preview-cluster.internal",
                affectedUrl="https://app.preview-cluster.internal",
                cvss="6.1",
                cvssVersion="3.1",
                cweId="CWE-1021",
                owaspCategory="A05:2021-Security Misconfiguration",
                lineNumber=18,
                codeSnippet="Content-Security-Policy: (header missing)",
                description="No Content-Security-Policy header defined. Without CSP, modern browser defenses against Cross-Site Scripting (XSS) and unauthorized data exfiltration are disabled.",
                remediationSummary="Deploy a restrictive Content-Security-Policy restricting script-src, style-src, and object-src to trusted sources.",
                remediationCode="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="VERIFIED (LIVE PROBE)",
                confidence=1.0,
            ),
        ]

        summary = ScanSummary(
            totalFindings=3,
            confirmedCount=3,
            potentialCount=0,
            inconclusiveCount=0,
            criticalCount=0,
            highCount=1,
            mediumCount=2,
            lowCount=0,
            infoCount=0,
            riskScore=26.0,
            durationSeconds=1.42,
        )

        scan = ScanResponse(
            scanId="scan-demo-baseline",
            target="preview-cluster.internal",
            scanType=ScanType.FULL,
            status="COMPLETED",
            createdAt=datetime.utcnow().isoformat() + "Z",
            summary=summary,
            findings=default_findings,
            executiveSummary=(
                "Baseline security audit for preview-cluster.internal completed. 3 findings confirmed "
                "(0 Critical, 1 High, 2 Medium). Immediate focus recommended for CORS policy on auth service."
            ),
        )
        self.scans[scan.scanId] = scan

    def save_scan(self, scan: ScanResponse):
        self.scans[scan.scanId] = scan

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        return self.scans.get(scan_id)

    def get_latest_scan(self) -> Optional[ScanResponse]:
        if not self.scans:
            return None
        return list(self.scans.values())[-1]

    def list_scans(self) -> List[ScanResponse]:
        return list(self.scans.values())

    def get_finding(self, finding_id: str) -> Optional[SecurityFinding]:
        for scan in self.scans.values():
            for f in scan.findings:
                if f.id == finding_id:
                    return f
        return None

    def suppress_finding(self, finding_id: str, justification: str, operator_name: str = "security_lead") -> Optional[SecurityFinding]:
        finding = self.get_finding(finding_id)
        if finding:
            finding.suppressed = True
            finding.suppressionJustification = f"Suppressed by {operator_name} at {datetime.utcnow().isoformat()}Z: {justification}"
            finding.statusBadge = "SUPPRESSED (POLICY)"
            return finding
        return None

    def get_subsystem_status(self) -> List[SubsystemStatusModel]:
        return [
            SubsystemStatusModel(
                name="Security Assessment Core",
                designation="MOD-01",
                status="OPERATIONAL",
                phase="PRODUCTION ENGINE",
                progressPercent=100,
                note="SAST AST engine & DAST network posture auditor active",
            ),
            SubsystemStatusModel(
                name="Vulnerability Verification Engine",
                designation="MOD-02",
                status="OPERATIONAL",
                phase="ACTIVE VERIFIER",
                progressPercent=100,
                note="Evidence validation, baseline comparison, and canary probes active",
            ),
            SubsystemStatusModel(
                name="False-Positive Reduction Engine",
                designation="MOD-03",
                status="OPERATIONAL",
                phase="CALIBRATED FILTER",
                progressPercent=100,
                note="Deduplication, suppression management, and calibrated confidence scoring",
            ),
            SubsystemStatusModel(
                name="Software Supply Chain & CVE Engine",
                designation="MOD-04",
                status="OPERATIONAL",
                phase="INTELLIGENCE HUB",
                progressPercent=100,
                note="OSV/NVD CVE range matching across npm, pip, go, cargo, and maven",
            ),
            SubsystemStatusModel(
                name="Container & Infrastructure-as-Code Auditor",
                designation="MOD-05",
                status="OPERATIONAL",
                phase="STATIC AUDITOR",
                progressPercent=100,
                note="Dockerfile, Kubernetes YAML, and Terraform security scanning",
            ),
            SubsystemStatusModel(
                name="CipherFlux Autonomous Security Analyst",
                designation="MOD-06",
                status="OPERATIONAL",
                phase="ACTIVE AGENT",
                progressPercent=98,
                note="Natural language reasoning & voice query processing ready",
            ),
        ]

scan_store = MemoryStore()
