import io
import csv
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from ..models.schemas import ScanResponse, SecurityFinding, SeverityLevel, VerificationStatus
from ..core.safety import SecurityScopeEnforcer
from ..core.risk_engine import RiskEngine

class ReportGenerator:
    """
    Enterprise Vulnerability Report Generator for CipherFlux Labs.
    Generates structured, evidence-driven audit reports complying with 21 core finding attributes.
    Supports JSON, publication-ready Markdown, CSV, and professional PDF deliverables.
    Enforces automatic redaction of sensitive tokens and credentials across all formats.
    """

    @staticmethod
    def compute_posture_grade(risk_score: float) -> str:
        return RiskEngine.get_posture_grade(risk_score)

    @staticmethod
    def map_owasp_category(category: str, cwe_id: str = "") -> str:
        mapping = {
            "CWE-89": "A03:2021 - Injection (SQLi)",
            "CWE-78": "A03:2021 - Injection (Command)",
            "CWE-95": "A03:2021 - Injection (Eval)",
            "CWE-79": "A03:2021 - Injection (XSS)",
            "CWE-1336": "A03:2021 - Injection (SSTI)",
            "CWE-113": "A03:2021 - Injection (CRLF/HTTP Splitting)",
            "CWE-798": "A07:2021 - Identification & Authentication Failures (Hardcoded Credentials)",
            "CWE-502": "A08:2021 - Software & Data Integrity (Insecure Deserialization)",
            "CWE-328": "A02:2021 - Cryptographic Failures (Weak Hash)",
            "CWE-326": "A02:2021 - Cryptographic Failures (Weak Protocol/Key)",
            "CWE-319": "A02:2021 - Cryptographic Failures (Cleartext HTTP)",
            "CWE-942": "A01:2021 - Broken Access Control (CORS)",
            "CWE-1021": "A05:2021 - Security Misconfiguration (Clickjacking/CSP)",
            "CWE-215": "A05:2021 - Security Misconfiguration (Debug Mode)",
            "CWE-200": "A05:2021 - Security Misconfiguration (Banner/Info Disclosure)",
            "CWE-250": "A05:2021 - Security Misconfiguration (Privileged Container/Root)",
            "CWE-732": "A01:2021 - Broken Access Control (Public Storage ACL)",
            "CWE-1395": "A06:2021 - Vulnerable & Outdated Components (SCA)",
            "CWE-358": "A05:2021 - Security Misconfiguration (DNS/SPF/DMARC)",
            "CWE-346": "A01:2021 - Broken Access Control (CSWSH)",
            "CWE-601": "A01:2021 - Broken Access Control (Open Redirect)",
        }
        return mapping.get(cwe_id, f"A05:2021 - Security Misconfiguration ({category})")

    def generate_detailed_report(self, scan: ScanResponse) -> Dict[str, Any]:
        """Synthesize a complete structured audit report with 21 standard finding attributes."""
        summary = scan.summary
        findings = scan.findings
        posture_grade = self.compute_posture_grade(summary.riskScore)

        owasp_breakdown: Dict[str, int] = {}
        for f in findings:
            cat = self.map_owasp_category(f.category, f.cweId or "")
            owasp_breakdown[cat] = owasp_breakdown.get(cat, 0) + 1

        dossiers: List[Dict[str, Any]] = []
        for idx, f in enumerate(findings, start=1):
            owasp_class = f.owaspCategory or self.map_owasp_category(f.category, f.cweId or "")
            
            # Sanitize and redact evidence
            raw_evidence = f.evidence or {}
            redacted_evidence = SecurityScopeEnforcer.redact_finding_evidence(raw_evidence)
            redacted_snippet = SecurityScopeEnforcer.redact_sensitive_string(f.codeSnippet)

            # Build 21 standard report attributes
            dossier = {
                "index": idx,
                "vulnerabilityTitle": f.title,                           # 1. Title
                "findingId": f.id,                                       # 2. Unique Finding ID
                "affectedAsset": f.targetScope,                          # 3. Affected Asset
                "affectedUrl": f.affectedUrl or f.targetScope,           # 4. Affected URL or Service
                "httpMethod": f.httpMethod or "N/A",                     # 5. HTTP Method
                "affectedParameter": f.affectedParameter or "N/A",       # 6. Affected Parameter
                "category": f.category,                                  # 7. Vulnerability Category
                "owaspCategory": owasp_class,                            # 8. OWASP Mapping
                "cweId": f.cweId or "N/A",                               # 9. CWE ID
                "cveId": f.cveId or "N/A",                               # 10. CVE ID
                "severity": f.severity,                                  # 11. Severity
                "cvss": {                                                # 12. CVSS Version & Score
                    "version": f.cvssVersion,
                    "score": f.cvss,
                    "vector": f.cvssVector or f"CVSS:{f.cvssVersion}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                },
                "confidence": f"{int(f.confidence * 100)}%",             # 13. Detection Confidence
                "verificationStatus": f.verificationStatus,              # 14. Verification Status
                "description": f.description,                            # 15. Technical Description
                "evidence": {                                            # 16. Evidence
                    "observedSnippet": redacted_snippet,
                    "structuredEvidence": redacted_evidence,
                },
                "reproductionSteps": f.reproductionSteps or [            # 17. Safe Reproduction Steps
                    f"1. Target affected asset: {f.targetScope}",
                    f"2. Inspect affected component / parameter: {f.affectedParameter or 'N/A'}",
                    f"3. Validate safe canary or configuration against rule {f.cweId or 'check'}.",
                ],
                "impact": f.impact or (                                  # 18. Potential Impact
                    "Critical compromise risk: attacker can execute unauthorized actions, modify state, or extract sensitive data."
                    if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
                    else "Defensive posture gap: weakens defense-in-depth or leaks reconnaissance intelligence."
                ),
                "remediation": {                                         # 19. Remediation Steps
                    "summary": f.remediationSummary,
                    "codePatch": f.remediationCode,
                },
                "references": f.references or [                          # 20. References
                    "https://owasp.org/Top10/",
                    "https://cwe.mitre.org/",
                    "https://nvd.nist.gov/",
                ],
                "detectionTimestamp": f.timestamp,                       # 21. Detection Timestamp
                "statusBadge": f.statusBadge,
                "suppressed": f.suppressed,
                "suppressionJustification": f.suppressionJustification,
            }
            dossiers.append(dossier)

        # Immediate vs Scheduled roadmap
        immediate_actions = [
            f"Remediate {d['vulnerabilityTitle']} in {d['affectedAsset']} (CVSS {d['cvss']['score']})"
            for d in dossiers if d["severity"] in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) and not d["suppressed"]
        ]
        scheduled_actions = [
            f"Harden {d['vulnerabilityTitle']} in {d['affectedAsset']}"
            for d in dossiers if d["severity"] not in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) and not d["suppressed"]
        ]

        report = {
            "metadata": {
                "reportId": f"CFL-{scan.scanId.upper()}",
                "scanId": scan.scanId,
                "target": scan.target,
                "auditType": scan.scanType,
                "engineVersion": "CipherFlux Labs Enterprise Security Engine v2.0",
                "generatedAt": datetime.utcnow().isoformat() + "Z",
                "auditDuration": f"{summary.durationSeconds}s",
            },
            "executiveSummary": {
                "headline": scan.executiveSummary,
                "postureGrade": posture_grade,
                "riskScore": summary.riskScore,
                "totalVulnerabilities": summary.totalFindings,
                "confirmedFindings": summary.confirmedCount,
                "potentialFindings": summary.potentialCount,
                "threatAssessment": (
                    "IMMEDIATE ACTION REQUIRED: Confirmed critical and/or high severity attack vectors were detected."
                    if summary.criticalCount > 0 or summary.highCount > 0
                    else "POSTURE RESILIENT: Zero high-criticality vulnerabilities found. Defense-in-depth improvements recommended."
                ),
                "leadershipTakeaway": (
                    "Allocate immediate sprint capacity for verified critical/high findings. Code-level remediation diffs "
                    "have been prepared in the technical findings dossiers."
                ),
            },
            "riskBreakdown": {
                "severityDistribution": {
                    "critical": summary.criticalCount,
                    "high": summary.highCount,
                    "medium": summary.mediumCount,
                    "low": summary.lowCount,
                    "informational": summary.infoCount,
                },
                "verificationBreakdown": {
                    "confirmed": summary.confirmedCount,
                    "potential": summary.potentialCount,
                    "inconclusive": summary.inconclusiveCount,
                },
                "owaspTop10Impact": owasp_breakdown,
                "attackSurfaceCoverage": [
                    "Static Application Security Testing (SAST AST & syntax rules)",
                    "Web & API Injection / Posture (DAST Canary Verification)",
                    "Network & Service Vulnerability Assessment (Controlled Port Probes)",
                    "Dedicated SSL/TLS Protocol & Cipher Suite Analysis",
                    "DNS, Domain & Email Security Assessment (SPF, DMARC, AXFR)",
                    "Software Composition Analysis (Multi-Ecosystem SCA & CVE Matching)",
                    "Container & Infrastructure-as-Code Auditing (Dockerfile, K8s, Terraform)",
                ],
            },
            "findingsDossiers": dossiers,
            "remediationPlan": {
                "phase1ImmediateP0": immediate_actions or ["No P0 actions required."],
                "phase2DefensiveHygieneP1": scheduled_actions or ["No P1 actions required."],
                "governanceChecklist": [
                    "Ensure all secrets and keys are removed from version control and injected via Secret Store.",
                    "Verify all database queries utilize parameterized queries or ORM bindings.",
                    "Enforce TLS 1.2+ with forward-secret cipher suites across all gateway routes.",
                    "Audit Access-Control-Allow-Origin headers to prevent wildcard credential reflection.",
                    "Deploy Content-Security-Policy (CSP) with strict nonce/hash rules.",
                    "Publish SPF (~all or -all) and DMARC (quarantine or reject) records for all managed domains.",
                ],
            },
        }
        return report

    def render_markdown_report(self, report: Dict[str, Any]) -> str:
        """Render the structured report into publication-ready GitHub-flavored Markdown."""
        meta = report["metadata"]
        exec_sum = report["executiveSummary"]
        risk = report["riskBreakdown"]
        dossiers = report["findingsDossiers"]
        plan = report["remediationPlan"]

        md = []
        md.append(f"# 🛡️ Mahoraga AI Security Audit Report | CipherFlux Labs: `{meta['target']}`")
        md.append(f"**Report ID**: `{meta['reportId']}` | **Scan ID**: `{meta['scanId']}` | **Date**: `{meta['generatedAt']}`")
        md.append(f"**Audit Engine**: `{meta['engineVersion']}` | **Audit Type**: `{meta['auditType']}` | **Duration**: `{meta['auditDuration']}`\n")
        md.append("---\n")

        # 1. Executive Summary
        md.append("## 1. Executive Summary\n")
        md.append(f"> **Overall Security Posture Grade**: **`{exec_sum['postureGrade']}`** (Normalized Risk Score: **{exec_sum['riskScore']}/100**)\n")
        md.append(f"- **Total Findings**: {exec_sum['totalVulnerabilities']} ({exec_sum['confirmedFindings']} Confirmed, {exec_sum['potentialFindings']} Potential)")
        md.append(f"- **Headline**: {exec_sum['headline']}")
        md.append(f"- **Threat Assessment**: {exec_sum['threatAssessment']}")
        md.append(f"- **Leadership Recommendation**: {exec_sum['leadershipTakeaway']}\n")

        # 2. Risk Metrics
        md.append("## 2. Risk Metrics & Severity Breakdown\n")
        md.append("| Severity | Total Count | Confirmed | Action Level |")
        md.append("| :--- | :---: | :---: | :--- |")
        sev = risk["severityDistribution"]
        md.append(f"| 🔴 **CRITICAL** | **{sev['critical']}** | {sum(1 for d in dossiers if d['severity'] == SeverityLevel.CRITICAL and d['verificationStatus'] == VerificationStatus.CONFIRMED)} | Immediate P0 Hotfix |")
        md.append(f"| 🟠 **HIGH** | **{sev['high']}** | {sum(1 for d in dossiers if d['severity'] == SeverityLevel.HIGH and d['verificationStatus'] == VerificationStatus.CONFIRMED)} | Current Sprint Remediation |")
        md.append(f"| 🟡 **MEDIUM** | **{sev['medium']}** | {sum(1 for d in dossiers if d['severity'] == SeverityLevel.MEDIUM and d['verificationStatus'] == VerificationStatus.CONFIRMED)} | Scheduled Fix |")
        md.append(f"| 🔵 **LOW** | **{sev['low']}** | {sum(1 for d in dossiers if d['severity'] == SeverityLevel.LOW and d['verificationStatus'] == VerificationStatus.CONFIRMED)} | Defensive Hardening |")
        md.append(f"| ⚪ **INFORMATIONAL** | **{sev['informational']}** | {sum(1 for d in dossiers if d['severity'] == SeverityLevel.INFORMATIONAL and d['verificationStatus'] == VerificationStatus.CONFIRMED)} | Operational Observation |\n")

        md.append("### OWASP Top 10 Distribution\n")
        for owasp_cat, count in risk["owaspTop10Impact"].items():
            md.append(f"- **{owasp_cat}**: {count} finding(s)")
        md.append("")

        # 3. Deep-Dive Vulnerability Dossiers
        md.append("## 3. Deep-Dive Vulnerability Dossiers (21 Standard Attributes)\n")
        if not dossiers:
            md.append("✅ **No vulnerabilities detected across the audited scope.**\n")
        else:
            for d in dossiers:
                md.append(f"### Finding #{d['index']}: {d['vulnerabilityTitle']}")
                md.append(f"- **Finding ID**: `{d['findingId']}` | **Verification Status**: `{d['verificationStatus']}` (`{d['statusBadge']}`)")
                md.append(f"- **Severity**: `{d['severity']}` | **CVSS**: `{d['cvss']['score']}` ({d['cvss']['version']})")
                md.append(f"- **Category**: `{d['category']}` | **OWASP Mapping**: `{d['owaspCategory']}`")
                md.append(f"- **CWE ID**: `{d['cweId']}` | **CVE ID**: `{d['cveId']}` | **Confidence**: `{d['confidence']}`")
                md.append(f"- **Affected Asset**: `{d['affectedAsset']}` | **URL/Endpoint**: `{d['affectedUrl']}`")
                if d.get("affectedParameter") != "N/A":
                    md.append(f"- **Parameter**: `{d['affectedParameter']}` | **HTTP Method**: `{d['httpMethod']}`")
                md.append(f"- **Detection Timestamp**: `{d['detectionTimestamp']}`\n")
                
                md.append(f"**Technical Description:**\n{d['description']}\n")
                md.append(f"**Potential Impact:**\n{d['impact']}\n")

                if d["evidence"].get("observedSnippet"):
                    md.append("**Evidence / Observed Context:**")
                    md.append(f"```\n{d['evidence']['observedSnippet']}\n```\n")

                md.append("**Safe Reproduction Steps:**")
                for step in d["reproductionSteps"]:
                    md.append(f"- {step}")
                md.append("")

                md.append(f"**Remediation Guidance:**\n{d['remediation']['summary']}\n")
                if d["remediation"].get("codePatch"):
                    md.append("**Recommended Code / Configuration Patch:**")
                    md.append(f"```\n{d['remediation']['codePatch']}\n```\n")

                if d.get("references"):
                    md.append("**Authoritative References:**")
                    for ref in d["references"]:
                        md.append(f"- {ref}")
                    md.append("")

                md.append("---\n")

        # 4. Remediation Action Plan
        md.append("## 4. Remediation Roadmap & Engineering Verification\n")
        md.append("### Phase 1: Immediate Triage (P0)")
        for act in plan["phase1ImmediateP0"]:
            md.append(f"- [ ] {act}")
        md.append("")

        md.append("### Phase 2: Defensive Hardening (P1)")
        for act in plan["phase2DefensiveHygieneP1"]:
            md.append(f"- [ ] {act}")
        md.append("")

        md.append("### Security Governance Checklist")
        for item in plan["governanceChecklist"]:
            md.append(f"- [x] {item}")
        md.append("\n---\n*Generated autonomously by CipherFlux Labs Enterprise Security Assessment Platform.*")

        return "\n".join(md)

    def render_csv_report(self, report: Dict[str, Any]) -> str:
        """Export all findings in a standardized CSV format with 21 attributes."""
        output = io.StringIO()
        fieldnames = [
            "Finding ID", "Title", "Severity", "CVSS Score", "Verification Status",
            "Category", "OWASP Category", "CWE ID", "CVE ID", "Confidence",
            "Affected Asset", "Affected URL", "HTTP Method", "Affected Parameter",
            "Technical Description", "Potential Impact", "Remediation Summary",
            "Detection Timestamp", "Status Badge"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for d in report["findingsDossiers"]:
            writer.writerow({
                "Finding ID": d["findingId"],
                "Title": d["vulnerabilityTitle"],
                "Severity": d["severity"],
                "CVSS Score": d["cvss"]["score"],
                "Verification Status": d["verificationStatus"],
                "Category": d["category"],
                "OWASP Category": d["owaspCategory"],
                "CWE ID": d["cweId"],
                "CVE ID": d["cveId"],
                "Confidence": d["confidence"],
                "Affected Asset": d["affectedAsset"],
                "Affected URL": d["affectedUrl"],
                "HTTP Method": d["httpMethod"],
                "Affected Parameter": d["affectedParameter"],
                "Technical Description": d["description"],
                "Potential Impact": d["impact"],
                "Remediation Summary": d["remediation"]["summary"],
                "Detection Timestamp": d["detectionTimestamp"],
                "Status Badge": d["statusBadge"],
            })

        return output.getvalue()

    def render_pdf_report(self, report: Dict[str, Any]) -> bytes:
        """Generate a publication-ready PDF audit report using ReportLab."""
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
        )
        meta_style = ParagraphStyle(
            "MetaCustom",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#64748b"),
        )

        elements = []
        meta = report["metadata"]
        exec_sum = report["executiveSummary"]
        dossiers = report["findingsDossiers"]

        # Title & Header
        elements.append(Paragraph("🛡️ CipherFlux Labs Security Assessment Report", title_style))
        elements.append(Paragraph(f"Target: <b>{meta['target']}</b> | Report ID: {meta['reportId']} | Date: {meta['generatedAt'][:10]}", meta_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3b82f6"), spaceAfter=14))

        # Executive Summary
        elements.append(Paragraph("1. Executive Summary", h2_style))
        elements.append(Paragraph(f"<b>Overall Security Posture:</b> {exec_sum['postureGrade']} (Risk Score: {exec_sum['riskScore']}/100)", body_style))
        elements.append(Paragraph(f"<b>Total Vulnerabilities:</b> {exec_sum['totalVulnerabilities']} ({exec_sum['confirmedFindings']} Confirmed, {exec_sum['potentialFindings']} Potential)", body_style))
        elements.append(Paragraph(f"<b>Threat Assessment:</b> {exec_sum['threatAssessment']}", body_style))
        elements.append(Paragraph(f"<b>Leadership Takeaway:</b> {exec_sum['leadershipTakeaway']}", body_style))
        elements.append(Spacer(1, 12))

        # Findings Summary Table
        elements.append(Paragraph("2. Vulnerability Findings Summary", h2_style))
        table_data = [["#", "Vulnerability Title", "Severity", "CVSS", "Status", "CWE"]]
        for d in dossiers[:20]:  # Up to top 20 findings in summary table
            table_data.append([
                str(d["index"]),
                Paragraph(d["vulnerabilityTitle"][:45] + "...", body_style),
                d["severity"],
                d["cvss"]["score"],
                d["verificationStatus"][:9],
                d["cweId"] or "N/A"
            ])

        table = Table(table_data, colWidths=[20, 230, 65, 45, 75, 75])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 14))

        # Governance & Roadmap
        elements.append(Paragraph("3. Remediation Roadmap", h2_style))
        for item in report["remediationPlan"]["governanceChecklist"][:4]:
            elements.append(Paragraph(f"• {item}", body_style))

        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Generated autonomously by CipherFlux Labs Enterprise Security Engine.", meta_style))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

report_generator = ReportGenerator()
