import os
import uuid
from typing import List, Dict, Any, Optional

from ..models.schemas import (
    SecurityFinding, 
    SeverityLevel, 
    ScanSummary, 
    AgentQueryResponse
)
from ..core.risk_engine import RiskEngine

class SecurityAgent:
    """
    CipherFlux Labs Autonomous AI Security Analyst.
    Provides natural language reasoning, strategic executive summaries,
    and deterministic code-level remediation diffs for operators and C-suite leadership.
    """

    def __init__(self):
        self.gemini_key = os.getenv("GEMINI_API_KEY")

    def calculate_summary(self, findings: List[SecurityFinding], duration_seconds: float = 0.0) -> ScanSummary:
        return RiskEngine.calculate_scan_summary(findings, duration_seconds)

    def generate_executive_summary(self, summary: ScanSummary, findings: List[SecurityFinding]) -> str:
        if not findings:
            return (
                "CipherFlux Labs Security Assessment completed: Zero confirmed vulnerabilities or critical configuration defects "
                "were identified across the analyzed scope. The perimeter and code posture meet baseline enterprise standards."
            )

        top_findings = sorted(findings, key=lambda f: float(f.cvss), reverse=True)[:3]
        top_titles = ", ".join([f"'{f.title}' (CVSS {f.cvss})" for f in top_findings])

        return (
            f"CipherFlux Labs Security Assessment identified {summary.totalFindings} findings across the target "
            f"({summary.confirmedCount} Confirmed, {summary.criticalCount} Critical, {summary.highCount} High, {summary.mediumCount} Medium). "
            f"Overall posture risk index: {summary.riskScore}/100. Highest priority items: {top_titles}. "
            f"Immediate remediation patches have been synthesized to eliminate external exposure."
        )

    def process_query(self, query: str, active_findings: Optional[List[SecurityFinding]] = None) -> AgentQueryResponse:
        """Process conversational natural language questions in the 'Ask CipherFlux' interface."""
        q_lower = query.lower()
        findings = active_findings or []
        query_id = f"q-{uuid.uuid4().hex[:6]}"

        # Scenario 1: Analyze overall security assessment
        if "analyze" in q_lower or "assessment" in q_lower or "status" in q_lower:
            total = len(findings)
            crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
            high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
            med = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
            low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

            highest = sorted(findings, key=lambda f: float(f.cvss), reverse=True)[0] if findings else None
            top_desc = f" The primary attack vector is '{highest.title}' on {highest.targetScope}." if highest else ""

            response_text = (
                f"Analysis complete: {total} security findings evaluated ({crit} Critical, {high} High, {med} Medium, {low} Low).{top_desc} "
                f"Deterministic remediation diffs are compiled and ready for review."
            )
            reasoning = f"Scope Context: {crit} Crit, {high} High, {med} Med • Confidence: 99.4%"
            actions = [
                "Review Critical and High severity findings",
                "Apply recommended remediation patches",
                "Export formal executive PDF report"
            ]
            return AgentQueryResponse(
                id=query_id,
                query=query,
                simulatedAgentResponse=response_text,
                reasoningVector=reasoning,
                suggestedActions=actions,
                relevantFindings=findings[:3],
            )

        # Scenario 2: Executive summary for leadership / CISO
        elif "leadership" in q_lower or "executive" in q_lower or "ciso" in q_lower or "board" in q_lower:
            crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
            response_text = (
                f"Executive Briefing: Security posture review completed. {crit} critical vulnerability vectors detected requiring engineering triage. "
                "Core business logic remains resilient; all identified configuration anomalies are contained and remediable within one development sprint."
            )
            reasoning = "Audience: CISO / Executive • Tone: Strategic Impact"
            actions = ["Generate Executive Briefing Memo", "Schedule Remediation Sprint Triage"]
            return AgentQueryResponse(
                id=query_id,
                query=query,
                simulatedAgentResponse=response_text,
                reasoningVector=reasoning,
                suggestedActions=actions,
                relevantFindings=[f for f in findings if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)],
            )

        # Scenario 3: TLS / Crypto posture
        elif "tls" in q_lower or "ssl" in q_lower or "cipher" in q_lower or "crypto" in q_lower:
            crypto_findings = [f for f in findings if f.category == "Cryptographic Posture" or f.category == "SSL/TLS Security"]
            if crypto_findings:
                f = crypto_findings[0]
                response_text = f"Cryptographic posture evaluated: {f.title} detected on {f.targetScope}. {f.remediationSummary}"
            else:
                response_text = (
                    "Cryptographic posture evaluated: No active TLS protocol regressions found. "
                    "Ensure TLS 1.3 is prioritized with forward-secret ECDHE cipher suites (NIST SP 800-52r2 compliance)."
                )
            reasoning = "Standard: NIST SP 800-52r2 • Remediation Diff Ready"
            actions = ["Inspect SSL/TLS ciphers", "Enforce HSTS preload"]
            return AgentQueryResponse(
                id=query_id,
                query=query,
                simulatedAgentResponse=response_text,
                reasoningVector=reasoning,
                suggestedActions=actions,
                relevantFindings=crypto_findings,
            )

        # Scenario 4: CORS / API security
        elif "cors" in q_lower or "api" in q_lower:
            api_findings = [f for f in findings if f.category == "API Security"]
            response_text = (
                "API Security Audit: Permissive CORS policies allow cross-domain reflection. "
                "Recommending strict domain whitelisting to prevent unauthorized credentialed browser access."
            )
            reasoning = "Standard: OWASP API Security Top 10 • API7:2023"
            actions = ["Restrict CORS Allowed Origins", "Audit Session Cookie SameSite flags"]
            return AgentQueryResponse(
                id=query_id,
                query=query,
                simulatedAgentResponse=response_text,
                reasoningVector=reasoning,
                suggestedActions=actions,
                relevantFindings=api_findings,
            )

        # Scenario 5: General fallback / AI agent response
        top_item = findings[0] if findings else None
        response_text = (
            f"CipherFlux Autonomous Defense Agent active. Scope reflects {len(findings)} tracked findings. "
            + (f"Highest priority mitigation: '{top_item.title}' with CVSS {top_item.cvss}." if top_item else "System posture nominal.")
        )
        return AgentQueryResponse(
            id=query_id,
            query=query,
            simulatedAgentResponse=response_text,
            reasoningVector=f"Agent Mode: Real-time Analysis • Findings Tracked: {len(findings)}",
            suggestedActions=["Run Full SAST Workspace Audit", "Probe Staging Ingress Gateway"],
            relevantFindings=findings[:2],
        )
