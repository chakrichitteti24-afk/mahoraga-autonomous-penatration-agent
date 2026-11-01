from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from ..models.schemas import (
    SecurityFinding,
    SeverityLevel,
    VerificationStatus,
    RuleDefinitionModel,
)

@dataclass
class DetectionRule:
    rule_id: str
    rule_name: str
    category: str
    cwe_id: str
    default_severity: SeverityLevel
    cvss_base: str
    description: str
    detection_logic: str
    required_evidence: str
    verification_logic: str
    false_positive_conditions: str
    remediation_guidance: str
    references: List[str] = field(default_factory=list)

class RuleRegistry:
    """Central registry of authoritative, evidence-driven security detection rules."""
    def __init__(self):
        self._rules: Dict[str, DetectionRule] = {}
        self._register_default_rules()

    def register(self, rule: DetectionRule):
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Optional[DetectionRule]:
        return self._rules.get(rule_id)

    def list_all(self) -> List[DetectionRule]:
        return list(self._rules.values())

    def to_models(self) -> List[RuleDefinitionModel]:
        return [
            RuleDefinitionModel(
                ruleId=r.rule_id,
                ruleName=r.rule_name,
                category=r.category,
                cweId=r.cwe_id,
                defaultSeverity=r.default_severity,
                cvssBase=r.cvss_base,
                description=r.description,
                detectionLogic=r.detection_logic,
                requiredEvidence=r.required_evidence,
                verificationLogic=r.verification_logic,
                falsePositiveConditions=r.false_positive_conditions,
                remediationGuidance=r.remediation_guidance,
                references=r.references,
            )
            for r in self._rules.values()
        ]

    def _register_default_rules(self):
        rules = [
            DetectionRule(
                rule_id="CFL-SQLI-001",
                rule_name="SQL Injection Indicator",
                category="Injection Vulnerabilities",
                cwe_id="CWE-89",
                default_severity=SeverityLevel.CRITICAL,
                cvss_base="9.3",
                description="Application reflects SQL syntax errors or differentiates responses based on Boolean canary conditions.",
                detection_logic="Probe target parameter with non-destructive arithmetic and syntax markers (' OR 1=1 vs ' OR 1=2).",
                required_evidence="Differential response code, distinct body lengths, or database syntax error message signature.",
                verification_logic="Establish baseline HTTP response, execute balanced query pair, verify differential behavior.",
                false_positive_conditions="Generic 500 error pages triggered by unhandled non-numeric input without SQL-specific evidence.",
                remediation_guidance="Use parameterized queries (prepared statements) or Object-Relational Mapping (ORM) query builders.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
            ),
            DetectionRule(
                rule_id="CFL-XSS-001",
                rule_name="Cross-Site Scripting (XSS) Reflection",
                category="Cross-Site Scripting",
                cwe_id="CWE-79",
                default_severity=SeverityLevel.HIGH,
                cvss_base="7.5",
                description="User input is reflected in HTML document context without contextual output encoding.",
                detection_logic="Inject benign unique canary token with HTML delimiter characters (<cf_probe_id>).",
                required_evidence="Unencoded reflection of delimiter characters inside renderable HTML context.",
                verification_logic="Verify token reflection in response body while ensuring Content-Type is text/html or application/xhtml.",
                false_positive_conditions="Reflection inside JSON APIs, text/plain responses, or properly HTML-entity-encoded output.",
                remediation_guidance="Apply context-aware output encoding (HTML, JavaScript, Attribute) and enforce Content-Security-Policy.",
                references=["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
            ),
            DetectionRule(
                rule_id="CFL-CORS-001",
                rule_name="Permissive CORS Policy with Credentials",
                category="Security Misconfigurations",
                cwe_id="CWE-942",
                default_severity=SeverityLevel.CRITICAL,
                cvss_base="8.8",
                description="Server dynamically reflects untrusted origin and allows credentials in cross-origin requests.",
                detection_logic="Send OPTIONS and GET with external and null Origin headers.",
                required_evidence="Access-Control-Allow-Origin matching injected origin combined with Access-Control-Allow-Credentials: true.",
                verification_logic="Verify that response headers reflect injected external origin and allow credentials simultaneously.",
                false_positive_conditions="Access-Control-Allow-Origin: * without credentials enabled on public APIs.",
                remediation_guidance="Implement server-side origin whitelisting; never reflect incoming Origin headers with credentials.",
                references=["https://portswigger.net/web-security/cors", "https://cwe.mitre.org/data/definitions/942.html"],
            ),
            DetectionRule(
                rule_id="CFL-TLS-001",
                rule_name="Obsolete TLS Protocol / Insecure Ciphers",
                category="SSL/TLS Security",
                cwe_id="CWE-326",
                default_severity=SeverityLevel.HIGH,
                cvss_base="7.4",
                description="Server negotiates deprecated TLS 1.0/1.1 or broken cipher suites (RC4, 3DES, EXPORT).",
                detection_logic="Execute direct TLS socket handshake negotiation across protocol matrix.",
                required_evidence="Successful TLS handshake negotiated using SSLv2, SSLv3, TLSv1.0, TLSv1.1, or deprecated cipher.",
                verification_logic="Socket handshake confirmed at cryptographic layer via OpenSSL/Python SSL context.",
                false_positive_conditions="Port redirecting plain HTTP or non-SSL protocol error.",
                remediation_guidance="Enforce TLS 1.2 minimum and enable modern AEAD ciphers (AES-GCM, CHACHA20-POLY1305).",
                references=["https://datatracker.ietf.org/doc/html/rfc8996", "https://cwe.mitre.org/data/definitions/326.html"],
            ),
            DetectionRule(
                rule_id="CFL-SCA-001",
                rule_name="Known Vulnerable Third-Party Dependency",
                category="Software Composition Analysis",
                cwe_id="CWE-1395",
                default_severity=SeverityLevel.HIGH,
                cvss_base="8.1",
                description="Application includes a package with a documented CVE and known fixed version.",
                detection_logic="Parse dependency manifest and verify package name and version range against vulnerability advisories.",
                required_evidence="Exact package name and version confirmed within documented affected version interval.",
                verification_logic="Cross-reference advisory database (NVD/OSV/GitHub Advisories) and verify fixed release availability.",
                false_positive_conditions="Transitive dependencies excluded by lockfile or vendored patched copies.",
                remediation_guidance="Upgrade package to specified fixed version or apply vendor security backport.",
                references=["https://osv.dev", "https://nvd.nist.gov"],
            ),
            DetectionRule(
                rule_id="CFL-SSRF-001",
                rule_name="Server-Side Request Forgery Indicator",
                category="Server-Side Vulnerabilities",
                cwe_id="CWE-918",
                default_severity=SeverityLevel.CRITICAL,
                cvss_base="9.1",
                description="Application fetches or redirects requests to backend services based on user-supplied URL parameters.",
                detection_logic="Supply safe benign canary domain to URL parameters and observe backend behavior.",
                required_evidence="Differential response latency, connection callback, or internal proxy error banners.",
                verification_logic="Compare baseline parameter response with canary URL parameter response.",
                false_positive_conditions="Static parameter values ignored by backend or validated against strict domain whitelist.",
                remediation_guidance="Restrict outbound network calls, enforce strict domain allowlists, and block loopback/metadata IP ranges.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
            ),
            DetectionRule(
                rule_id="CFL-AUTH-001",
                rule_name="Missing Authentication / Authorization on Endpoint",
                category="Authentication and Authorization",
                cwe_id="CWE-306",
                default_severity=SeverityLevel.HIGH,
                cvss_base="8.2",
                description="Administrative or sensitive resource accessible without valid authentication token or credentials.",
                detection_logic="Issue request without Authorization header or cookies to protected routes.",
                required_evidence="HTTP 200 OK status containing private resource data instead of HTTP 401 or 403.",
                verification_logic="Compare authenticated response with unauthenticated request response on the same resource.",
                false_positive_conditions="Public endpoints intentionally configured for anonymous access.",
                remediation_guidance="Enforce mandatory authentication middleware across all non-public routes.",
                references=["https://cwe.mitre.org/data/definitions/306.html"],
            ),
            DetectionRule(
                rule_id="CFL-SECR-001",
                rule_name="Hardcoded Secret or Cryptographic Credential",
                category="Information Disclosure",
                cwe_id="CWE-798",
                default_severity=SeverityLevel.CRITICAL,
                cvss_base="9.1",
                description="Cryptographic key, API token, or database password committed into source code or configuration.",
                detection_logic="Pattern matching and entropy analysis across source files, configs, and environment files.",
                required_evidence="Matches verified high-entropy credential signature (e.g. AWS Key, PEM private key).",
                verification_logic="Check file context, exclude sample/dummy test tokens (e.g. 'EXAMPLE', '123456').",
                false_positive_conditions="Explicit dummy mock values in test fixtures or documentation files.",
                remediation_guidance="Store secrets in environment variables or an enterprise secret store; immediately rotate exposed keys.",
                references=["https://cwe.mitre.org/data/definitions/798.html"],
            ),
        ]
        for rule in rules:
            self.register(rule)

rule_registry = RuleRegistry()

class FalsePositiveEngine:
    """
    Evaluates suspected findings, eliminates duplicate entries,
    compares against baseline responses, and manages suppression policies.
    """

    def __init__(self, registry: RuleRegistry = rule_registry):
        self.registry = registry

    def deduplicate(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Eliminate duplicate findings with identical target, parameter, and CWE."""
        seen_keys = set()
        deduped = []
        for f in findings:
            key = f"{f.targetScope}|{f.cweId or f.category}|{f.affectedParameter or ''}|{f.title}"
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)
        return deduped

    def calibrate_confidence(self, finding: SecurityFinding) -> float:
        """
        Calibrate confidence score based on verified evidence completeness.
        Never fabricate confidence: calibrate based on observable artifacts.
        """
        score = 0.50

        # Evidence indicators
        evidence = finding.evidence or {}
        if "responseStatus" in evidence:
            score += 0.10
        if "observedDiff" in evidence:
            score += 0.15
        if "canaryToken" in evidence and evidence.get("canaryMatched"):
            score += 0.20
        if finding.verificationStatus == VerificationStatus.CONFIRMED:
            score = max(score, 0.95)
        elif finding.verificationStatus == VerificationStatus.NOT_TESTED:
            score = 0.20
        elif finding.verificationStatus == VerificationStatus.INCONCLUSIVE:
            score = 0.40

        # Adjust for test mock patterns
        if finding.codeSnippet and ("EXAMPLE" in finding.codeSnippet or "test_key" in finding.codeSnippet):
            score = max(0.1, score - 0.3)

        return round(min(1.0, max(0.05, score)), 2)

    def suppress_finding(
        self,
        finding: SecurityFinding,
        justification: str,
        operator_name: str = "security_lead"
    ) -> SecurityFinding:
        """Apply documented suppression with audit justification."""
        finding.suppressed = True
        finding.suppressionJustification = f"Suppressed by {operator_name} at {datetime.utcnow().isoformat()}Z: {justification}"
        finding.statusBadge = "SUPPRESSED (DOCUMENTED)"
        return finding
