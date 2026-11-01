from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    NOT_TESTED = "NOT_TESTED"

class ScanType(str, Enum):
    CODE = "CODE_SAST"
    ENDPOINT = "ENDPOINT_DAST"
    DEPENDENCIES = "DEPENDENCIES_SCA"
    NETWORK = "NETWORK_ASSESSMENT"
    DNS = "DNS_DOMAIN_ASSESSMENT"
    CONTAINER_IAC = "CONTAINER_IAC_AUDIT"
    API = "API_SECURITY_AUDIT"
    FULL = "FULL_AUDIT"

class SecurityFinding(BaseModel):
    # 21 Standard Report Attributes compliant with Enterprise Vulnerability Management
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Vulnerability Title / Short descriptive name")
    severity: SeverityLevel = Field(..., description="Calibrated risk severity rating")
    category: str = Field(..., description="Vulnerability category (e.g. Injection, Broken Access Control, Cryptography)")
    targetScope: str = Field(..., description="Affected Asset / Target scope path or host")
    
    # Target specifics
    affectedUrl: Optional[str] = Field(None, description="Affected URL or Service endpoint")
    httpMethod: Optional[str] = Field(None, description="HTTP Method if applicable (GET, POST, etc.)")
    affectedParameter: Optional[str] = Field(None, description="Affected Parameter or Header name")
    lineNumber: Optional[int] = Field(None, description="Line number if applicable (SAST / SCA)")
    codeSnippet: Optional[str] = Field(None, description="Affected snippet, request/response header, or banner")
    
    # Standards & Metrics
    cvss: str = Field("0.0", description="CVSS base score (e.g. 8.5)")
    cvssVersion: str = Field("3.1", description="CVSS version ('3.1' or '4.0')")
    cvssVector: Optional[str] = Field(None, description="Full CVSS vector string")
    cweId: Optional[str] = Field(None, description="Common Weakness Enumeration ID (e.g. CWE-89)")
    cveId: Optional[str] = Field(None, description="Known CVE ID if applicable (e.g. CVE-2023-45803)")
    owaspCategory: Optional[str] = Field(None, description="OWASP Top 10 Mapping (e.g. A01:2021-Broken Access Control)")
    
    # Evidence & Verification
    verificationStatus: VerificationStatus = Field(VerificationStatus.POTENTIAL, description="Evidence verification status")
    confidence: float = Field(0.95, description="Detection confidence score from 0.0 to 1.0 (calibrated, not fabricated)")
    description: str = Field(..., description="Detailed technical description of the vulnerability")
    impact: Optional[str] = Field(None, description="Potential technical and business impact")
    remediationSummary: str = Field(..., description="High-level guidance for remediation")
    remediationCode: Optional[str] = Field(None, description="Suggested code-level patch or configuration fix")
    reproductionSteps: Optional[List[str]] = Field(default_factory=list, description="Safe reproduction steps")
    references: Optional[List[str]] = Field(default_factory=list, description="Authoritative reference URLs (NIST, OWASP, RFC)")
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Structured reproducible evidence (payloads, canaries, baseline diff)")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z", description="Detection timestamp")
    
    # UI and Triage Badges
    statusBadge: str = Field("ACTIVE FINDING", description="Display badge (e.g. VERIFIED, POTENTIAL, PROBE)")
    suppressed: bool = Field(False, description="Whether finding has been suppressed by policy")
    suppressionJustification: Optional[str] = Field(None, description="Documented justification for suppression")

class ScanSummary(BaseModel):
    totalFindings: int = 0
    confirmedCount: int = 0
    potentialCount: int = 0
    inconclusiveCount: int = 0
    criticalCount: int = 0
    highCount: int = 0
    mediumCount: int = 0
    lowCount: int = 0
    infoCount: int = 0
    riskScore: float = Field(0.0, description="Normalized score 0.0 to 100.0")
    durationSeconds: float = 0.0

class CodeScanRequest(BaseModel):
    targetPath: Optional[str] = Field(None, description="Local folder or file to scan (defaults to workspace)")
    rawCode: Optional[str] = Field(None, description="Direct code string for instant snippet inspection")
    language: Optional[str] = Field("auto", description="Programming language (python, javascript, etc.)")
    maxFiles: int = Field(500, description="Max files to scan to prevent resource exhaustion")
    authorizedBy: Optional[str] = Field("operator", description="Explicit security authorization confirmation")

class EndpointScanRequest(BaseModel):
    targetUrl: str = Field(..., description="Web or API URL to audit (e.g. https://target.internal)")
    checkCors: bool = Field(True, description="Analyze Cross-Origin Resource Sharing policies")
    checkHeaders: bool = Field(True, description="Verify defensive security headers (CSP, HSTS, etc.)")
    checkSsl: bool = Field(True, description="Audit TLS protocols and certificate posture")
    checkInjection: bool = Field(True, description="Execute safe canary checks for injection vectors")
    timeoutSeconds: float = Field(8.0, description="HTTP timeout for target probe")
    authorizedBy: Optional[str] = Field("operator", description="Explicit authorization confirmation")

class DependencyScanRequest(BaseModel):
    manifestPath: Optional[str] = Field(None, description="Path to manifest file")
    manifestContent: Optional[str] = Field(None, description="Raw manifest file string")
    manifestType: Optional[str] = Field("npm", description="'npm', 'pip', 'cargo', 'go', 'maven', or 'composer'")
    authorizedBy: Optional[str] = Field("operator", description="Explicit authorization confirmation")

class NetworkScanRequest(BaseModel):
    targetHost: str = Field(..., description="Target hostname or IP address to assess")
    ports: Optional[List[int]] = Field(None, description="Specific ports to audit (defaults to common service ports)")
    timeoutSeconds: float = Field(4.0, description="Socket connection timeout")
    authorizedBy: Optional[str] = Field("operator", description="Explicit authorization confirmation")

class DnsScanRequest(BaseModel):
    domain: str = Field(..., description="Domain name to assess (e.g. example.com)")
    checkZoneTransfer: bool = Field(True, description="Test safe AXFR zone transfer posture")
    checkMailRecords: bool = Field(True, description="Audit SPF, DMARC, and DKIM configuration")
    checkTakeover: bool = Field(True, description="Identify dangling DNS / subdomain takeover indicators")
    authorizedBy: Optional[str] = Field("operator", description="Explicit authorization confirmation")

class IaCScanRequest(BaseModel):
    targetPath: Optional[str] = Field(None, description="Local directory or file path for IaC configs")
    rawContent: Optional[str] = Field(None, description="Raw Dockerfile, Kubernetes YAML, or Terraform content")
    fileType: str = Field("dockerfile", description="'dockerfile', 'kubernetes', or 'terraform'")
    authorizedBy: Optional[str] = Field("operator", description="Explicit authorization confirmation")

class ApiScanRequest(BaseModel):
    targetUrl: str = Field(..., description="API endpoint root URL")
    apiType: str = Field("rest", description="'rest', 'graphql', or 'websocket'")
    headers: Optional[Dict[str, str]] = Field(default_factory=dict, description="Authorized API authentication headers")
    checkIntrospection: bool = Field(True, description="Check GraphQL introspection and schema exposure")
    checkRateLimit: bool = Field(True, description="Analyze rate limiting and resource throttling headers")
    authorizedBy: Optional[str] = Field("operator", description="Explicit authorization confirmation")

class ScanResponse(BaseModel):
    scanId: str
    target: str
    scanType: ScanType
    status: str = "COMPLETED"
    createdAt: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    summary: ScanSummary
    findings: List[SecurityFinding]
    executiveSummary: str

class AgentQueryRequest(BaseModel):
    query: str = Field(..., description="Natural language prompt or voice command for CipherFlux Security Analyst")
    scanId: Optional[str] = Field(None, description="Optional scan reference for context")
    contextFilter: Optional[str] = Field(None, description="Optional focus (e.g. 'high-risk', 'remediation')")

class AgentQueryResponse(BaseModel):
    id: str
    query: str
    simulatedAgentResponse: str
    reasoningVector: str
    suggestedActions: List[str] = []
    relevantFindings: List[SecurityFinding] = []

class SubsystemStatusModel(BaseModel):
    name: str
    designation: str
    status: str
    phase: str
    progressPercent: int
    note: str

class RuleDefinitionModel(BaseModel):
    ruleId: str
    ruleName: str
    category: str
    cweId: Optional[str] = None
    defaultSeverity: SeverityLevel
    cvssBase: str
    description: str
    detectionLogic: str
    requiredEvidence: str
    verificationLogic: str
    falsePositiveConditions: str
    remediationGuidance: str
    references: List[str] = []

class VulnerabilityCoverageItem(BaseModel):
    category: str
    engine: str
    status: str  # "DETECTED", "CONFIRMED", "POTENTIAL", "NOT_DETECTED", "NOT_TESTED"
    checksCount: int
    notes: str
