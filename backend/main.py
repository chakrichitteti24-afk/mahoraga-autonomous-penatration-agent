import time
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from .config import settings
from .models.schemas import (
    CodeScanRequest,
    EndpointScanRequest,
    DependencyScanRequest,
    NetworkScanRequest,
    DnsScanRequest,
    IaCScanRequest,
    ApiScanRequest,
    ScanResponse,
    ScanType,
    ScanSummary,
    SecurityFinding,
    VerificationStatus,
    AgentQueryRequest,
    AgentQueryResponse,
    SubsystemStatusModel,
    RuleDefinitionModel,
    VulnerabilityCoverageItem,
)
from .scanners.sast_scanner import SASTScanner
from .scanners.web_scanner import WebPostureScanner
from .scanners.sca_scanner import SCAScanner
from .scanners.network_scanner import NetworkScanner
from .scanners.dns_scanner import DNSDomainScanner
from .scanners.api_scanner import APISecurityScanner
from .scanners.iac_scanner import IaCScanner
from .agent.security_agent import SecurityAgent
from .storage.memory_store import scan_store
from .reporting.report_generator import report_generator
from .core.verification_engine import VerificationEngine
from .core.false_positive_engine import FalsePositiveEngine, rule_registry
from .core.safety import SecurityScopeEnforcer

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Backend API for CipherFlux Labs Enterprise-Grade Vulnerability Assessment Platform",
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Engine Singletons
sast_engine = SASTScanner()
web_engine = WebPostureScanner(timeout_seconds=settings.default_request_timeout)
sca_engine = SCAScanner()
network_engine = NetworkScanner(timeout=settings.default_request_timeout)
dns_engine = DNSDomainScanner(timeout=settings.default_request_timeout)
api_engine = APISecurityScanner(timeout=settings.default_request_timeout)
iac_engine = IaCScanner()
agent_engine = SecurityAgent()
verification_engine = VerificationEngine(timeout_seconds=settings.default_request_timeout)
fp_engine = FalsePositiveEngine(registry=rule_registry)

@app.get("/api/health")
async def health_check():
    """Health check endpoint and active engine telemetry."""
    return {
        "status": "ONLINE",
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "activeEngines": [
            "SAST_AST",
            "WEB_POSTURE_DAST",
            "DEPENDENCY_SCA",
            "NETWORK_ASSESSMENT",
            "DNS_SECURITY",
            "API_SECURITY_AUDIT",
            "CONTAINER_IAC_AUDIT",
            "VERIFICATION_ENGINE",
            "FALSE_POSITIVE_FILTER",
            "AGENT_REASONING",
        ],
    }

@app.get("/api/subsystems", response_model=List[SubsystemStatusModel])
async def get_subsystems():
    """Returns real-time status of CipherFlux Labs architecture modules."""
    return scan_store.get_subsystem_status()

@app.get("/api/rules", response_model=List[RuleDefinitionModel])
async def list_rules():
    """Catalog of registered, evidence-driven security detection rules."""
    return rule_registry.to_models()

@app.get("/api/coverage", response_model=List[VulnerabilityCoverageItem])
async def get_coverage_matrix():
    """Matrix of covered vulnerability categories, verification status, and supported engines."""
    return [
        VulnerabilityCoverageItem(
            category="Injection Vulnerabilities",
            engine="SAST + DAST",
            status="CONFIRMED",
            checksCount=14,
            notes="SQLi, OS Command, SSTI, XPath, LDAP, CRLF, Code Injection",
        ),
        VulnerabilityCoverageItem(
            category="Cross-Site Scripting (XSS)",
            engine="SAST + DAST",
            status="CONFIRMED",
            checksCount=6,
            notes="Reflected XSS, DOM injection, dangerouslySetInnerHTML, contextual escaping",
        ),
        VulnerabilityCoverageItem(
            category="Broken Access Control & IDOR",
            engine="API + DAST",
            status="CONFIRMED",
            checksCount=8,
            notes="CORS wildcard reflection with credentials, CSWSH, excessive exposure",
        ),
        VulnerabilityCoverageItem(
            category="Authentication & Session",
            engine="DAST + SAST",
            status="CONFIRMED",
            checksCount=10,
            notes="Cookie flags (HttpOnly, Secure, SameSite), cleartext HTTP, hardcoded secrets",
        ),
        VulnerabilityCoverageItem(
            category="SSL/TLS & Cryptography",
            engine="TLS + SAST",
            status="CONFIRMED",
            checksCount=12,
            notes="Cert validity, expiration, key size, hash algorithm, weak protocols/ciphers",
        ),
        VulnerabilityCoverageItem(
            category="Software Composition Analysis (SCA)",
            engine="SCA + OSV/CVE",
            status="CONFIRMED",
            checksCount=18,
            notes="npm, pip, go, cargo, maven, composer with genuine version range matching",
        ),
        VulnerabilityCoverageItem(
            category="DNS & Domain Security",
            engine="DNS Scanner",
            status="CONFIRMED",
            checksCount=6,
            notes="SPF permissive policies (+all), DMARC policy, AXFR zone transfer, takeover",
        ),
        VulnerabilityCoverageItem(
            category="Network Vulnerability Assessment",
            engine="Network Scanner",
            status="CONFIRMED",
            checksCount=15,
            notes="Insecure services (Telnet, FTP, SMB), exposed databases, banner grab",
        ),
        VulnerabilityCoverageItem(
            category="Container & IaC Security",
            engine="IaC Scanner",
            status="CONFIRMED",
            checksCount=9,
            notes="Dockerfile root execution, K8s privileged pods, hostNetwork, Terraform S3 ACL",
        ),
    ]

@app.post("/api/scan/code", response_model=ScanResponse)
async def scan_code(request: CodeScanRequest):
    """
    Perform Static Application Security Testing (SAST).
    Scans source files or snippets for secrets, injection, crypto flaws, and misconfigurations.
    """
    is_auth, auth_msg = SecurityScopeEnforcer.validate_authorization(request.authorizedBy)
    if not is_auth:
        raise HTTPException(status_code=403, detail=auth_msg)

    start_time = time.time()
    findings: List[SecurityFinding] = []

    if request.rawCode:
        findings = sast_engine.scan_code_snippet(
            code=request.rawCode,
            language=request.language or "auto",
            scope_name="code_snippet",
        )
        target_name = "Code Snippet"
    else:
        target_dir = request.targetPath or str(settings.workspace_root)
        findings, files_scanned = sast_engine.scan_directory(
            target_dir=target_dir,
            max_files=request.maxFiles,
        )
        target_name = f"Workspace ({files_scanned} files)"

    # Deduplicate and calibrate confidence
    findings = fp_engine.deduplicate(findings)
    for f in findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=target_name,
        scanType=ScanType.CODE,
        status="COMPLETED",
        summary=summary,
        findings=findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.post("/api/scan/endpoint", response_model=ScanResponse)
async def scan_endpoint(request: EndpointScanRequest):
    """
    Audit web target security posture: HTTP headers, TLS certificate, CORS policies, cookies, and safe injection canaries.
    """
    is_auth, auth_msg = SecurityScopeEnforcer.validate_authorization(request.authorizedBy)
    if not is_auth:
        raise HTTPException(status_code=403, detail=auth_msg)

    start_time = time.time()
    findings = await web_engine.scan_endpoint(
        target_url=request.targetUrl,
        check_cors=request.checkCors,
        check_headers=request.checkHeaders,
        check_ssl=request.checkSsl,
        check_injection=request.checkInjection,
        authorized_by=request.authorizedBy,
    )

    findings = fp_engine.deduplicate(findings)
    for f in findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=request.targetUrl,
        scanType=ScanType.ENDPOINT,
        status="COMPLETED",
        summary=summary,
        findings=findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.post("/api/scan/dependencies", response_model=ScanResponse)
async def scan_dependencies(request: DependencyScanRequest):
    """
    Audit project dependencies for known CVEs across npm, pip, cargo, go, maven, and composer (SCA).
    """
    is_auth, auth_msg = SecurityScopeEnforcer.validate_authorization(request.authorizedBy)
    if not is_auth:
        raise HTTPException(status_code=403, detail=auth_msg)

    start_time = time.time()
    findings: List[SecurityFinding] = []
    manifest_type = (request.manifestType or "npm").lower()

    if request.manifestContent:
        if manifest_type == "pip":
            findings = sca_engine.scan_pip_manifest(request.manifestContent)
        elif manifest_type == "cargo":
            findings = sca_engine.scan_cargo_manifest(request.manifestContent)
        elif manifest_type == "go":
            findings = sca_engine.scan_go_manifest(request.manifestContent)
        elif manifest_type == "maven":
            findings = sca_engine.scan_maven_manifest(request.manifestContent)
        elif manifest_type == "composer":
            findings = sca_engine.scan_composer_manifest(request.manifestContent)
        else:
            findings = sca_engine.scan_npm_manifest(request.manifestContent)
        target_name = f"Uploaded {manifest_type} manifest"
    else:
        findings = sca_engine.audit_workspace_manifests()
        target_name = "Workspace manifests (package.json / requirements.txt)"

    findings = fp_engine.deduplicate(findings)
    for f in findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=target_name,
        scanType=ScanType.DEPENDENCIES,
        status="COMPLETED",
        summary=summary,
        findings=findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.post("/api/scan/network", response_model=ScanResponse)
async def scan_network(request: NetworkScanRequest):
    """
    Authorized network assessment: scans target host for unexpected open ports and insecure service exposure.
    """
    is_auth, auth_msg = SecurityScopeEnforcer.validate_authorization(request.authorizedBy)
    if not is_auth:
        raise HTTPException(status_code=403, detail=auth_msg)

    start_time = time.time()
    findings = await network_engine.scan_host(
        target_host=request.targetHost,
        ports=request.ports,
        authorized_by=request.authorizedBy,
    )

    findings = fp_engine.deduplicate(findings)
    for f in findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=request.targetHost,
        scanType=ScanType.NETWORK,
        status="COMPLETED",
        summary=summary,
        findings=findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.post("/api/scan/dns", response_model=ScanResponse)
async def scan_dns(request: DnsScanRequest):
    """
    Audit DNS and domain posture: SPF policies, DMARC records, AXFR zone transfer leaks, and dangling CNAME indicators.
    """
    is_auth, auth_msg = SecurityScopeEnforcer.validate_authorization(request.authorizedBy)
    if not is_auth:
        raise HTTPException(status_code=403, detail=auth_msg)

    start_time = time.time()
    findings = await dns_engine.scan_domain(
        domain=request.domain,
        check_zone_transfer=request.checkZoneTransfer,
        check_mail_records=request.checkMailRecords,
        check_takeover=request.checkTakeover,
        authorized_by=request.authorizedBy,
    )

    findings = fp_engine.deduplicate(findings)
    for f in findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=request.domain,
        scanType=ScanType.DNS,
        status="COMPLETED",
        summary=summary,
        findings=findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.post("/api/scan/iac", response_model=ScanResponse)
async def scan_iac(request: IaCScanRequest):
    """
    Audit Infrastructure as Code: Dockerfiles, Kubernetes YAML manifests, or Terraform templates.
    """
    is_auth, auth_msg = SecurityScopeEnforcer.validate_authorization(request.authorizedBy)
    if not is_auth:
        raise HTTPException(status_code=403, detail=auth_msg)

    start_time = time.time()
    findings: List[SecurityFinding] = []
    file_type = request.fileType.lower()

    if request.rawContent:
        if file_type == "dockerfile":
            findings = iac_engine.scan_dockerfile(request.rawContent)
        elif file_type == "kubernetes":
            findings = iac_engine.scan_kubernetes_yaml(request.rawContent)
        elif file_type == "terraform":
            findings = iac_engine.scan_terraform(request.rawContent)
        target_name = f"Uploaded {file_type} manifest"
    else:
        target_name = "IaC Workspace Files"

    findings = fp_engine.deduplicate(findings)
    for f in findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=target_name,
        scanType=ScanType.CONTAINER_IAC,
        status="COMPLETED",
        summary=summary,
        findings=findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.post("/api/scan/api", response_model=ScanResponse)
async def scan_api(request: ApiScanRequest):
    """
    Audit API Security: REST, GraphQL introspection, and WebSocket CSWSH origin verification.
    """
    is_auth, auth_msg = SecurityScopeEnforcer.validate_authorization(request.authorizedBy)
    if not is_auth:
        raise HTTPException(status_code=403, detail=auth_msg)

    start_time = time.time()
    findings = await api_engine.scan_api(
        target_url=request.targetUrl,
        api_type=request.apiType,
        headers=request.headers,
        check_introspection=request.checkIntrospection,
        check_rate_limit=request.checkRateLimit,
        authorized_by=request.authorizedBy,
    )

    findings = fp_engine.deduplicate(findings)
    for f in findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=request.targetUrl,
        scanType=ScanType.API,
        status="COMPLETED",
        summary=summary,
        findings=findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.post("/api/scan/full", response_model=ScanResponse)
async def scan_full():
    """
    Execute a comprehensive multi-vector security assessment across the entire workspace (SAST + SCA).
    """
    start_time = time.time()
    sast_findings, files_count = sast_engine.scan_directory(str(settings.workspace_root))
    sca_findings = sca_engine.audit_workspace_manifests()
    all_findings = sast_findings + sca_findings

    all_findings = fp_engine.deduplicate(all_findings)
    for f in all_findings:
        f.confidence = fp_engine.calibrate_confidence(f)

    duration = time.time() - start_time
    summary = agent_engine.calculate_summary(all_findings, duration)
    exec_summary = agent_engine.generate_executive_summary(summary, all_findings)

    scan_res = ScanResponse(
        scanId=f"scan-{uuid.uuid4().hex[:8]}",
        target=f"Full Project Audit ({files_count} files analyzed)",
        scanType=ScanType.FULL,
        status="COMPLETED",
        summary=summary,
        findings=all_findings,
        executiveSummary=exec_summary,
    )
    scan_store.save_scan(scan_res)
    return scan_res

@app.get("/api/scans", response_model=List[ScanResponse])
async def list_scans():
    """List historical security scans."""
    return scan_store.list_scans()

@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan_details(scan_id: str):
    """Retrieve full details and findings for a specific scan."""
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return scan

@app.get("/api/findings/latest", response_model=List[SecurityFinding])
async def get_latest_findings():
    """Retrieve findings from the latest scan for the frontend dashboard preview."""
    latest = scan_store.get_latest_scan()
    if not latest:
        return []
    return latest.findings

@app.post("/api/findings/{finding_id}/verify", response_model=SecurityFinding)
async def verify_finding(finding_id: str, target_url: Optional[str] = None):
    """
    Run dedicated Verification Engine against a candidate finding to confirm or refute vulnerability.
    """
    finding = scan_store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    verified = await verification_engine.verify_finding(finding, base_url=target_url)
    return verified

@app.post("/api/findings/{finding_id}/suppress", response_model=SecurityFinding)
async def suppress_finding(finding_id: str, justification: str, operator_name: str = "security_lead"):
    """
    Suppress a finding with mandatory documented justification.
    """
    finding = scan_store.suppress_finding(finding_id, justification, operator_name)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return finding

@app.post("/api/agent/ask", response_model=AgentQueryResponse)
async def ask_agent(request: AgentQueryRequest):
    """
    Process natural language or voice security queries with the CipherFlux AI Security Analyst.
    """
    active_findings: List[SecurityFinding] = []
    if request.scanId:
        scan = scan_store.get_scan(request.scanId)
        if scan:
            active_findings = scan.findings
    else:
        latest = scan_store.get_latest_scan()
        if latest:
            active_findings = latest.findings

    return agent_engine.process_query(request.query, active_findings=active_findings)

@app.get("/api/report/{scan_id}")
async def get_detailed_report(scan_id: str):
    """
    Generate and return structured 21-attribute enterprise audit report for a specific scan.
    """
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return report_generator.generate_detailed_report(scan)

@app.get("/api/report/{scan_id}/markdown")
async def get_markdown_report(scan_id: str):
    """
    Export the detailed security report in publication-ready GitHub-flavored Markdown.
    """
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    report_data = report_generator.generate_detailed_report(scan)
    md_content = report_generator.render_markdown_report(report_data)
    return PlainTextResponse(md_content, media_type="text/markdown")

@app.get("/api/report/{scan_id}/csv")
async def get_csv_report(scan_id: str):
    """
    Export the scan findings in standardized CSV format.
    """
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    report_data = report_generator.generate_detailed_report(scan)
    csv_content = report_generator.render_csv_report(report_data)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cipherflux-report-{scan_id}.csv"}
    )

@app.get("/api/report/{scan_id}/pdf")
async def get_pdf_report(scan_id: str):
    """
    Export the scan report as a high-fidelity PDF document.
    """
    scan = scan_store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    report_data = report_generator.generate_detailed_report(scan)
    pdf_bytes = report_generator.render_pdf_report(report_data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cipherflux-report-{scan_id}.pdf"}
    )

@app.post("/api/report/generate")
async def generate_live_report():
    """
    Execute full workspace scan and return the complete detailed audit report.
    """
    scan_res = await scan_full()
    return report_generator.generate_detailed_report(scan_res)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=settings.host, port=settings.port, reload=True)
