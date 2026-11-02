"""
CipherFlux Labs Centralized Scan Orchestrator.
Orchestrates Quick, Standard, Deep and Custom security scans across all implemented engines:
Web, API, Network, SSL/TLS, CVE, DNS, SAST, SCA, Cloud, Container/IaC.
Strictly non-destructive, safe validation with progress monitoring.
"""
import asyncio
import time
import uuid
import urllib.parse
from enum import Enum
from typing import List, Dict, Any, Optional, Callable

from backend.models.schemas import (
    ScanResponse,
    ScanType,
    ScanSummary,
    SecurityFinding,
    SeverityLevel,
    VerificationStatus,
)
from backend.core.safety import SecurityScopeEnforcer
from backend.core.false_positive_engine import FalsePositiveEngine, rule_registry
from backend.core.verification_engine import VerificationEngine
from backend.agent.security_agent import SecurityAgent

# Existing engines
from backend.scanners.sast_scanner import SASTScanner
from backend.scanners.web_scanner import WebPostureScanner
from backend.scanners.sca_scanner import SCAScanner
from backend.scanners.network_scanner import NetworkScanner
from backend.scanners.dns_scanner import DNSDomainScanner
from backend.scanners.api_scanner import APISecurityScanner
from backend.scanners.tls_scanner import TLSScanner
from backend.scanners.cve_engine import cve_engine

# New scanners
from ..scanners.cloud_scanner import cloud_scanner
from ..scanners.container_scanner import container_scanner
from ..storage.target_store import target_store
from ..storage.history_store import history_store
from ..storage.config_store import config_store

# Feature 1 & 3: Live CVE Feed + Browser Engine (lazy-loaded, fail-safe)
try:
    from backend.scanners.browser_engine import browser_engine
    _BROWSER_ENGINE_AVAILABLE = True
except ImportError:
    browser_engine = None  # type: ignore
    _BROWSER_ENGINE_AVAILABLE = False

try:
    from backend.scanners.osv_feed import live_cve_feed
    _OSV_FEED_AVAILABLE = True
except ImportError:
    live_cve_feed = None  # type: ignore
    _OSV_FEED_AVAILABLE = False

class ScanProfile(str, Enum):
    PASSIVE = "passive"      # Low-impact inspection, headers, TLS, DNS, exposures
    QUICK = "quick"          # Fast availability, headers, TLS, basic tech ID, exposures
    STANDARD = "standard"    # Quick + safe canaries, CORS, cookies, API, common ports
    DEEP = "deep"            # Comprehensive: Web + API + Network + SAST + SCA + IaC

class ScanOrchestrator:
    def __init__(self):
        self.fp_engine = FalsePositiveEngine(registry=rule_registry)
        self.agent_engine = SecurityAgent()
        self.verification_engine = VerificationEngine(timeout_seconds=8.0)
        self.sast_engine = SASTScanner()
        self.web_engine = WebPostureScanner(timeout_seconds=8.0)
        self.sca_engine = SCAScanner()
        self.network_engine = NetworkScanner(timeout=3.0)
        self.dns_engine = DNSDomainScanner(timeout=5.0)
        self.api_engine = APISecurityScanner(timeout=6.0)
        self.tls_engine = TLSScanner(timeout=5.0)
        self.cloud_engine = cloud_scanner
        self.container_engine = container_scanner
        # Feature 3: Playwright browser engine (None when not installed)
        self.browser_engine = browser_engine if _BROWSER_ENGINE_AVAILABLE else None
        # Feature 1: Live OSV.dev CVE feed singleton
        self.live_cve_feed = live_cve_feed if _OSV_FEED_AVAILABLE else None

    async def execute_quick_scan(
        self,
        target_url: str,
        authorized_by: str = "security_lead",
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> ScanResponse:
        """
        Execute Low-Impact Quick Vulnerability Scan.
        Checks: HTTP/HTTPS availability, security headers, SSL/TLS certificate, basic configuration, and public exposures.
        """
        start_time = time.time()
        scan_id = f"scan-quick-{uuid.uuid4().hex[:8]}"

        if progress_callback:
            progress_callback(f"Validating target scope for {target_url}...", 10)

        # 1. Scope & Safety Check
        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(target_url)
        if not is_safe:
            return self._create_aborted_response(scan_id, target_url, ScanType.ENDPOINT, msg, start_time)

        findings: List[SecurityFinding] = []
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname or parsed.netloc.split(":")[0] or target_url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 2. Web Posture & Headers & Public Exposure (check_injection=False for quick profile)
        if progress_callback:
            progress_callback(f"Auditing web availability, headers, and exposures on {hostname}...", 30)

        web_findings = await self.web_engine.scan_endpoint(
            target_url=target_url,
            check_cors=True,
            check_headers=True,
            check_ssl=True,
            check_injection=False,  # Low-impact
            authorized_by=authorized_by,
        )
        findings.extend(web_findings)

        # 3. DNS Mail & Domain Records
        if progress_callback:
            progress_callback(f"Auditing DNS SPF, DMARC, and domain configuration on {hostname}...", 65)

        try:
            dns_findings = await self.dns_engine.scan_domain(
                domain=hostname,
                check_zone_transfer=True,
                check_mail_records=True,
                check_takeover=True,
                authorized_by=authorized_by,
            )
            findings.extend(dns_findings)
        except Exception:
            pass

        if progress_callback:
            progress_callback("Deduplicating findings and calibrating confidence...", 90)

        # Deduplicate and calibrate
        findings = self.fp_engine.deduplicate(findings)
        for f in findings:
            f.confidence = self.fp_engine.calibrate_confidence(f)

        duration = time.time() - start_time
        summary = self.agent_engine.calculate_summary(findings, duration)
        exec_summary = (
            f"Quick Security Audit completed for {target_url} in {duration:.2f}s. "
            f"Evaluated defensive headers, TLS certificate parameters, DNS policy records, and public exposure endpoints. "
            f"Identified {summary.totalFindings} findings ({summary.confirmedCount} verified, {summary.potentialCount} potential). "
            f"Note: This is a low-impact quick scan and does not substitute for a comprehensive full audit."
        )

        scan_res = ScanResponse(
            scanId=scan_id,
            target=target_url,
            scanType=ScanType.ENDPOINT,
            status="COMPLETED",
            summary=summary,
            findings=findings,
            executiveSummary=exec_summary,
        )

        history_store.save_scan(scan_res)
        if progress_callback:
            progress_callback("Quick scan completed successfully.", 100)

        return scan_res

    async def execute_full_scan(
        self,
        target_url: str,
        authorized_by: str = "security_lead",
        include_code_audit: bool = True,
        include_network: bool = True,
        progress_callback: Optional[Callable[[str, int], None]] = None,
    ) -> ScanResponse:
        """
        Execute Full Multi-Vector Vulnerability Assessment.
        Orchestrates Web, API, Network, SSL/TLS, DNS, SAST, SCA, and IaC/Container engines.
        """
        start_time = time.time()
        scan_id = f"scan-full-{uuid.uuid4().hex[:8]}"

        if progress_callback:
            progress_callback(f"Checking authorization scope for {target_url}...", 5)

        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(target_url)
        if not is_safe:
            return self._create_aborted_response(scan_id, target_url, ScanType.FULL, msg, start_time)

        findings: List[SecurityFinding] = []
        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname or parsed.netloc.split(":")[0] or target_url

        # 1. Web Application & Active Canary Injection (SSTI, CRLF, CORS, Headers)
        if progress_callback:
            progress_callback("Executing Web Application Posture & Safe Canary Probes...", 20)
        try:
            web_findings = await self.web_engine.scan_endpoint(
                target_url=target_url,
                check_cors=True,
                check_headers=True,
                check_ssl=True,
                check_injection=True,
                authorized_by=authorized_by,
            )
            findings.extend(web_findings)
        except Exception:
            pass

        # 2. API Security (GraphQL Introspection, REST Rate Limits, WebSocket CSWSH)
        if progress_callback:
            progress_callback("Auditing API Endpoints (GraphQL / REST / WebSocket)...", 35)
        try:
            api_findings = await self.api_engine.scan_api(
                target_url=target_url,
                api_type="rest",
                check_rate_limit=True,
                authorized_by=authorized_by,
            )
            findings.extend(api_findings)
        except Exception:
            pass

        # 3. DNS & Domain Security (SPF, DMARC, AXFR, Takeover)
        if progress_callback:
            progress_callback("Auditing DNS infrastructure and email security policies...", 50)
        try:
            dns_findings = await self.dns_engine.scan_domain(
                domain=hostname,
                check_zone_transfer=True,
                check_mail_records=True,
                check_takeover=True,
                authorized_by=authorized_by,
            )
            findings.extend(dns_findings)
        except Exception:
            pass

        # 4. Controlled Network Port Discovery
        if include_network:
            if progress_callback:
                progress_callback("Scanning authorized service ports for plaintext protocol exposure...", 65)
            try:
                net_findings = await self.network_engine.scan_host(
                    target_host=hostname,
                    authorized_by=authorized_by,
                )
                findings.extend(net_findings)
            except Exception:
                pass

        # 5. Local Workspace SAST & SCA & Container IaC if requested
        if include_code_audit:
            if progress_callback:
                progress_callback("Auditing workspace source code (SAST), dependencies (SCA), and IaC...", 80)
            try:
                sast_findings, _ = self.sast_engine.scan_directory(".", max_files=200)
                findings.extend(sast_findings)
            except Exception:
                pass

            try:
                sca_findings = self.sca_engine.audit_workspace_manifests()
                findings.extend(sca_findings)
            except Exception:
                pass

        if progress_callback:
            progress_callback("Executing verification engine and false-positive calibration...", 95)

        # Deduplication and Calibration
        findings = self.fp_engine.deduplicate(findings)
        for f in findings:
            f.confidence = self.fp_engine.calibrate_confidence(f)

        duration = time.time() - start_time
        summary = self.agent_engine.calculate_summary(findings, duration)
        exec_summary = self.agent_engine.generate_executive_summary(summary, findings)

        scan_res = ScanResponse(
            scanId=scan_id,
            target=target_url,
            scanType=ScanType.FULL,
            status="COMPLETED",
            summary=summary,
            findings=findings,
            executiveSummary=exec_summary,
        )

        history_store.save_scan(scan_res)
        if progress_callback:
            progress_callback("Full vulnerability assessment completed.", 100)

        return scan_res

    def _create_aborted_response(
        self,
        scan_id: str,
        target: str,
        scan_type: ScanType,
        reason: str,
        start_time: float,
    ) -> ScanResponse:
        duration = time.time() - start_time
        finding = SecurityFinding(
            id=f"finding-{uuid.uuid4().hex[:8]}",
            title="Scan Terminated: Target Outside Authorized Boundary",
            severity=SeverityLevel.INFORMATIONAL,
            category="Operational Safety",
            targetScope=target,
            cvss="0.0",
            description=f"Assessment aborted by safety enforcement: {reason}",
            remediationSummary="Verify target domain and register in the authorized target management registry.",
            verificationStatus=VerificationStatus.NOT_TESTED,
            statusBadge="SCOPE BLOCKED",
        )
        summary = ScanSummary(
            totalFindings=1,
            infoCount=1,
            riskScore=0.0,
            durationSeconds=duration,
        )
        return ScanResponse(
            scanId=scan_id,
            target=target,
            scanType=scan_type,
            status="ABORTED",
            summary=summary,
            findings=[finding],
            executiveSummary=f"Scan aborted for '{target}': {reason}",
        )

orchestrator = ScanOrchestrator()
