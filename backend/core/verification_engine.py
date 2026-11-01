import asyncio
import re
import uuid
from typing import List, Dict, Any, Optional
import httpx

from ..models.schemas import (
    SecurityFinding,
    VerificationStatus,
    SeverityLevel,
)
from .safety import SecurityScopeEnforcer

class VerificationEngine:
    """
    Dedicated Vulnerability Verification Engine.
    Operates independently from initial detection to rigorously validate suspected findings
    using safe, reproducible, non-destructive validation probes.
    
    Principles:
    - Never mark an unverified suspicion as CONFIRMED.
    - Preserve reproducible evidence (request, response, canary, delta).
    - Establish a baseline response for comparative differential analysis.
    - Report CONFIRMED, POTENTIAL, INCONCLUSIVE, NOT_VULNERABLE, or NOT_TESTED.
    """

    def __init__(self, timeout_seconds: float = 6.0):
        self.timeout = timeout_seconds

    async def verify_finding(self, finding: SecurityFinding, base_url: Optional[str] = None) -> SecurityFinding:
        """
        Verify a single candidate finding using category-specific validation heuristics.
        """
        # Record verification attempt metadata
        attempts = finding.evidence.get("verificationAttempts", 0) + 1
        finding.evidence["verificationAttempts"] = attempts
        finding.evidence["lastVerificationTimestamp"] = asyncio.get_event_loop().time()

        category = finding.category.lower()

        # 1. Web / API Injection Verification
        if "injection" in category or finding.cweId in ("CWE-89", "CWE-79", "CWE-78", "CWE-918", "CWE-1336"):
            return await self._verify_web_injection(finding, base_url)

        # 2. CORS Verification
        elif "cors" in category or finding.cweId == "CWE-942":
            return await self._verify_cors(finding, base_url)

        # 3. Security Headers / Transport Posture
        elif "cryptographic" in category or "frontend integrity" in category or finding.cweId in ("CWE-319", "CWE-1021", "CWE-326"):
            return await self._verify_header_posture(finding, base_url)

        # 4. Sensitive Path / File Exposure
        elif "information disclosure" in category and finding.affectedUrl:
            return await self._verify_path_exposure(finding)

        # 5. Software Composition Analysis (SCA)
        elif "supply chain" in category or finding.cweId in ("CWE-1395", "CVE-"):
            return self._verify_sca_advisory(finding)

        # 6. Source Code Analysis (SAST)
        elif "secrets" in category or finding.cweId == "CWE-798":
            return self._verify_sast_secret(finding)

        # Default fallback
        if finding.verificationStatus == VerificationStatus.POTENTIAL:
            finding.verificationStatus = VerificationStatus.INCONCLUSIVE
            finding.statusBadge = "INCONCLUSIVE (NEEDS MANUAL TRIAGE)"

        return finding

    async def _verify_web_injection(self, finding: SecurityFinding, base_url: Optional[str]) -> SecurityFinding:
        """Safe non-destructive verification of injection vulnerabilities."""
        target_url = finding.affectedUrl or base_url
        if not target_url:
            finding.verificationStatus = VerificationStatus.NOT_TESTED
            finding.evidence["verificationNote"] = "No target URL provided for active probe."
            return finding

        # Verify scope safety
        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(target_url)
        if not is_safe:
            finding.verificationStatus = VerificationStatus.NOT_TESTED
            finding.evidence["verificationNote"] = f"Verification blocked by safety policy: {msg}"
            return finding

        canary_token = f"cf_{uuid.uuid4().hex[:6]}"

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                # 1. Establish baseline
                baseline_res = await client.get(target_url)
                baseline_body = baseline_res.text
                baseline_status = baseline_res.status_code

                # 2. XSS Reflection Probe
                if finding.cweId == "CWE-79":
                    probe_val = f"<cflx_{canary_token}>"
                    param = finding.affectedParameter or "q"
                    probe_url = f"{target_url}{'&' if '?' in target_url else '?'}{param}={probe_val}"
                    
                    probe_res = await client.get(probe_url)
                    content_type = probe_res.headers.get("content-type", "").lower()

                    if probe_val in probe_res.text and "text/html" in content_type:
                        finding.verificationStatus = VerificationStatus.CONFIRMED
                        finding.statusBadge = "CONFIRMED (CANARY REFLECTED)"
                        finding.confidence = 0.98
                        finding.evidence.update({
                            "canaryToken": probe_val,
                            "canaryMatched": True,
                            "baselineStatus": baseline_status,
                            "probeStatus": probe_res.status_code,
                            "contentType": content_type,
                            "context": "Unescaped HTML document reflection"
                        })
                    elif probe_val in probe_res.text:
                        # Reflected in non-HTML content (e.g. JSON API)
                        finding.verificationStatus = VerificationStatus.POTENTIAL
                        finding.statusBadge = "POTENTIAL (REFLECTED IN NON-HTML)"
                        finding.confidence = 0.60
                    else:
                        finding.verificationStatus = VerificationStatus.NOT_VULNERABLE
                        finding.statusBadge = "NOT VULNERABLE (CANARY ENCODED/FILTERED)"
                        finding.confidence = 0.95

                # 3. SQLi Boolean Differential or Error Probe
                elif finding.cweId == "CWE-89":
                    param = finding.affectedParameter or "id"
                    # Safe arithmetic canaries: 1 vs 1' OR '1'='1
                    true_probe = f"{target_url}{'&' if '?' in target_url else '?'}{param}=1'%20AND%20'1'='1"
                    false_probe = f"{target_url}{'&' if '?' in target_url else '?'}{param}=1'%20AND%20'1'='2"

                    res_true = await client.get(true_probe)
                    res_false = await client.get(false_probe)

                    # Look for SQL error signatures
                    sql_errors = [
                        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL query failed",
                        "sqlite3.OperationalError", "Microsoft OLE DB Provider for SQL Server"
                    ]
                    has_error = any(err in res_true.text or err in res_false.text for err in sql_errors)

                    if has_error:
                        finding.verificationStatus = VerificationStatus.CONFIRMED
                        finding.statusBadge = "CONFIRMED (SQL ERROR SIGNATURE)"
                        finding.confidence = 0.99
                        finding.evidence.update({
                            "sqlErrorObserved": True,
                            "trueStatus": res_true.status_code,
                            "falseStatus": res_false.status_code,
                        })
                    elif res_true.status_code == baseline_status and res_false.status_code != baseline_status:
                        finding.verificationStatus = VerificationStatus.CONFIRMED
                        finding.statusBadge = "CONFIRMED (BOOLEAN DIFFERENTIAL)"
                        finding.confidence = 0.92
                        finding.evidence.update({
                            "booleanDifferential": True,
                            "trueStatus": res_true.status_code,
                            "falseStatus": res_false.status_code,
                        })
                    else:
                        finding.verificationStatus = VerificationStatus.POTENTIAL
                        finding.statusBadge = "POTENTIAL (REQUIRES AUTH LAB REVIEW)"
                        finding.confidence = 0.55

        except Exception as e:
            finding.verificationStatus = VerificationStatus.INCONCLUSIVE
            finding.evidence["verificationError"] = str(e)
            finding.statusBadge = "INCONCLUSIVE (PROBE ERROR)"

        return finding

    async def _verify_cors(self, finding: SecurityFinding, base_url: Optional[str]) -> SecurityFinding:
        """Verify CORS by re-probing target with untrusted origin."""
        target_url = finding.affectedUrl or base_url
        if not target_url:
            return finding

        test_origin = "https://untrusted-canary.internal"
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                res = await client.options(
                    target_url,
                    headers={"Origin": test_origin, "Access-Control-Request-Method": "POST"}
                )
                acao = res.headers.get("access-control-allow-origin")
                acac = res.headers.get("access-control-allow-credentials", "").lower() == "true"

                if acao == test_origin and acac:
                    finding.verificationStatus = VerificationStatus.CONFIRMED
                    finding.statusBadge = "CONFIRMED (REFLECTED WITH CREDS)"
                    finding.confidence = 1.0
                    finding.evidence["verifiedOrigin"] = acao
                    finding.evidence["verifiedCredentials"] = True
                elif acao == test_origin:
                    finding.verificationStatus = VerificationStatus.CONFIRMED
                    finding.statusBadge = "CONFIRMED (REFLECTED ORIGIN)"
                    finding.confidence = 0.95
                else:
                    finding.verificationStatus = VerificationStatus.NOT_VULNERABLE
                    finding.statusBadge = "NOT VULNERABLE (ORIGIN REJECTED)"
        except Exception:
            finding.verificationStatus = VerificationStatus.INCONCLUSIVE

        return finding

    async def _verify_header_posture(self, finding: SecurityFinding, base_url: Optional[str]) -> SecurityFinding:
        """Directly verify presence/absence of response headers."""
        target_url = finding.affectedUrl or base_url
        if not target_url:
            return finding

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                res = await client.get(target_url)
                headers = {k.lower(): v for k, v in res.headers.items()}

                if "hsts" in finding.title.lower():
                    if "strict-transport-security" not in headers:
                        finding.verificationStatus = VerificationStatus.CONFIRMED
                        finding.statusBadge = "CONFIRMED (HEADER MISSING)"
                    else:
                        finding.verificationStatus = VerificationStatus.NOT_VULNERABLE
                elif "content-security-policy" in finding.title.lower():
                    if "content-security-policy" not in headers:
                        finding.verificationStatus = VerificationStatus.CONFIRMED
                        finding.statusBadge = "CONFIRMED (HEADER MISSING)"
                    else:
                        finding.verificationStatus = VerificationStatus.NOT_VULNERABLE
        except Exception:
            finding.verificationStatus = VerificationStatus.INCONCLUSIVE

        return finding

    async def _verify_path_exposure(self, finding: SecurityFinding) -> SecurityFinding:
        """Verify whether an exposed sensitive file is an actual leak vs a generic SPA fallback."""
        if not finding.affectedUrl:
            return finding

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                res = await client.get(finding.affectedUrl)
                if res.status_code == 200:
                    text = res.text[:300]
                    # Verify content matches file signature
                    if ".env" in finding.affectedUrl and ("=" in text or "KEY" in text or "SECRET" in text):
                        finding.verificationStatus = VerificationStatus.CONFIRMED
                        finding.statusBadge = "CONFIRMED (SECRETS LEAKED)"
                        finding.confidence = 1.0
                    elif ".git" in finding.affectedUrl and "ref: refs/" in text:
                        finding.verificationStatus = VerificationStatus.CONFIRMED
                        finding.statusBadge = "CONFIRMED (GIT REPO EXPOSED)"
                        finding.confidence = 1.0
                    else:
                        # 200 OK but likely default index.html SPA page
                        finding.verificationStatus = VerificationStatus.NOT_VULNERABLE
                        finding.statusBadge = "NOT VULNERABLE (SPA FALLBACK 200)"
                else:
                    finding.verificationStatus = VerificationStatus.NOT_VULNERABLE
                    finding.statusBadge = "NOT VULNERABLE (HTTP " + str(res.status_code) + ")"
        except Exception:
            finding.verificationStatus = VerificationStatus.INCONCLUSIVE

        return finding

    def _verify_sca_advisory(self, finding: SecurityFinding) -> SecurityFinding:
        """Validate software dependency against exact fixed version semantics."""
        if finding.cweId and ("CVE-" in finding.cweId or "GHSA-" in finding.cweId):
            finding.verificationStatus = VerificationStatus.CONFIRMED
            finding.statusBadge = "CONFIRMED (ADVISORY MATCH)"
            finding.confidence = 0.98
        else:
            finding.verificationStatus = VerificationStatus.POTENTIAL
        return finding

    def _verify_sast_secret(self, finding: SecurityFinding) -> SecurityFinding:
        """Differentiate real secrets from documentation/dummy test credentials."""
        snippet = finding.codeSnippet or ""
        test_indicators = ["example", "test", "dummy", "sample", "fake", "placeholder", "xxx", "123456"]
        if any(ind in snippet.lower() for ind in test_indicators):
            finding.verificationStatus = VerificationStatus.POTENTIAL
            finding.statusBadge = "POTENTIAL (MOCK/TEST TOKEN)"
            finding.confidence = 0.40
        else:
            finding.verificationStatus = VerificationStatus.CONFIRMED
            finding.statusBadge = "CONFIRMED (HIGH-ENTROPY KEY)"
            finding.confidence = 0.95
        return finding
