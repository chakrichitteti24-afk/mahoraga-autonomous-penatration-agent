import asyncio
import re
import uuid
import ipaddress
from typing import List, Dict, Any, Optional
import dns.resolver
import dns.query
import dns.zone
import dns.exception
import httpx

from ..models.schemas import SecurityFinding, SeverityLevel, VerificationStatus
from ..core.safety import SecurityScopeEnforcer

# Known provider CNAME patterns and body signatures for safe subdomain takeover assessment
TAKEOVER_SIGNATURES = [
    {
        "provider": "GitHub Pages",
        "cname_pattern": r"\.github\.io\b",
        "body_fingerprint": "There isn't a GitHub Pages site here",
        "cwe": "CWE-284",
    },
    {
        "provider": "Amazon S3",
        "cname_pattern": r"\.s3(?:-website)?\.[a-z0-9\-]+\.amazonaws\.com\b",
        "body_fingerprint": "NoSuchBucket",
        "cwe": "CWE-284",
    },
    {
        "provider": "Heroku",
        "cname_pattern": r"\.herokudns\.com|\.herokuapp\.com\b",
        "body_fingerprint": "No such app",
        "cwe": "CWE-284",
    },
    {
        "provider": "Microsoft Azure",
        "cname_pattern": r"\.azurewebsites\.net|\.cloudapp\.net\b",
        "body_fingerprint": "404 Web Site not found",
        "cwe": "CWE-284",
    },
]

class DNSDomainScanner:
    """
    DNS & Domain Security Assessment Engine.
    Audits email protection records (SPF, DMARC), tests DNS zone transfers (AXFR),
    and evaluates dangling CNAME takeover indicators with provider verification.
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    async def scan_domain(
        self,
        domain: str,
        check_zone_transfer: bool = True,
        check_mail_records: bool = True,
        check_takeover: bool = True,
        authorized_by: Optional[str] = "operator",
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        domain = domain.strip().lower()
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://")[1].split("/")[0].split(":")[0]

        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(domain)
        if not is_safe:
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title="DNS Scan Aborted: Safety Policy",
                    severity=SeverityLevel.INFORMATIONAL,
                    category="DNS & Domain Security",
                    targetScope=domain,
                    cvss="0.0",
                    description=f"Scan rejected by safety policy: {msg}",
                    remediationSummary="Ensure domain is within authorized scope.",
                    verificationStatus=VerificationStatus.NOT_TESTED,
                    statusBadge="SCOPE BLOCKED",
                )
            )
            return findings

        # If target is an IP address or localhost, skip domain DNS checks
        try:
            ipaddress.ip_address(domain)
            return findings
        except ValueError:
            if domain in ("localhost", "local", "internal"):
                return findings

        # Run checks in worker thread
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout

        if check_mail_records:
            mail_findings = await asyncio.to_thread(self._audit_mail_records, resolver, domain)
            findings.extend(mail_findings)

        if check_zone_transfer:
            axfr_findings = await asyncio.to_thread(self._audit_zone_transfer, resolver, domain)
            findings.extend(axfr_findings)

        if check_takeover:
            takeover_findings = await self._audit_dangling_cname(resolver, domain)
            findings.extend(takeover_findings)

        return findings

    def _audit_mail_records(self, resolver: dns.resolver.Resolver, domain: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # 1. SPF Check
        has_spf = False
        spf_record = None
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="replace") for b in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    has_spf = True
                    spf_record = txt_str
                    break
        except Exception:
            pass

        if not has_spf:
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title="Missing Sender Policy Framework (SPF) Record",
                    severity=SeverityLevel.MEDIUM,
                    category="DNS & Domain Security",
                    targetScope=f"TXT @{domain}",
                    cvss="5.3",
                    cweId="CWE-358",
                    description=f"Domain '{domain}' does not publish an SPF TXT record. Attackers can forge mail claiming to originate from this domain.",
                    remediationSummary="Publish a valid SPF record specifying authorized outgoing mail servers.",
                    remediationCode=f"{domain}. IN TXT \"v=spf1 include:_spf.google.com ~all\"",
                    verificationStatus=VerificationStatus.CONFIRMED,
                    statusBadge="VERIFIED (DNS QUERY)",
                    confidence=1.0,
                )
            )
        elif spf_record:
            if "+all" in spf_record:
                findings.append(
                    SecurityFinding(
                        id=f"finding-{uuid.uuid4().hex[:8]}",
                        title="Critical SPF Misconfiguration (+all Permissive Policy)",
                        severity=SeverityLevel.CRITICAL,
                        category="DNS & Domain Security",
                        targetScope=f"TXT @{domain}",
                        cvss="9.1",
                        cweId="CWE-358",
                        codeSnippet=f"Record: {spf_record}",
                        description="The SPF record uses '+all', authorizing the entire Internet to send authenticated email on behalf of your domain.",
                        remediationSummary="Change '+all' to '~all' (SoftFail) or '-all' (Fail).",
                        remediationCode=f"{domain}. IN TXT \"v=spf1 include:your_mail_provider.com -all\"",
                        verificationStatus=VerificationStatus.CONFIRMED,
                        statusBadge="VERIFIED (SPF SYNTAX)",
                        confidence=1.0,
                    )
                )

        # 2. DMARC Check
        dmarc_domain = f"_dmarc.{domain}"
        has_dmarc = False
        dmarc_record = None
        try:
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="replace") for b in rdata.strings])
                if "v=DMARC1" in txt_str:
                    has_dmarc = True
                    dmarc_record = txt_str
                    break
        except Exception:
            pass

        if not has_dmarc:
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title="Missing DMARC Policy Record",
                    severity=SeverityLevel.MEDIUM,
                    category="DNS & Domain Security",
                    targetScope=f"TXT {dmarc_domain}",
                    cvss="5.3",
                    cweId="CWE-358",
                    description=f"No DMARC record found at '{dmarc_domain}'. Lacking DMARC allows unauthorized senders to spoof emails without receiver rejection.",
                    remediationSummary="Configure a DMARC record at _dmarc.<domain> with quarantine or reject policy.",
                    remediationCode=f"_dmarc.{domain}. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}\"",
                    verificationStatus=VerificationStatus.CONFIRMED,
                    statusBadge="VERIFIED (DNS QUERY)",
                    confidence=1.0,
                )
            )
        elif dmarc_record and "p=none" in dmarc_record:
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title="Weak DMARC Policy (p=none - Monitoring Only)",
                    severity=SeverityLevel.LOW,
                    category="DNS & Domain Security",
                    targetScope=f"TXT {dmarc_domain}",
                    cvss="3.7",
                    cweId="CWE-358",
                    codeSnippet=f"Record: {dmarc_record}",
                    description="The DMARC policy is set to 'p=none'. Unauthenticated spoofed emails are delivered to user inboxes without restriction.",
                    remediationSummary="Transition policy from 'p=none' to 'p=quarantine' or 'p=reject' once legitimate senders are verified.",
                    remediationCode=f"_dmarc.{domain}. IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}\"",
                    verificationStatus=VerificationStatus.CONFIRMED,
                    statusBadge="VERIFIED (DMARC POLICY)",
                    confidence=1.0,
                )
            )

        return findings

    def _audit_zone_transfer(self, resolver: dns.resolver.Resolver, domain: str) -> List[SecurityFinding]:
        """Test safe non-destructive AXFR zone transfer against authoritative nameservers."""
        findings: List[SecurityFinding] = []
        try:
            ns_answers = resolver.resolve(domain, "NS")
            nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answers]
        except Exception:
            return findings

        for ns in nameservers:
            try:
                # Query IP of nameserver
                ns_ips = [str(r.address) for r in resolver.resolve(ns, "A")]
                for ns_ip in ns_ips:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=3.0))
                        if zone and len(zone.nodes) > 1:
                            findings.append(
                                SecurityFinding(
                                    id=f"finding-{uuid.uuid4().hex[:8]}",
                                    title=f"Insecure DNS Zone Transfer (AXFR) Permitted on {ns}",
                                    severity=SeverityLevel.HIGH,
                                    category="DNS & Domain Security",
                                    targetScope=f"{ns} ({ns_ip})",
                                    cvss="7.5",
                                    cweId="CWE-200",
                                    codeSnippet=f"Authoritative NS: {ns} ({ns_ip})\nDisclosed Records: {len(zone.nodes)} DNS nodes leaked",
                                    description=(
                                        f"Nameserver '{ns}' permitted an unauthenticated AXFR zone transfer for domain '{domain}'. "
                                        f"This discloses the complete internal DNS topology, subdomains, and IP mappings."
                                    ),
                                    remediationSummary="Disable unrestricted AXFR zone transfers in nameserver configuration; restrict AXFR to secondary slave IP addresses.",
                                    remediationCode="# BIND9 named.conf:\nzone \"" + domain + "\" {\n    type master;\n    allow-transfer { 192.0.2.2; };\n};",
                                    verificationStatus=VerificationStatus.CONFIRMED,
                                    statusBadge="VERIFIED (AXFR EXPOSURE)",
                                    confidence=1.0,
                                    evidence={"nameserver": ns, "leakedNodeCount": len(zone.nodes)},
                                )
                            )
                            return findings  # One confirmed zone transfer is sufficient
                    except Exception:
                        continue
            except Exception:
                continue

        return findings

    async def _audit_dangling_cname(self, resolver: dns.resolver.Resolver, domain: str) -> List[SecurityFinding]:
        """Inspect CNAME records against known cloud services for takeover indicators."""
        findings: List[SecurityFinding] = []
        try:
            cname_answer = await asyncio.to_thread(resolver.resolve, domain, "CNAME")
            cname_target = str(cname_answer[0].target).rstrip(".")
        except Exception:
            return findings

        # Check if CNAME matches known provider
        matched_provider = None
        for item in TAKEOVER_SIGNATURES:
            if re.search(item["cname_pattern"], cname_target, re.IGNORECASE):
                matched_provider = item
                break

        if matched_provider:
            # Safely verify by probing HTTP response for provider unclaimed resource signature
            try:
                async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                    res = await client.get(f"http://{domain}")
                    if matched_provider["body_fingerprint"] in res.text:
                        findings.append(
                            SecurityFinding(
                                id=f"finding-{uuid.uuid4().hex[:8]}",
                                title=f"Potential Subdomain Takeover ({matched_provider['provider']} Dangling CNAME)",
                                severity=SeverityLevel.HIGH,
                                category="DNS & Domain Security",
                                targetScope=domain,
                                cvss="8.1",
                                cweId=matched_provider["cwe"],
                                codeSnippet=f"CNAME: {domain} -> {cname_target}\nProvider Fingerprint: '{matched_provider['body_fingerprint']}' observed",
                                description=(
                                    f"Domain '{domain}' points via CNAME to '{cname_target}' on {matched_provider['provider']}, "
                                    f"but the provider returned '{matched_provider['body_fingerprint']}'. An attacker could claim "
                                    f"the abandoned resource and host arbitrary malicious content under this domain."
                                ),
                                remediationSummary=f"Reclaim or remove the dangling CNAME record '{cname_target}' from DNS.",
                                verificationStatus=VerificationStatus.CONFIRMED,
                                statusBadge="VERIFIED (DANGLING CNAME)",
                                confidence=0.96,
                                evidence={"cnameTarget": cname_target, "provider": matched_provider["provider"]},
                            )
                        )
            except Exception:
                pass

        return findings
