import asyncio
import socket
import uuid
from typing import List, Dict, Any, Optional

from ..models.schemas import SecurityFinding, SeverityLevel, VerificationStatus
from ..core.safety import SecurityScopeEnforcer

# Common critical and high-risk service ports to audit
DEFAULT_PORT_REGISTRY = {
    21: {"service": "FTP", "risk": SeverityLevel.HIGH, "cwe": "CWE-319", "desc": "Unencrypted File Transfer Protocol (FTP) detected. Credentials and data sent in cleartext."},
    22: {"service": "SSH", "risk": SeverityLevel.INFORMATIONAL, "cwe": "CWE-200", "desc": "SSH management port exposed."},
    23: {"service": "Telnet", "risk": SeverityLevel.CRITICAL, "cwe": "CWE-319", "desc": "Insecure legacy Telnet service exposed. Communication is unencrypted and vulnerable to credential sniffing."},
    25: {"service": "SMTP", "risk": SeverityLevel.LOW, "cwe": "CWE-200", "desc": "SMTP Mail Transfer Agent service open."},
    80: {"service": "HTTP", "risk": SeverityLevel.MEDIUM, "cwe": "CWE-319", "desc": "Plaintext HTTP port active. Unencrypted web transport."},
    445: {"service": "SMB", "risk": SeverityLevel.HIGH, "cwe": "CWE-200", "desc": "Direct-hosted SMB service exposed to network interface."},
    1433: {"service": "MSSQL", "risk": SeverityLevel.HIGH, "cwe": "CWE-200", "desc": "Microsoft SQL Server database listener directly accessible over network."},
    1521: {"service": "Oracle-DB", "risk": SeverityLevel.HIGH, "cwe": "CWE-200", "desc": "Oracle Database listener exposed on network boundary."},
    3306: {"service": "MySQL", "risk": SeverityLevel.HIGH, "cwe": "CWE-200", "desc": "MySQL database port exposed externally. Potential brute-force or injection vector."},
    3389: {"service": "RDP", "risk": SeverityLevel.HIGH, "cwe": "CWE-200", "desc": "Remote Desktop Protocol (RDP) service exposed. Common target for credential stuffing."},
    5432: {"service": "PostgreSQL", "risk": SeverityLevel.HIGH, "cwe": "CWE-200", "desc": "PostgreSQL database port accessible across network."},
    6379: {"service": "Redis", "risk": SeverityLevel.CRITICAL, "cwe": "CWE-306", "desc": "Redis in-memory store exposed. Frequently lacks authentication leading to arbitrary command execution or data wipeout."},
    8080: {"service": "HTTP-Alt", "risk": SeverityLevel.LOW, "cwe": "CWE-200", "desc": "Alternate HTTP / proxy port active."},
    9200: {"service": "Elasticsearch", "risk": SeverityLevel.CRITICAL, "cwe": "CWE-306", "desc": "Elasticsearch cluster REST API exposed. Risk of unauthenticated document exfiltration."},
    27017: {"service": "MongoDB", "risk": SeverityLevel.CRITICAL, "cwe": "CWE-306", "desc": "MongoDB database listener active. Frequently misconfigured without authentication."},
}

class NetworkScanner:
    """
    Authorized Network Vulnerability Assessment Engine.
    Executes controlled socket probes to identify open ports, service banners,
    and exposure of insecure or sensitive administrative services.
    Strictly passive and non-destructive.
    """

    def __init__(self, timeout: float = 3.0, max_concurrency: int = 10):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self._semaphore = None

    @property
    def semaphore(self):
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
        return self._semaphore

    async def scan_host(
        self,
        target_host: str,
        ports: Optional[List[int]] = None,
        authorized_by: Optional[str] = "operator"
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        # Scope safety check
        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(target_host)
        if not is_safe:
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title="Network Scan Aborted: Safety Boundary Enforced",
                    severity=SeverityLevel.INFORMATIONAL,
                    category="Network Vulnerability Assessment",
                    targetScope=target_host,
                    cvss="0.0",
                    description=f"Scan rejected by safety policy: {msg}",
                    remediationSummary="Verify network boundaries and provide an authorized target.",
                    verificationStatus=VerificationStatus.NOT_TESTED,
                    statusBadge="SCOPE BLOCKED",
                )
            )
            return findings

        ports_to_test = ports or list(DEFAULT_PORT_REGISTRY.keys())

        # Test ports concurrently
        tasks = [self._probe_port(target_host, port) for port in ports_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, SecurityFinding):
                findings.append(res)

        return findings

    async def _probe_port(self, target_host: str, port: int) -> Optional[SecurityFinding]:
        async with self.semaphore:
            try:
                conn_coro = asyncio.open_connection(target_host, port)
                reader, writer = await asyncio.wait_for(conn_coro, timeout=self.timeout)

                # Attempt safe non-destructive banner grab
                banner = ""
                try:
                    # Send newline or generic probe
                    writer.write(b"\r\n")
                    await writer.drain()
                    banner_bytes = await asyncio.wait_for(reader.read(256), timeout=1.0)
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                port_meta = DEFAULT_PORT_REGISTRY.get(port, {
                    "service": f"TCP/{port}",
                    "risk": SeverityLevel.LOW,
                    "cwe": "CWE-200",
                    "desc": f"Unexpected open port {port} exposed on host."
                })

                code_snippet = f"Port: {port}/TCP\nState: OPEN\nService: {port_meta['service']}"
                if banner:
                    code_snippet += f"\nBanner: {banner[:100]}"

                return SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title=f"Insecure Service Exposure: {port_meta['service']} on Port {port}",
                    severity=port_meta["risk"],
                    category="Network Vulnerability Assessment",
                    targetScope=f"{target_host}:{port}",
                    cvss="9.1" if port_meta["risk"] == SeverityLevel.CRITICAL else ("7.5" if port_meta["risk"] == SeverityLevel.HIGH else "4.3"),
                    cweId=port_meta["cwe"],
                    codeSnippet=code_snippet,
                    description=f"{port_meta['desc']} Target host accepts inbound TCP connections on port {port}.",
                    remediationSummary=f"Restrict access to port {port} using firewall or security group rules, or bind service to localhost (127.0.0.1) only.",
                    remediationCode=f"# Linux iptables / ufw firewall restriction:\nufw deny {port}/tcp",
                    verificationStatus=VerificationStatus.CONFIRMED,
                    statusBadge="VERIFIED (SOCKET CONNECTED)",
                    confidence=1.0,
                    evidence={"port": port, "banner": banner, "socketStatus": "CONNECTED"},
                )

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                # Port closed or filtered
                return None
