import asyncio
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from ..models.schemas import SecurityFinding, SeverityLevel, VerificationStatus

class TLSScanner:
    """
    Dedicated SSL/TLS and Cryptographic Security Engine.
    Audits certificates, protocol handshakes, cipher suites, key sizes, and signature algorithms.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def scan_tls(self, hostname: str, port: int = 443) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []

        def inspect_socket() -> Tuple[Optional[ssl.SSLSocket], Optional[bytes], Optional[str], Optional[Tuple]]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Inspect raw cert even if untrusted/expired

            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    version = ssock.version()
                    cipher = ssock.cipher()
                    return None, cert_der, version, cipher

        try:
            _, cert_der, version, cipher = await asyncio.to_thread(inspect_socket)
        except Exception as e:
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title="TLS Handshake Failed",
                    severity=SeverityLevel.HIGH,
                    category="SSL/TLS Security",
                    targetScope=f"{hostname}:{port}",
                    cvss="5.0",
                    cweId="CWE-326",
                    description=f"Could not complete TLS handshake with {hostname}:{port}: {str(e)}",
                    remediationSummary="Verify TLS configuration and certificate installation on the server listener.",
                    verificationStatus=VerificationStatus.INCONCLUSIVE,
                    statusBadge="HANDSHAKE ERROR",
                )
            )
            return findings

        # 1. Check Protocol Version
        if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title=f"Deprecated TLS Protocol Negotiated ({version})",
                    severity=SeverityLevel.HIGH,
                    category="SSL/TLS Security",
                    targetScope=f"{hostname}:{port}",
                    cvss="7.4",
                    cweId="CWE-326",
                    codeSnippet=f"Protocol: {version}\nCipher Suite: {cipher[0] if cipher else 'Unknown'}",
                    description=f"The server negotiates connections using legacy {version}. These protocols are formally deprecated by IETF RFC 8996 due to known attacks (POODLE, BEAST).",
                    remediationSummary="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enforce TLS 1.2 minimum and enable TLS 1.3.",
                    remediationCode="ssl_protocols TLSv1.2 TLSv1.3;",
                    verificationStatus=VerificationStatus.CONFIRMED,
                    statusBadge="VERIFIED (SOCKET PROBE)",
                    confidence=1.0,
                )
            )

        # 2. Check Cipher Suite Weaknesses
        if cipher and cipher[0]:
            cipher_name = cipher[0].upper()
            weak_ciphers = ["RC4", "3DES", "DES", "EXPORT", "NULL", "MD5"]
            if any(w in cipher_name for w in weak_ciphers):
                findings.append(
                    SecurityFinding(
                        id=f"finding-{uuid.uuid4().hex[:8]}",
                        title=f"Insecure Cipher Suite Negotiated ({cipher_name})",
                        severity=SeverityLevel.HIGH,
                        category="SSL/TLS Security",
                        targetScope=f"{hostname}:{port}",
                        cvss="7.5",
                        cweId="CWE-327",
                        codeSnippet=f"Negotiated Cipher: {cipher_name}",
                        description=f"The server negotiated an insecure cipher suite containing weak algorithms: {cipher_name}.",
                        remediationSummary="Remove weak ciphers and configure secure modern AEAD ciphers (e.g. ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384).",
                        remediationCode="ssl_ciphers 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA';",
                        verificationStatus=VerificationStatus.CONFIRMED,
                        statusBadge="VERIFIED (SOCKET PROBE)",
                        confidence=1.0,
                    )
                )

        # 3. Analyze Certificate Details via Cryptography
        if cert_der:
            try:
                cert = x509.load_der_x509_certificate(cert_der)
                now = datetime.now(timezone.utc)
                
                # Check expiration
                not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
                not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)

                if now > not_after:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title="Expired SSL/TLS Certificate",
                            severity=SeverityLevel.CRITICAL,
                            category="SSL/TLS Security",
                            targetScope=f"{hostname}:{port}",
                            cvss="9.1",
                            cweId="CWE-298",
                            codeSnippet=f"Not After: {not_after.isoformat()}\nCurrent Time: {now.isoformat()}",
                            description=f"The certificate expired on {not_after.strftime('%Y-%m-%d')}. Browsers and API clients will reject connections with certificate trust errors.",
                            remediationSummary="Renew and replace the expired certificate immediately.",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="VERIFIED (CERTIFICATE)",
                            confidence=1.0,
                        )
                    )
                else:
                    days_remaining = (not_after - now).days
                    if days_remaining < 30:
                        findings.append(
                            SecurityFinding(
                                id=f"finding-{uuid.uuid4().hex[:8]}",
                                title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} Days Remaining)",
                                severity=SeverityLevel.MEDIUM,
                                category="SSL/TLS Security",
                                targetScope=f"{hostname}:{port}",
                                cvss="5.3",
                                cweId="CWE-298",
                                codeSnippet=f"Valid Until: {not_after.isoformat()} ({days_remaining} days remaining)",
                                description=f"The SSL certificate will expire in {days_remaining} days. Unattended expiration will cause service outage and client errors.",
                                remediationSummary="Schedule certificate renewal before expiration or configure automated renewal (e.g. Certbot / ACME).",
                                verificationStatus=VerificationStatus.CONFIRMED,
                                statusBadge="WARNING (EXPIRING)",
                                confidence=1.0,
                            )
                        )

                # Check Self-Signed Certificate
                if cert.issuer == cert.subject:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title="Self-Signed SSL/TLS Certificate in Use",
                            severity=SeverityLevel.MEDIUM,
                            category="SSL/TLS Security",
                            targetScope=f"{hostname}:{port}",
                            cvss="5.3",
                            cweId="CWE-295",
                            codeSnippet=f"Subject: {cert.subject.rfc4514_string()}\nIssuer: {cert.issuer.rfc4514_string()}",
                            description="The certificate issuer matches the subject (self-signed). Clients without a custom root CA installed will reject connections.",
                            remediationSummary="Replace self-signed certificates with certificates issued by a trusted public Certificate Authority (e.g. Let's Encrypt).",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="VERIFIED (SELF-SIGNED)",
                            confidence=1.0,
                        )
                    )

                # Check Key Length
                pub_key = cert.public_key()
                if isinstance(pub_key, rsa.RSAPublicKey):
                    if pub_key.key_size < 2048:
                        findings.append(
                            SecurityFinding(
                                id=f"finding-{uuid.uuid4().hex[:8]}",
                                title=f"Weak RSA Key Size ({pub_key.key_size} bits)",
                                severity=SeverityLevel.HIGH,
                                category="SSL/TLS Security",
                                targetScope=f"{hostname}:{port}",
                                cvss="7.5",
                                cweId="CWE-326",
                                codeSnippet=f"Key Algorithm: RSA\nKey Size: {pub_key.key_size} bits (Minimum required: 2048 bits)",
                                description=f"RSA key size of {pub_key.key_size} bits does not provide adequate security margin against modern cryptanalysis.",
                                remediationSummary="Generate a new private key with a minimum size of 2048 bits (or preferably 3072/4096 bits) or use ECDSA (P-256/P-384).",
                                verificationStatus=VerificationStatus.CONFIRMED,
                                statusBadge="VERIFIED (KEY SIZE)",
                                confidence=1.0,
                            )
                        )

                # Check Signature Hash Algorithm
                sig_hash = getattr(cert.signature_hash_algorithm, "name", "").lower()
                if sig_hash in ("md5", "sha1"):
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Deprecated Certificate Signature Hash ({sig_hash.upper()})",
                            severity=SeverityLevel.HIGH,
                            category="SSL/TLS Security",
                            targetScope=f"{hostname}:{port}",
                            cvss="7.4",
                            cweId="CWE-328",
                            codeSnippet=f"Signature Algorithm: {cert.signature_algorithm_oid._name}\nHash: {sig_hash}",
                            description=f"Certificate was signed using broken {sig_hash.upper()} digest algorithm, susceptible to collision forgery.",
                            remediationSummary="Re-issue certificate using SHA-256 or stronger signature digest.",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="VERIFIED (SIGNATURE HASH)",
                            confidence=1.0,
                        )
                    )

            except Exception:
                pass

        return findings
