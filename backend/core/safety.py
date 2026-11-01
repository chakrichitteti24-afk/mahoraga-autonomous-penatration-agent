import ipaddress
import re
import socket
import urllib.parse
from typing import Dict, Any, Optional, Tuple, List

from ..config import settings

# Cloud metadata endpoints that must strictly NEVER be queried
BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.gcp.internal",
    "100.100.100.200",  # Alibaba cloud metadata
}

# Regex patterns for redacting sensitive secrets in logs and reports
REDACTION_PATTERNS = [
    # AWS Access Keys
    (re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), r"\1****************"),
    # AWS Secret Key
    (re.compile(r"""(?i)(aws_secret_access_key|secret_key|secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"""), r"\1: [REDACTED_AWS_SECRET]"),
    # Generic Bearer Tokens / JWT
    (re.compile(r"Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*)", re.IGNORECASE), "Bearer [REDACTED_JWT_TOKEN]"),
    # Generic API Keys / Passwords
    (re.compile(r"""(?i)(password|passwd|pwd|api_key|apikey|token|secret)\s*[:=]\s*["']?([^"'\s,;]{4,})["']?"""), r"\1: [REDACTED_SECRET]"),
    # Private Key blocks
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY-----\n[REDACTED_CRYPTOGRAPHIC_KEY]\n-----END PRIVATE KEY-----"),
    # Set-Cookie Session tokens
    (re.compile(r"""(?i)(set-cookie:\s*[^=]+)=([^;\r\n]+)"""), r"\1=[REDACTED_COOKIE]"),
]

class SecurityScopeEnforcer:
    """
    Enforces scanning safety, explicit authorization boundaries,
    and protects against SSRF and unintended network side-effects.
    """

    @staticmethod
    def validate_authorization(authorized_by: Optional[str]) -> Tuple[bool, str]:
        """Verify that an audit operator or client identity has provided explicit authorization."""
        if not settings.enforce_authorization_checks:
            return True, "Authorization check disabled by configuration."
        if not authorized_by or authorized_by.strip() == "":
            return False, "Target assessment rejected: Explicit scanning authorization is required."
        return True, f"Scan authorized by operator: '{authorized_by}'."

    @staticmethod
    def validate_target_safety(target_url_or_host: str) -> Tuple[bool, str]:
        """
        Verify target host to prevent DNS rebinding, cloud metadata exfiltration,
        and unauthorized internal infrastructure pivoting.
        """
        target = target_url_or_host.strip()
        parsed = urllib.parse.urlparse(target)
        hostname = parsed.hostname or parsed.netloc.split(":")[0] or target

        # 1. Block known cloud metadata IP addresses and hostnames unconditionally
        if hostname.lower() in BLOCKED_METADATA_HOSTS:
            return False, f"Target safety policy violation: Access to cloud metadata service '{hostname}' is blocked."

        # 2. Resolve target IP to check for private / loopback addresses
        try:
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)

            if ip_str in BLOCKED_METADATA_HOSTS:
                return False, f"Target resolved to blocked metadata service IP: {ip_str}."

            if ip_obj.is_link_local:
                return False, f"Target IP {ip_str} is a link-local address. Network policy blocks assessment."

            if (ip_obj.is_private or ip_obj.is_loopback) and not settings.allow_private_ip_scans:
                return False, f"Target IP {ip_str} is within private RFC 1918 / loopback space and private scans are disabled."

        except socket.gaierror:
            # If domain cannot be resolved at pre-check, we allow caller to handle connection error
            pass

        return True, "Target URL is within authorized scanning boundaries."

    @staticmethod
    def redact_sensitive_string(content: Optional[str]) -> Optional[str]:
        """Redact API keys, tokens, passwords, and private keys from any output text."""
        if not content:
            return content
        redacted = content
        for pattern, replacement in REDACTION_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    @classmethod
    def redact_finding_evidence(cls, finding_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact sensitive tokens from finding evidence dictionaries."""
        sanitized = {}
        for key, value in finding_dict.items():
            if isinstance(value, str):
                sanitized[key] = cls.redact_sensitive_string(value)
            elif isinstance(value, dict):
                sanitized[key] = cls.redact_finding_evidence(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    cls.redact_sensitive_string(item) if isinstance(item, str)
                    else (cls.redact_finding_evidence(item) if isinstance(item, dict) else item)
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized
