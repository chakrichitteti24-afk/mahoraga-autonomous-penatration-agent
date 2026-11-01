"""
CipherFlux Labs Container & Kubernetes Security Scanner.
Audits Dockerfile configurations, Docker daemon/socket exposures,
Kubernetes YAML manifests, RBAC policies, and Terraform container configurations.
"""
import re
import uuid
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.models.schemas import SecurityFinding, SeverityLevel, VerificationStatus
from backend.scanners.iac_scanner import IaCScanner

class ContainerSecurityScanner:
    """
    Dedicated Container & Kubernetes Vulnerability Assessment Engine.
    Extends Infrastructure-as-Code checks to include runtime container posture,
    Kubernetes Pod Security Standards (PSS), RBAC privilege checks, and Docker socket security.
    """

    def __init__(self):
        self.iac_engine = IaCScanner()

    def scan_dockerfile_content(self, content: str, file_path: str = "Dockerfile") -> List[SecurityFinding]:
        """Audit Dockerfile content for insecure defaults."""
        return self.iac_engine.scan_dockerfile(content, file_path=file_path)

    def scan_kubernetes_manifest(self, content: str, file_path: str = "manifest.yaml") -> List[SecurityFinding]:
        """Audit Kubernetes Pod, Deployment, or Service manifests."""
        findings = self.iac_engine.scan_kubernetes_yaml(content, file_path=file_path)

        # Extended Kubernetes RBAC checks
        try:
            docs = list(yaml.safe_load_all(content))
        except Exception:
            return findings

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            meta = doc.get("metadata", {})
            name = meta.get("name", "unnamed")

            if kind in ("ClusterRole", "Role"):
                rules = doc.get("rules", [])
                for idx, rule in enumerate(rules, start=1):
                    verbs = rule.get("verbs", [])
                    resources = rule.get("resources", [])
                    api_groups = rule.get("apiGroups", [])

                    # Check wildcard cluster admin RBAC
                    if "*" in verbs and "*" in resources:
                        findings.append(
                            SecurityFinding(
                                id=f"finding-{uuid.uuid4().hex[:8]}",
                                title=f"Overly Permissive Kubernetes RBAC: Wildcard Cluster Privileges in {kind}/{name}",
                                severity=SeverityLevel.CRITICAL,
                                category="Container Security",
                                targetScope=f"{file_path}:{kind}/{name}",
                                cvss="9.8",
                                cweId="CWE-269",
                                codeSnippet=f"verbs: ['*']\nresources: ['*']",
                                description=f"Kubernetes {kind} '{name}' grants wildcard '*' verbs across all resources. Anyone bound to this role possesses full cluster administrator privileges.",
                                remediationSummary="Follow the principle of least privilege. Grant only specific read or write verbs on explicit resources.",
                                verificationStatus=VerificationStatus.CONFIRMED,
                                statusBadge="CONFIRMED (K8S RBAC WILDCARD)",
                                confidence=1.0,
                            )
                        )
                    # Check secrets access privilege
                    elif ("get" in verbs or "list" in verbs or "*" in verbs) and ("secrets" in resources or "*" in resources):
                        findings.append(
                            SecurityFinding(
                                id=f"finding-{uuid.uuid4().hex[:8]}",
                                title=f"Broad Access to Kubernetes Secrets in {kind}/{name}",
                                severity=SeverityLevel.HIGH,
                                category="Container Security",
                                targetScope=f"{file_path}:{kind}/{name}",
                                cvss="8.2",
                                cweId="CWE-200",
                                codeSnippet=f"resources: {resources}\nverbs: {verbs}",
                                description=f"Role '{name}' permits retrieving cluster secrets. Service accounts bound to this role can access sensitive credentials across the namespace.",
                                remediationSummary="Restrict secrets retrieval to dedicated credential management operators.",
                                verificationStatus=VerificationStatus.CONFIRMED,
                                statusBadge="CONFIRMED (K8S SECRETS READ)",
                                confidence=0.95,
                            )
                        )

            elif kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet"):
                spec = doc.get("spec", {})
                template = spec.get("template", spec)
                pod_spec = template.get("spec", spec)

                # Check hostPID or hostIPC
                if pod_spec.get("hostPID") is True:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Host PID Namespace Sharing Enabled in {kind}/{name}",
                            severity=SeverityLevel.HIGH,
                            category="Container Security",
                            targetScope=f"{file_path}:{kind}/{name}",
                            cvss="8.5",
                            cweId="CWE-250",
                            codeSnippet="hostPID: true",
                            description="Sharing the host process ID namespace breaks container isolation, enabling the container to inspect and kill processes running on the host node.",
                            remediationSummary="Disable hostPID unless explicitly required for privileged system node monitoring.",
                            remediationCode="hostPID: false",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="CONFIRMED (HOST PID SHARED)",
                            confidence=1.0,
                        )
                    )

        return findings

    def audit_docker_daemon_config(self, config_json: str) -> List[SecurityFinding]:
        """Audit /etc/docker/daemon.json configuration."""
        findings = []
        try:
            cfg = yaml.safe_load(config_json)
        except Exception:
            return findings

        if not isinstance(cfg, dict):
            return findings

        # Check for unauthenticated remote TCP socket
        hosts = cfg.get("hosts", [])
        for h in hosts:
            if "tcp://" in h and "0.0.0.0" in h and not cfg.get("tlsverify"):
                findings.append(
                    SecurityFinding(
                        id=f"finding-{uuid.uuid4().hex[:8]}",
                        title="Unencrypted and Unauthenticated Docker Daemon TCP Socket Exposed",
                        severity=SeverityLevel.CRITICAL,
                        category="Container Security",
                        targetScope=f"docker-daemon:{h}",
                        cvss="9.8",
                        cweId="CWE-306",
                        codeSnippet=f"hosts: {hosts}\ntlsverify: false",
                        description="Docker daemon is listening on an unauthenticated TCP socket across network interfaces. Anyone with network access can execute arbitrary containers with root privileges on the host.",
                        remediationSummary="Enable TLS mutual authentication (tlsverify: true) or restrict Docker management to local unix socket.",
                        verificationStatus=VerificationStatus.CONFIRMED,
                        statusBadge="CONFIRMED (DOCKER TCP EXPOSED)",
                        confidence=1.0,
                    )
                )

        return findings

container_scanner = ContainerSecurityScanner()
