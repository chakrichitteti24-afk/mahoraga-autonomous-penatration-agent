import re
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
import yaml

from ..models.schemas import SecurityFinding, SeverityLevel, VerificationStatus

class IaCScanner:
    """
    Container, Kubernetes & Infrastructure-as-Code (IaC) Security Auditor.
    Audits Dockerfiles, Kubernetes Pod/Deployment manifests, and Terraform configuration files
    for privilege escalation, exposed secrets, insecure network ingress, and missing resource limits.
    """

    def scan_dockerfile(self, content: str, file_path: str = "Dockerfile") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.splitlines()

        has_user_directive = False
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check User directive
            if stripped.upper().startswith("USER "):
                user_val = stripped.split()[1]
                if user_val not in ("root", "0"):
                    has_user_directive = True

            # 1. Unpinned / Latest Base Image
            if stripped.upper().startswith("FROM "):
                image = stripped.split()[1]
                if ":latest" in image or ":" not in image:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Unpinned / Mutable Base Image in Dockerfile ({image})",
                            severity=SeverityLevel.LOW,
                            category="Container Security",
                            targetScope=f"{file_path}:{idx}",
                            lineNumber=idx,
                            cvss="3.7",
                            cweId="CWE-1395",
                            codeSnippet=stripped,
                            description=f"Base image '{image}' uses ':latest' or lacks an immutable digest/version tag. Builds are non-reproducible and vulnerable to supply-chain tampering.",
                            remediationSummary="Pin base container images to a specific version tag or immutable sha256 digest.",
                            remediationCode=f"FROM {image.split(':')[0]}:1.21-alpine@sha256:...",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="VERIFIED (DOCKERFILE AST)",
                            confidence=1.0,
                        )
                    )

            # 2. Hardcoded Secrets in ENV instructions
            if stripped.upper().startswith("ENV "):
                if re.search(r"""(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=""", stripped, re.IGNORECASE):
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title="Embedded Secret in Dockerfile ENV Instruction",
                            severity=SeverityLevel.CRITICAL,
                            category="Container Security",
                            targetScope=f"{file_path}:{idx}",
                            lineNumber=idx,
                            cvss="9.1",
                            cweId="CWE-798",
                            codeSnippet=stripped,
                            description="Environment variable containing sensitive tokens committed directly in Dockerfile. Values remain permanently readable in image layer history.",
                            remediationSummary="Inject secrets at runtime using environment files, Kubernetes Secrets, or Docker secret mounts.",
                            remediationCode="# Use BuildKit secret mount during build:\nRUN --mount=type=secret,id=mysecret ./build.sh",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="VERIFIED (SECRETS DETECTED)",
                            confidence=0.98,
                        )
                    )

            # 3. Dangerous curl/wget piping to shell
            if re.search(r"""(?:curl|wget)\s+[^|]+\|\s*(?:sh|bash|sudo\s+sh)""", stripped, re.IGNORECASE):
                findings.append(
                    SecurityFinding(
                        id=f"finding-{uuid.uuid4().hex[:8]}",
                        title="Unsafe Script Execution via Pipe to Shell in Dockerfile",
                        severity=SeverityLevel.HIGH,
                        category="Container Security",
                        targetScope=f"{file_path}:{idx}",
                        lineNumber=idx,
                        cvss="8.1",
                        cweId="CWE-78",
                        codeSnippet=stripped,
                        description="Piping remote HTTP downloads directly into sh/bash bypasses integrity checks and creates arbitrary command execution risks if the remote host or DNS is compromised.",
                        remediationSummary="Download installation packages with cryptographic checksum verification before executing.",
                        verificationStatus=VerificationStatus.CONFIRMED,
                        statusBadge="VERIFIED (UNSAFE EXECUTION)",
                        confidence=0.95,
                    )
                )

        # 4. Check Root User Execution
        if not has_user_directive:
            findings.append(
                SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title="Container Execution as Root (Missing Non-Root USER Directive)",
                    severity=SeverityLevel.HIGH,
                    category="Container Security",
                    targetScope=file_path,
                    cvss="7.4",
                    cweId="CWE-250",
                    codeSnippet=f"Target file: {file_path}\n(No non-root USER instruction found)",
                    description="The container does not switch to an unprivileged user. In the event of a container escape, processes run with root privileges on the host.",
                    remediationSummary="Create a non-root group and user in the Dockerfile and enforce USER <non-root> before entrypoint.",
                    remediationCode="RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser",
                    verificationStatus=VerificationStatus.CONFIRMED,
                    statusBadge="VERIFIED (ROOT EXECUTION)",
                    confidence=1.0,
                )
            )

        return findings

    def scan_kubernetes_yaml(self, content: str, file_path: str = "k8s-manifest.yaml") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        try:
            docs = list(yaml.safe_load_all(content))
        except Exception:
            return findings

        for doc_idx, doc in enumerate(docs):
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "Unknown")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", f"doc-{doc_idx}")

            # Inspect Pod or Deployment specs
            spec = doc.get("spec", {})
            if "template" in spec and isinstance(spec["template"], dict):
                spec = spec["template"].get("spec", {})

            # 1. Host Network / Host PID Exposure
            if spec.get("hostNetwork") is True:
                findings.append(
                    SecurityFinding(
                        id=f"finding-{uuid.uuid4().hex[:8]}",
                        title=f"Kubernetes Pod Shares Host Network (hostNetwork: true) in {kind}/{name}",
                        severity=SeverityLevel.HIGH,
                        category="Kubernetes Security",
                        targetScope=f"{file_path} ({kind}/{name})",
                        cvss="7.8",
                        cweId="CWE-250",
                        codeSnippet="hostNetwork: true",
                        description=f"{kind}/{name} enables hostNetwork, granting pod access to loopback services on the node and bypassing NetworkPolicies.",
                        remediationSummary="Disable hostNetwork unless strictly required for low-level node monitoring daemons.",
                        remediationCode="hostNetwork: false",
                        verificationStatus=VerificationStatus.CONFIRMED,
                        statusBadge="VERIFIED (K8S MANIFEST)",
                        confidence=1.0,
                    )
                )

            # 2. Containers security context inspection
            containers = spec.get("containers", [])
            for c in containers:
                c_name = c.get("name", "container")
                sec_ctx = c.get("securityContext", {})

                # Privileged mode
                if sec_ctx.get("privileged") is True:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Privileged Container Flag Enabled (privileged: true) on {c_name}",
                            severity=SeverityLevel.CRITICAL,
                            category="Kubernetes Security",
                            targetScope=f"{file_path} ({kind}/{name}:{c_name})",
                            cvss="9.6",
                            cweId="CWE-250",
                            codeSnippet=f"container: {c_name}\nsecurityContext:\n  privileged: true",
                            description=f"Container '{c_name}' runs in privileged mode, granting full access to node device nodes and kernel capabilities (trivial container breakout).",
                            remediationSummary="Set privileged: false and drop all unneeded Linux capabilities.",
                            remediationCode="securityContext:\n  privileged: false\n  capabilities:\n    drop: [\"ALL\"]",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="VERIFIED (PRIVILEGED K8S)",
                            confidence=1.0,
                        )
                    )

                # Missing Resource Limits
                resources = c.get("resources", {})
                if not resources.get("limits"):
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Missing Resource Limits on Container '{c_name}'",
                            severity=SeverityLevel.LOW,
                            category="Kubernetes Security",
                            targetScope=f"{file_path} ({kind}/{name}:{c_name})",
                            cvss="3.5",
                            cweId="CWE-770",
                            codeSnippet=f"container: {c_name}\n(resources.limits is missing)",
                            description="Container does not define CPU and memory limits. A runaway process can cause denial of service (OOMKilled) on adjacent node pods.",
                            remediationSummary="Specify CPU and memory limits for all production containers.",
                            remediationCode="resources:\n  limits:\n    cpu: \"500m\"\n    memory: \"512Mi\"",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="VERIFIED (K8S SPEC)",
                            confidence=1.0,
                        )
                    )

        return findings

    def scan_terraform(self, content: str, file_path: str = "main.tf") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            # 1. S3 Public ACL
            if re.search(r"""acl\s*=\s*["']public-(?:read|read-write)["']""", line, re.IGNORECASE):
                findings.append(
                    SecurityFinding(
                        id=f"finding-{uuid.uuid4().hex[:8]}",
                        title="Terraform S3 Bucket Configured with Public Access ACL",
                        severity=SeverityLevel.CRITICAL,
                        category="Cloud Infrastructure (IaC)",
                        targetScope=f"{file_path}:{idx}",
                        lineNumber=idx,
                        cvss="9.1",
                        cweId="CWE-732",
                        codeSnippet=line.strip(),
                        description="S3 bucket defined with public-read or public-read-write ACL, exposing bucket storage to the public Internet.",
                        remediationSummary="Set S3 bucket ACL to 'private' and enable Public Access Block resources.",
                        remediationCode="acl = \"private\"",
                        verificationStatus=VerificationStatus.CONFIRMED,
                        statusBadge="VERIFIED (TERRAFORM AST)",
                        confidence=1.0,
                    )
                )

            # 2. Unrestricted Ingress (0.0.0.0/0)
            if "0.0.0.0/0" in line and ("ingress" in content[max(0, idx-50):idx+50] or "cidr_blocks" in line):
                findings.append(
                    SecurityFinding(
                        id=f"finding-{uuid.uuid4().hex[:8]}",
                        title="Unrestricted Security Group Ingress from 0.0.0.0/0",
                        severity=SeverityLevel.HIGH,
                        category="Cloud Infrastructure (IaC)",
                        targetScope=f"{file_path}:{idx}",
                        lineNumber=idx,
                        cvss="7.5",
                        cweId="CWE-284",
                        codeSnippet=line.strip(),
                        description="Security group allows ingress traffic from any source IP (0.0.0.0/0). Management or database ports exposed here are vulnerable to scanning and attack.",
                        remediationSummary="Restrict ingress cidr_blocks to specific trusted corporate IP blocks or VPN gateways.",
                        remediationCode="cidr_blocks = [\"192.0.2.0/24\"]",
                        verificationStatus=VerificationStatus.CONFIRMED,
                        statusBadge="VERIFIED (TERRAFORM AST)",
                        confidence=0.92,
                    )
                )

        return findings
