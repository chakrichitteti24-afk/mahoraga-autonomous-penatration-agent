import pytest
from cipherflux.scanners.cloud_scanner import CloudSecurityScanner
from cipherflux.scanners.container_scanner import ContainerSecurityScanner
from backend.models.schemas import SeverityLevel, VerificationStatus

def test_cloud_scanner_detects_iam_wildcard_admin():
    scanner = CloudSecurityScanner()
    vulnerable_policy = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }"""
    findings = scanner.audit_iam_policy_document(vulnerable_policy)
    assert len(findings) >= 1
    assert any(f.severity == SeverityLevel.CRITICAL for f in findings)
    assert any(f.cweId == "CWE-732" for f in findings)
    assert any("unrestricted administrator" in f.title.lower() for f in findings)

def test_cloud_scanner_safe_iam_policy_negative():
    scanner = CloudSecurityScanner()
    safe_policy = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-secure-bucket/*"]
            }
        ]
    }"""
    findings = scanner.audit_iam_policy_document(safe_policy)
    assert len(findings) == 0

def test_cloud_scanner_detects_open_security_group_ports():
    scanner = CloudSecurityScanner()
    sg_json = """{
        "IpPermissions": [
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            },
            {
                "FromPort": 5432,
                "ToPort": 5432,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }"""
    findings = scanner.audit_security_group_rules(sg_json)
    assert len(findings) == 2
    assert any("SSH" in f.title for f in findings)
    assert any("PostgreSQL" in f.title for f in findings)

def test_container_scanner_dockerfile_ast():
    scanner = ContainerSecurityScanner()
    dockerfile_bad = """
    FROM node:latest
    ENV DB_PASSWORD=SecretPassword123!
    RUN curl -s http://example.com/install.sh | bash
    EXPOSE 8080
    CMD ["node", "server.js"]
    """
    findings = scanner.scan_dockerfile_content(dockerfile_bad)
    assert len(findings) >= 3
    # Check latest tag
    assert any("Unpinned" in f.title for f in findings)
    # Check embedded secret
    assert any("Embedded Secret" in f.title for f in findings)
    # Check pipe to shell
    assert any("Pipe to Shell" in f.title for f in findings)

def test_container_scanner_dockerfile_safe_negative():
    scanner = ContainerSecurityScanner()
    dockerfile_good = """
    FROM node:20.11.0-alpine@sha256:73...
    WORKDIR /app
    COPY package*.json ./
    RUN npm ci --only=production
    COPY . .
    USER node
    EXPOSE 8080
    CMD ["node", "index.js"]
    """
    findings = scanner.scan_dockerfile_content(dockerfile_good)
    # None of the critical/high rules should fire
    assert not any(f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for f in findings)

def test_container_scanner_kubernetes_rbac_wildcard():
    scanner = ContainerSecurityScanner()
    manifest = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  hostPID: true
  containers:
  - name: test
    image: alpine:3.19
"""
    findings = scanner.scan_kubernetes_manifest(manifest)
    assert len(findings) >= 2
    assert any("Wildcard Cluster Privileges" in f.title for f in findings)
    assert any("Host PID Namespace" in f.title for f in findings)
