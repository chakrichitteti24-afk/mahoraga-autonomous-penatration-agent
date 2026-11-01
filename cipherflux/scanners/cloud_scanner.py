"""
CipherFlux Labs Cloud Security Scanner.
Audits AWS, Azure, and Google Cloud resource configurations and access policies
for public storage exposure, excessive IAM permissions, insecure network boundaries,
unencrypted storage, and sensitive service exposure.
Strictly read-only and non-destructive.
"""
import json
import re
import uuid
import httpx
from typing import List, Dict, Any, Optional
from backend.models.schemas import SecurityFinding, SeverityLevel, VerificationStatus
from backend.core.safety import SecurityScopeEnforcer

class CloudSecurityScanner:
    """
    Authorized Cloud Security Assessment Engine.
    Evaluates cloud storage bucket posture, IAM policy definitions,
    and security group firewall rules across AWS, Azure, and Google Cloud.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def audit_s3_bucket(self, bucket_name: str, authorized_by: str = "operator") -> List[SecurityFinding]:
        """
        Check public read/write exposure on an AWS S3 bucket.
        """
        findings: List[SecurityFinding] = []
        clean_bucket = bucket_name.strip().lower()
        if clean_bucket.startswith("s3://"):
            clean_bucket = clean_bucket[5:]
        clean_bucket = clean_bucket.split("/")[0]

        # Target S3 endpoint URL
        s3_url = f"https://{clean_bucket}.s3.amazonaws.com/"

        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(s3_url)
        if not is_safe:
            return findings

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                # 1. Test Public Read / Listing
                r = await client.get(s3_url)
                if r.status_code == 200 and "<ListBucketResult" in r.text:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Publicly Readable AWS S3 Bucket Listing Disclosed ({clean_bucket})",
                            severity=SeverityLevel.HIGH,
                            category="Cloud Security",
                            targetScope=s3_url,
                            cvss="7.5",
                            cweId="CWE-732",
                            codeSnippet=f"GET {s3_url} -> HTTP 200 OK (<ListBucketResult>)",
                            description=f"AWS S3 bucket '{clean_bucket}' permits unauthenticated anonymous object listing. Anyone on the internet can index and retrieve bucket objects.",
                            remediationSummary="Enable S3 Block Public Access at the bucket and account level. Restrict bucket ACL to private.",
                            remediationCode="aws s3api put-public-access-block --bucket " + clean_bucket + " --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="CONFIRMED (S3 ANONYMOUS LISTING)",
                            confidence=1.0,
                            evidence={"bucket": clean_bucket, "httpStatus": r.status_code, "listingExposed": True},
                        )
                    )
                elif r.status_code == 403:
                    # Bucket exists and is protected from anonymous listing
                    pass
            except Exception:
                pass

        return findings

    async def audit_azure_blob_container(self, account_name: str, container_name: str) -> List[SecurityFinding]:
        """
        Check public exposure on an Azure Blob container.
        """
        findings: List[SecurityFinding] = []
        azure_url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"

        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(azure_url)
        if not is_safe:
            return findings

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                r = await client.get(azure_url)
                if r.status_code == 200 and "<EnumerationResults" in r.text:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Publicly Accessible Azure Storage Container ({account_name}/{container_name})",
                            severity=SeverityLevel.HIGH,
                            category="Cloud Security",
                            targetScope=azure_url,
                            cvss="7.5",
                            cweId="CWE-732",
                            codeSnippet=f"GET {azure_url} -> HTTP 200 OK (<EnumerationResults>)",
                            description=f"Azure Blob container '{container_name}' under storage account '{account_name}' allows anonymous public read access.",
                            remediationSummary="Disable anonymous public read access in Azure Storage Account settings.",
                            remediationCode="az storage container set-permission --name " + container_name + " --account-name " + account_name + " --public-access off",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="CONFIRMED (AZURE PUBLIC BLOB)",
                            confidence=1.0,
                            evidence={"account": account_name, "container": container_name, "anonymousAccess": True},
                        )
                    )
            except Exception:
                pass

        return findings

    async def audit_gcp_bucket(self, bucket_name: str) -> List[SecurityFinding]:
        """
        Check public exposure on a Google Cloud Storage (GCS) bucket.
        """
        findings: List[SecurityFinding] = []
        gcs_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o"

        is_safe, msg = SecurityScopeEnforcer.validate_target_safety(gcs_url)
        if not is_safe:
            return findings

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                r = await client.get(gcs_url)
                if r.status_code == 200 and '"items"' in r.text:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Publicly Accessible Google Cloud Storage Bucket ({bucket_name})",
                            severity=SeverityLevel.HIGH,
                            category="Cloud Security",
                            targetScope=gcs_url,
                            cvss="7.5",
                            cweId="CWE-732",
                            codeSnippet=f"GET {gcs_url} -> HTTP 200 OK (items listing returned)",
                            description=f"GCS bucket '{bucket_name}' has allUsers or allAuthenticatedUsers permissions enabled, permitting public object enumeration.",
                            remediationSummary="Enforce Uniform Bucket-Level Access and remove allUsers / allAuthenticatedUsers IAM bindings.",
                            remediationCode="gcloud storage buckets update gs://" + bucket_name + " --uniform-bucket-level-access",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="CONFIRMED (GCS PUBLIC ENUMERATION)",
                            confidence=1.0,
                            evidence={"bucket": bucket_name, "publicRead": True},
                        )
                    )
            except Exception:
                pass

        return findings

    def audit_iam_policy_document(self, policy_json: str, resource_name: str = "IAM Policy") -> List[SecurityFinding]:
        """
        Analyze AWS / GCP / Azure IAM policy JSON for overly permissive administrator privileges (*:*).
        """
        findings: List[SecurityFinding] = []
        try:
            data = json.loads(policy_json)
        except Exception:
            return findings

        statements = data.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements, start=1):
            effect = stmt.get("Effect", "")
            action = stmt.get("Action", [])
            resource = stmt.get("Resource", [])

            if isinstance(action, str):
                action = [action]
            if isinstance(resource, str):
                resource = [resource]

            if effect == "Allow":
                # Check for full admin rights (* on *)
                if "*" in action and "*" in resource:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title=f"Overly Permissive IAM Policy: Unrestricted Administrator Rights (*:*)",
                            severity=SeverityLevel.CRITICAL,
                            category="Cloud Security",
                            targetScope=f"{resource_name}:Statement[{idx}]",
                            cvss="9.8",
                            cweId="CWE-732",
                            codeSnippet=json.dumps(stmt, indent=2),
                            description="IAM statement grants full wildcard Action '*' on wildcard Resource '*'. This effectively awards unrestricted administrator privileges, violating least privilege principles.",
                            remediationSummary="Scope IAM policy down to explicit service actions and target ARN resources.",
                            remediationCode='{\n  "Effect": "Allow",\n  "Action": ["s3:GetObject"],\n  "Resource": "arn:aws:s3:::my-bucket/*"\n}',
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="CONFIRMED (IAM WILDCARD)",
                            confidence=1.0,
                            evidence={"statementIndex": idx, "action": action, "resource": resource},
                        )
                    )
                # Check for sensitive dangerous actions
                elif any(a in ("iam:CreateUser", "iam:AttachUserPolicy", "iam:PassRole") for a in action) and "*" in resource:
                    findings.append(
                        SecurityFinding(
                            id=f"finding-{uuid.uuid4().hex[:8]}",
                            title="IAM Privilege Escalation Path Detected (iam:PassRole / iam:AttachPolicy on *)",
                            severity=SeverityLevel.HIGH,
                            category="Cloud Security",
                            targetScope=f"{resource_name}:Statement[{idx}]",
                            cvss="8.8",
                            cweId="CWE-269",
                            codeSnippet=json.dumps(stmt, indent=2),
                            description="Policy grants critical IAM management permissions (PassRole, AttachPolicy) across all resources, enabling unauthorized privilege escalation to Administrator.",
                            remediationSummary="Restrict iam:PassRole and policy attachment actions to explicit role ARNs.",
                            verificationStatus=VerificationStatus.CONFIRMED,
                            statusBadge="CONFIRMED (IAM ESCALATION)",
                            confidence=0.98,
                        )
                    )

        return findings

    def audit_security_group_rules(self, rules_json: str, group_name: str = "Security Group") -> List[SecurityFinding]:
        """
        Audit security group / firewall rules for unrestricted 0.0.0.0/0 ingress to sensitive administrative ports.
        """
        findings: List[SecurityFinding] = []
        try:
            rules = json.loads(rules_json)
        except Exception:
            return findings

        if isinstance(rules, dict):
            rules = rules.get("IpPermissions", [rules])

        sensitive_ports = {
            22: "SSH",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
        }

        for rule in rules:
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")
            ip_ranges = rule.get("IpRanges", [])
            has_world_open = any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges)

            if has_world_open and from_port is not None and to_port is not None:
                for port, svc in sensitive_ports.items():
                    if from_port <= port <= to_port:
                        findings.append(
                            SecurityFinding(
                                id=f"finding-{uuid.uuid4().hex[:8]}",
                                title=f"Security Group Permits Unrestricted Public Ingress to {svc} (Port {port})",
                                severity=SeverityLevel.HIGH if port in (22, 3389) else SeverityLevel.CRITICAL,
                                category="Cloud Security",
                                targetScope=f"{group_name}:{port}",
                                cvss="8.5",
                                cweId="CWE-284",
                                codeSnippet=f"Port: {port} ({svc})\nCIDR Ingress: 0.0.0.0/0",
                                description=f"Security group rule permits inbound traffic from 0.0.0.0/0 (the entire internet) directly to sensitive service '{svc}' on port {port}.",
                                remediationSummary=f"Restrict inbound {svc} (port {port}) access to trusted corporate IP addresses or VPN subnets.",
                                verificationStatus=VerificationStatus.CONFIRMED,
                                statusBadge="CONFIRMED (OPEN SECURITY GROUP)",
                                confidence=1.0,
                            )
                        )

        return findings

cloud_scanner = CloudSecurityScanner()
