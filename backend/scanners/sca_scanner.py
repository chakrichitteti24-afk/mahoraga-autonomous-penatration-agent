import json
import re
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
import xml.etree.ElementTree as ET

from ..models.schemas import SecurityFinding, SeverityLevel, VerificationStatus
from ..config import settings
from .cve_engine import cve_engine

class SCAScanner:
    """
    Multi-Ecosystem Software Composition Analysis (SCA) Engine.
    Parses manifest files for Python, Node.js/JavaScript, Rust, Go, Java Maven, and PHP.
    Evaluates dependencies against verified CVE intelligence and detects dependency confusion risks.
    """

    def __init__(self):
        self.cve_engine = cve_engine

    def scan_npm_manifest(self, content: str, source_path: str = "package.json") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        try:
            data = json.loads(content)
        except Exception:
            return findings

        all_deps = {}
        if "dependencies" in data and isinstance(data["dependencies"], dict):
            all_deps.update(data["dependencies"])
        if "devDependencies" in data and isinstance(data["devDependencies"], dict):
            all_deps.update(data["devDependencies"])

        for pkg, version_spec in all_deps.items():
            # Match against CVE catalog
            pkg_findings = self.cve_engine.match_dependency(
                ecosystem="npm",
                package_name=pkg,
                version_str=str(version_spec),
                source_path=source_path,
            )
            findings.extend(pkg_findings)

            # Check dependency confusion
            confusion_finding = self.cve_engine.check_dependency_confusion_risk(pkg, "npm")
            if confusion_finding:
                confusion_finding.targetScope = f"{source_path}:{pkg}"
                findings.append(confusion_finding)

        return findings

    def scan_pip_manifest(self, content: str, source_path: str = "requirements.txt") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=)\s*([0-9\.]+)", line)
            if not match:
                continue

            pkg_name, version = match.group(1).lower(), match.group(2)
            pkg_findings = self.cve_engine.match_dependency(
                ecosystem="pip",
                package_name=pkg_name,
                version_str=version,
                source_path=source_path,
            )
            findings.extend(pkg_findings)

            confusion_finding = self.cve_engine.check_dependency_confusion_risk(pkg_name, "pip")
            if confusion_finding:
                confusion_finding.targetScope = f"{source_path}:{pkg_name}"
                findings.append(confusion_finding)

        return findings

    def scan_cargo_manifest(self, content: str, source_path: str = "Cargo.toml") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.splitlines()
        in_deps = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[dependencies]") or stripped.startswith("[dev-dependencies]"):
                in_deps = True
                continue
            elif stripped.startswith("[") and in_deps:
                in_deps = False
                continue

            if in_deps:
                # Format: package_name = "1.0.0" or package_name = { version = "1.0.0" }
                match = re.match(r"""^([a-zA-Z0-9_\-]+)\s*=\s*(?:["']([0-9\.]+)["']|\{\s*version\s*=\s*["']([0-9\.]+)["'])""", stripped)
                if match:
                    pkg = match.group(1)
                    ver = match.group(2) or match.group(3)
                    findings.extend(self.cve_engine.match_dependency("cargo", pkg, ver, source_path))

        return findings

    def scan_go_manifest(self, content: str, source_path: str = "go.mod") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lines = content.splitlines()
        for line in lines:
            match = re.match(r"^\s*([a-zA-Z0-9\.\-_/]+)\s+v([0-9\.]+)", line)
            if match:
                pkg, ver = match.group(1), match.group(2)
                findings.extend(self.cve_engine.match_dependency("go", pkg, ver, source_path))
        return findings

    def scan_maven_manifest(self, content: str, source_path: str = "pom.xml") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        try:
            root = ET.fromstring(content)
            # Find dependencies
            for dep in root.iter():
                if dep.tag.endswith("dependency"):
                    group_id = ""
                    artifact_id = ""
                    version = ""
                    for child in dep:
                        if child.tag.endswith("groupId") and child.text:
                            group_id = child.text.strip()
                        elif child.tag.endswith("artifactId") and child.text:
                            artifact_id = child.text.strip()
                        elif child.tag.endswith("version") and child.text:
                            version = child.text.strip()

                    if artifact_id and version and not version.startswith("${"):
                        full_name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                        findings.extend(self.cve_engine.match_dependency("maven", full_name, version, source_path))
        except Exception:
            pass
        return findings

    def scan_composer_manifest(self, content: str, source_path: str = "composer.json") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        try:
            data = json.loads(content)
            all_deps = {}
            if "require" in data and isinstance(data["require"], dict):
                all_deps.update(data["require"])
            if "require-dev" in data and isinstance(data["require-dev"], dict):
                all_deps.update(data["require-dev"])

            for pkg, ver in all_deps.items():
                clean_ver = str(ver).strip("^~><= ")
                findings.extend(self.cve_engine.match_dependency("composer", pkg, clean_ver, source_path))
        except Exception:
            pass
        return findings

    def audit_workspace_manifests(self) -> List[SecurityFinding]:
        """Audit all known dependency manifests located across the workspace."""
        findings: List[SecurityFinding] = []
        workspace = settings.workspace_root

        # 1. package.json
        pkg_json = workspace / "package.json"
        if pkg_json.exists():
            try:
                content = pkg_json.read_text(encoding="utf-8", errors="replace")
                findings.extend(self.scan_npm_manifest(content, "package.json"))
            except Exception:
                pass

        # 2. requirements.txt
        req_txt = workspace / "backend" / "requirements.txt"
        if req_txt.exists():
            try:
                content = req_txt.read_text(encoding="utf-8", errors="replace")
                findings.extend(self.scan_pip_manifest(content, "backend/requirements.txt"))
            except Exception:
                pass

        return findings
