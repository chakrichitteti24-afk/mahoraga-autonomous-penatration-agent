"""
CipherFlux Labs CLI Main Entry Point & Command Router.
Supports both direct CLI command execution and full interactive terminal navigation.
"""
import sys
import os
import json
import argparse
import asyncio
from typing import Optional, List

from rich.console import Console
from rich.table import Table
from rich import box

from .theme import get_console
from .banner import print_banner, VERSION
from .diagnostics import SystemDiagnostics
from .interactive import InteractiveCLI

from ..core.orchestrator import orchestrator, ScanProfile
from ..storage.target_store import target_store, TargetItem, TargetType
from ..storage.history_store import history_store
from ..storage.config_store import config_store
from ..reporting.exporter import report_exporter
from backend.core.false_positive_engine import rule_registry
from backend.scanners.cve_engine import KNOWN_CVE_DATABASE, cve_engine

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipherflux",
        description="CipherFlux Labs — Advanced Vulnerability Assessment Framework for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", "-v", action="version", version=f"CipherFlux Labs v{VERSION} (Kali Linux)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress terminal banner display")
    parser.add_argument("--plain", action="store_true", help="Plain text output without terminal colors")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format (suppresses banner)")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # doctor
    subparsers.add_parser("doctor", help="Run system diagnostics and engine integrity checks")

    # targets
    sub_targets = subparsers.add_parser("targets", help="Manage authorized scanning targets")
    sub_targets.add_argument("action", nargs="?", default="list", choices=["list", "add", "remove", "validate"], help="Action to perform")
    sub_targets.add_argument("--value", "-t", help="Target value (URL, IP, CIDR, Domain)")
    sub_targets.add_argument("--type", choices=["URL", "IP", "CIDR", "API", "DOMAIN"], default="URL", help="Target type")
    sub_targets.add_argument("--name", help="Target name / label")
    sub_targets.add_argument("--authorized", action="store_true", default=True, help="Authorize target")
    sub_targets.add_argument("--id", help="Target ID to remove")

    # scan
    sub_scan = subparsers.add_parser("scan", help="Execute vulnerability scan against target")
    sub_scan.add_argument("target", nargs="?", help="Target URL, IP or domain to scan")
    sub_scan.add_argument("--profile", "-p", choices=["passive", "quick", "standard", "deep"], default="standard", help="Scan profile")
    sub_scan.add_argument("--operator", default="security_lead", help="Authorized operator name")
    sub_scan.add_argument("--no-code", action="store_true", help="Skip local code SAST/SCA in deep scan")
    sub_scan.add_argument("--export", choices=["pdf", "json", "csv", "md"], help="Automatically export report")

    # web
    sub_web = subparsers.add_parser("web", help="Audit web application posture & injection canaries")
    sub_web.add_argument("target", help="Target web URL (e.g. https://target.lab)")
    sub_web.add_argument("--no-cors", action="store_true", help="Skip CORS checks")
    sub_web.add_argument("--no-injection", action="store_true", help="Skip injection canaries")

    # api
    sub_api = subparsers.add_parser("api", help="Audit API security (REST, GraphQL, WebSocket)")
    sub_api.add_argument("target", help="Target API URL")
    sub_api.add_argument("--type", choices=["rest", "graphql", "websocket"], default="rest", help="API type")

    # network
    sub_net = subparsers.add_parser("network", help="Execute authorized service port discovery")
    sub_net.add_argument("target", help="Target host or IP")
    sub_net.add_argument("--ports", help="Comma-separated list of ports to scan (e.g. 80,443,22)")

    # ssl
    sub_ssl = subparsers.add_parser("ssl", help="Inspect SSL/TLS handshake, ciphers, and certificate")
    sub_ssl.add_argument("host", help="Target hostname")
    sub_ssl.add_argument("--port", type=int, default=443, help="Port (default: 443)")

    # cve
    sub_cve = subparsers.add_parser("cve", help="Query verified CVE intelligence database")
    sub_cve.add_argument("--query", "-q", help="Search keyword (package or CVE ID)")
    sub_cve.add_argument("--package", help="Package name for version match")
    sub_cve.add_argument("--version-str", help="Package version string for version match")
    sub_cve.add_argument("--ecosystem", choices=["npm", "pip", "cargo", "go", "maven", "composer"], default="npm")

    # sast
    sub_sast = subparsers.add_parser("sast", help="Execute Static Application Security Testing (SAST)")
    sub_sast.add_argument("path", nargs="?", default=".", help="Directory or source file to audit")

    # sca
    sub_sca = subparsers.add_parser("sca", help="Execute Software Composition Analysis (SCA)")
    sub_sca.add_argument("manifest", nargs="?", help="Manifest file path (package.json, requirements.txt, etc.)")

    # dns
    sub_dns = subparsers.add_parser("dns", help="Audit DNS records, SPF, DMARC, and AXFR zone transfer")
    sub_dns.add_argument("domain", help="Target domain name")

    # cloud
    sub_cloud = subparsers.add_parser("cloud", help="Audit cloud storage & IAM configurations")
    sub_cloud.add_argument("--s3", help="AWS S3 bucket name")
    sub_cloud.add_argument("--azure-account", help="Azure storage account")
    sub_cloud.add_argument("--azure-container", help="Azure blob container")
    sub_cloud.add_argument("--gcs", help="Google Cloud Storage bucket name")
    sub_cloud.add_argument("--iam-file", help="Path to IAM policy JSON file")
    sub_cloud.add_argument("--sg-file", help="Path to Security Group JSON file")

    # container
    sub_container = subparsers.add_parser("container", help="Audit Dockerfile and Kubernetes manifests")
    sub_container.add_argument("--dockerfile", help="Path to Dockerfile")
    sub_container.add_argument("--k8s", help="Path to Kubernetes YAML manifest")
    sub_container.add_argument("--daemon", help="Path to Docker daemon.json")

    # results
    sub_results = subparsers.add_parser("results", help="View and filter vulnerability findings")
    sub_results.add_argument("--scan-id", help="Scan ID to inspect")
    sub_results.add_argument("--status", choices=["CONFIRMED", "POTENTIAL", "INCONCLUSIVE", "ALL"], default="ALL")

    # history
    subparsers.add_parser("history", help="List previous vulnerability scans")

    # report
    sub_report = subparsers.add_parser("report", help="Generate and export security audit report")
    sub_report.add_argument("--scan-id", help="Scan ID to export")
    sub_report.add_argument("--format", choices=["pdf", "json", "csv", "md"], default="pdf", help="Report format")
    sub_report.add_argument("--output", help="Output directory")

    # rules
    sub_rules = subparsers.add_parser("rules", help="List and inspect detection rules")
    sub_rules.add_argument("--search", help="Search rules by keyword")

    # browser  [NEW Feature 3 — Playwright]
    sub_browser = subparsers.add_parser("browser", help="Playwright browser engine: DOM XSS, localStorage secrets, CSP bypass, mixed content")
    sub_browser.add_argument("target", help="Target web URL (e.g. https://target.lab)")
    sub_browser.add_argument("--check", help="Playwright install check only", action="store_true", default=False)

    # cve-live  [NEW Feature 1 — OSV.dev live feed]
    sub_cvelive = subparsers.add_parser("cve-live", help="Query OSV.dev live CVE feed and NVD NIST for a package")
    sub_cvelive.add_argument("--package", "-p", required=True, help="Package name")
    sub_cvelive.add_argument("--version-str", "-V", required=True, help="Package version string")
    sub_cvelive.add_argument("--ecosystem", "-e", default="PyPI",
        choices=["PyPI", "npm", "Maven", "Go", "crates.io", "Packagist", "NuGet", "RubyGems"],
        help="Package ecosystem (default: PyPI)")
    sub_cvelive.add_argument("--nvd-search", help="Also search NVD NIST by keyword")
    sub_cvelive.add_argument("--cache-stats", action="store_true", help="Show local CVE cache statistics")
    sub_cvelive.add_argument("--clear-cache", action="store_true", help="Clear all cached CVE results")

    return parser

def main(args: Optional[List[str]] = None) -> int:
    parser = build_parser()
    parsed_args = parser.parse_args(args)
    console = get_console(no_color=parsed_args.plain)

    # 1. No subcommand provided -> Start interactive menu
    if not parsed_args.subcommand:
        cli = InteractiveCLI(console=console)
        cli.run(no_banner=parsed_args.no_banner, plain=parsed_args.plain)
        return 0

    # 2. Command execution
    cmd = parsed_args.subcommand

    # Print banner for CLI commands unless suppressed or JSON requested
    if not parsed_args.no_banner and not parsed_args.json:
        print_banner(console, plain=parsed_args.plain)

    if cmd == "doctor":
        success = SystemDiagnostics.render_diagnostics(console)
        return 0 if success else 1

    elif cmd == "targets":
        action = parsed_args.action
        if action == "list":
            targets = target_store.list_targets()
            if parsed_args.json:
                print(json.dumps([t.to_dict() for t in targets], indent=2))
            else:
                table = Table(title="Authorized Target Inventory", box=box.ROUNDED, expand=True)
                table.add_column("ID", style="bold cyan", width=14)
                table.add_column("Name", style="bold white", width=22)
                table.add_column("Type", width=8)
                table.add_column("Target Value", style="white")
                table.add_column("Authorized", width=12, justify="center")
                for t in targets:
                    auth_txt = "[bold green]YES[/bold green]" if t.authorized else "[bold red]NO[/bold red]"
                    table.add_row(t.id, t.name, t.target_type.value, t.value, auth_txt)
                console.print(table)
        elif action == "add":
            if not parsed_args.value:
                console.print("[bold red][!] Error: --value is required to add a target.[/bold red]")
                return 1
            t_type = TargetType(parsed_args.type)
            target = TargetItem(
                id="",
                name=parsed_args.name or parsed_args.value,
                target_type=t_type,
                value=parsed_args.value,
                authorized=parsed_args.authorized,
                authorized_by="cli_operator",
            )
            target_store.add_target(target)
            console.print(f"[bold green][✓] Added target '{target.name}' ({target.value}) with ID: {target.id}[/bold green]")
        elif action == "remove":
            if not parsed_args.id:
                console.print("[bold red][!] Error: --id is required to remove a target.[/bold red]")
                return 1
            if target_store.remove_target(parsed_args.id):
                console.print(f"[bold green][✓] Target '{parsed_args.id}' removed.[/bold green]")
            else:
                console.print(f"[bold red][!] Target '{parsed_args.id}' not found.[/bold red]")
                return 1
        return 0

    elif cmd == "scan":
        if not parsed_args.target:
            console.print("[bold red][!] Error: Target URL or Host is required. (e.g. cipherflux scan https://target.lab)[/bold red]")
            return 1

        prof = parsed_args.profile.lower()
        if prof in ("passive", "quick"):
            res = asyncio.run(orchestrator.execute_quick_scan(parsed_args.target, authorized_by=parsed_args.operator))
        else:
            inc_code = not parsed_args.no_code
            res = asyncio.run(orchestrator.execute_full_scan(parsed_args.target, authorized_by=parsed_args.operator, include_code_audit=inc_code))

        if parsed_args.json:
            print(json.dumps(res.model_dump(), indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_scan_results_table(res)

        if parsed_args.export:
            dest = report_exporter.export_report(res, format_type=parsed_args.export)
            console.print(f"[bold green][✓] Report saved to: {dest}[/bold green]")
        return 0

    elif cmd == "web":
        findings = asyncio.run(orchestrator.web_engine.scan_endpoint(
            target_url=parsed_args.target,
            check_cors=not parsed_args.no_cors,
            check_headers=True,
            check_ssl=True,
            check_injection=not parsed_args.no_injection,
        ))
        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"Web Security Posture: {parsed_args.target}", findings)
        return 0

    elif cmd == "api":
        findings = asyncio.run(orchestrator.api_engine.scan_api(
            target_url=parsed_args.target,
            api_type=parsed_args.type,
        ))
        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"API Security Audit: {parsed_args.target}", findings)
        return 0

    elif cmd == "network":
        ports = None
        if parsed_args.ports:
            ports = [int(p.strip()) for p in parsed_args.ports.split(",") if p.strip()]
        findings = asyncio.run(orchestrator.network_engine.scan_host(parsed_args.target, ports=ports))
        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"Network Assessment: {parsed_args.target}", findings)
        return 0

    elif cmd == "ssl":
        findings = asyncio.run(orchestrator.tls_engine.scan_tls(parsed_args.host, parsed_args.port))
        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"SSL/TLS Security Audit: {parsed_args.host}:{parsed_args.port}", findings)
        return 0

    elif cmd == "cve":
        if parsed_args.package and parsed_args.version_str:
            findings = cve_engine.match_dependency(parsed_args.ecosystem, parsed_args.package, parsed_args.version_str)
            if parsed_args.json:
                print(json.dumps([f.model_dump() for f in findings], indent=2))
            else:
                cli = InteractiveCLI(console=console)
                cli._render_findings_table(f"CVE Findings for {parsed_args.package}=={parsed_args.version_str}", findings)
        elif parsed_args.query:
            q = parsed_args.query.lower()
            matches = [c for c in KNOWN_CVE_DATABASE if q in c["package"].lower() or q in c["cve"].lower() or q in c["title"].lower()]
            if parsed_args.json:
                print(json.dumps(matches, indent=2))
            else:
                table = Table(title=f"CVE Advisories Matching '{q}'", box=box.ROUNDED, expand=True)
                table.add_column("CVE ID", style="bold cyan", width=16)
                table.add_column("Package", style="bold white", width=14)
                table.add_column("Fixed Version", width=14)
                table.add_column("Severity", width=10)
                table.add_column("Title / Description", style="dim white")
                for m in matches:
                    table.add_row(m["cve"], m["package"], f">= {m['fixed']}", m["severity"].value, m["title"])
                console.print(table)
        else:
            table = Table(title="Verified CVE Intelligence Database Catalog", box=box.ROUNDED, expand=True)
            table.add_column("Ecosystem", width=10)
            table.add_column("Package", style="bold white", width=14)
            table.add_column("CVE ID", style="bold cyan", width=16)
            table.add_column("Fixed In", width=12)
            table.add_column("Severity", width=10)
            table.add_column("Advisory Title", style="dim white")
            for c in KNOWN_CVE_DATABASE:
                table.add_row(c["ecosystem"], c["package"], c["cve"], c["fixed"], c["severity"].value, c["title"])
            console.print(table)
        return 0

    elif cmd == "sast":
        target_path = parsed_args.path
        if os.path.isfile(target_path):
            findings = orchestrator.sast_engine.scan_file(target_path)
        else:
            findings, _ = orchestrator.sast_engine.scan_directory(target_path)
        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"SAST Source Code Security: {target_path}", findings)
        return 0

    elif cmd == "sca":
        if parsed_args.manifest:
            fpath = parsed_args.manifest
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            fname = os.path.basename(fpath).lower()
            if "package.json" in fname:
                findings = orchestrator.sca_engine.scan_npm_manifest(content, fpath)
            elif "requirements" in fname or fname.endswith(".txt"):
                findings = orchestrator.sca_engine.scan_pip_manifest(content, fpath)
            elif "cargo" in fname:
                findings = orchestrator.sca_engine.scan_cargo_manifest(content, fpath)
            elif "go.mod" in fname:
                findings = orchestrator.sca_engine.scan_go_manifest(content, fpath)
            elif "pom.xml" in fname:
                findings = orchestrator.sca_engine.scan_maven_manifest(content, fpath)
            else:
                findings = orchestrator.sca_engine.scan_pip_manifest(content, fpath)
        else:
            findings = orchestrator.sca_engine.audit_workspace_manifests()
        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table("Software Composition Analysis (SCA)", findings)
        return 0

    elif cmd == "dns":
        findings = asyncio.run(orchestrator.dns_engine.scan_domain(parsed_args.domain))
        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"DNS & Domain Security: {parsed_args.domain}", findings)
        return 0

    elif cmd == "cloud":
        findings = []
        if parsed_args.s3:
            findings = asyncio.run(orchestrator.cloud_engine.audit_s3_bucket(parsed_args.s3))
        elif parsed_args.azure_account and parsed_args.azure_container:
            findings = asyncio.run(orchestrator.cloud_engine.audit_azure_blob_container(parsed_args.azure_account, parsed_args.azure_container))
        elif parsed_args.gcs:
            findings = asyncio.run(orchestrator.cloud_engine.audit_gcp_bucket(parsed_args.gcs))
        elif parsed_args.iam_file:
            with open(parsed_args.iam_file, "r", encoding="utf-8") as f:
                content = f.read()
            findings = orchestrator.cloud_engine.audit_iam_policy_document(content, os.path.basename(parsed_args.iam_file))
        elif parsed_args.sg_file:
            with open(parsed_args.sg_file, "r", encoding="utf-8") as f:
                content = f.read()
            findings = orchestrator.cloud_engine.audit_security_group_rules(content, os.path.basename(parsed_args.sg_file))
        else:
            console.print("[bold red][!] Error: Please specify cloud target (--s3, --azure-account, --gcs, --iam-file, or --sg-file).[/bold red]")
            return 1

        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table("Cloud Security Audit Findings", findings)
        return 0

    elif cmd == "container":
        findings = []
        if parsed_args.dockerfile:
            with open(parsed_args.dockerfile, "r", encoding="utf-8") as f:
                content = f.read()
            findings = orchestrator.container_engine.scan_dockerfile_content(content, parsed_args.dockerfile)
        elif parsed_args.k8s:
            with open(parsed_args.k8s, "r", encoding="utf-8") as f:
                content = f.read()
            findings = orchestrator.container_engine.scan_kubernetes_manifest(content, parsed_args.k8s)
        elif parsed_args.daemon:
            with open(parsed_args.daemon, "r", encoding="utf-8") as f:
                content = f.read()
            findings = orchestrator.container_engine.audit_docker_daemon_config(content)
        else:
            console.print("[bold red][!] Error: Please specify container target (--dockerfile, --k8s, or --daemon).[/bold red]")
            return 1

        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table("Container Security Audit Findings", findings)
        return 0

    elif cmd == "results":
        scans = history_store.list_scans()
        if not scans:
            console.print("[bold yellow][!] No scan history available.[/bold yellow]")
            return 0
        scan_id = parsed_args.scan_id or scans[0]["scanId"]
        scan = history_store.get_scan(scan_id)
        if not scan:
            console.print(f"[bold red][!] Scan '{scan_id}' not found.[/bold red]")
            return 1

        findings = scan.findings
        if parsed_args.status != "ALL":
            findings = [f for f in findings if (f.verificationStatus.value if hasattr(f.verificationStatus, "value") else str(f.verificationStatus)) == parsed_args.status]

        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"Vulnerability Results: {scan.target} ({parsed_args.status})", findings)
        return 0

    elif cmd == "history":
        scans = history_store.list_scans()
        if parsed_args.json:
            print(json.dumps(scans, indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli.menu_scan_history()
        return 0

    elif cmd == "report":
        scans = history_store.list_scans()
        if not scans:
            console.print("[bold yellow][!] No scans available to export.[/bold yellow]")
            return 1
        scan_id = parsed_args.scan_id or scans[0]["scanId"]
        scan = history_store.get_scan(scan_id)
        if not scan:
            console.print(f"[bold red][!] Scan '{scan_id}' not found.[/bold red]")
            return 1

        dest = report_exporter.export_report(scan, format_type=parsed_args.format, output_dir=parsed_args.output)
        if parsed_args.json:
            print(json.dumps({"status": "SUCCESS", "format": parsed_args.format, "path": dest}))
        else:
            console.print(f"[bold green][✓] Report generated: {dest}[/bold green]")
        return 0

    elif cmd == "rules":
        rules = rule_registry.list_all()
        if parsed_args.search:
            q = parsed_args.search.lower()
            rules = [r for r in rules if q in r.rule_id.lower() or q in r.rule_name.lower() or q in r.description.lower()]

        if parsed_args.json:
            models = [r.to_dict() if hasattr(r, "to_dict") else vars(r) for r in rules]
            print(json.dumps(models, indent=2, default=str))
        else:
            table = Table(title=f"CipherFlux Detection Rules ({len(rules)} Loaded)", box=box.ROUNDED, expand=True)
            table.add_column("Rule ID", style="bold cyan", width=16)
            table.add_column("Rule Name", style="bold white", width=28)
            table.add_column("CWE", width=10)
            table.add_column("Severity", width=10)
            table.add_column("CVSS", width=6)
            table.add_column("Detection Logic", style="dim white")
            for r in rules:
                table.add_row(r.rule_id, r.rule_name, r.cwe_id, r.default_severity.value, r.cvss_base, r.detection_logic)
            console.print(table)
        return 0

    # ──────────────────────────────────────────────────────────────────────────
    # Feature 3: Playwright Browser Engine
    # ──────────────────────────────────────────────────────────────────────────
    elif cmd == "browser":
        try:
            from backend.scanners.browser_engine import browser_engine as be
        except ImportError:
            console.print("[bold red][!] browser_engine module not found.[/bold red]")
            return 1

        available, reason = be.is_available()

        if parsed_args.check:
            if available:
                console.print("[bold green][✓] Playwright is installed and available.[/bold green]")
            else:
                console.print(f"[bold red][✗] Playwright not available: {reason}[/bold red]")
                console.print("[bold yellow][→] Install: pip install playwright && playwright install chromium[/bold yellow]")
            return 0 if available else 1

        if not available:
            console.print(f"[bold red][!] Playwright not installed.[/bold red]")
            console.print("[bold yellow][→] Run: pip install playwright && playwright install chromium[/bold yellow]")
            return 1

        console.print(f"[bold cyan][⚙] Starting browser security scan: {parsed_args.target}[/bold cyan]")
        findings = asyncio.run(be.scan(parsed_args.target))

        if parsed_args.json:
            print(json.dumps([f.model_dump() for f in findings], indent=2))
        else:
            cli = InteractiveCLI(console=console)
            cli._render_findings_table(f"Browser Security Audit: {parsed_args.target}", findings)
        return 0

    # ──────────────────────────────────────────────────────────────────────────
    # Feature 1: OSV.dev Live CVE Feed + NVD NIST
    # ──────────────────────────────────────────────────────────────────────────
    elif cmd == "cve-live":
        try:
            from backend.scanners.osv_feed import live_cve_feed as feed
        except ImportError:
            console.print("[bold red][!] osv_feed module not found.[/bold red]")
            return 1

        # Cache management flags
        if parsed_args.cache_stats:
            stats = feed.cache_stats()
            if parsed_args.json:
                print(json.dumps(stats, indent=2))
            else:
                table = Table(title="CVE Cache Statistics", box=box.ROUNDED)
                for k, v in stats.items():
                    table.add_column(k.replace("_", " ").title(), style="cyan")
                table.add_row(*[str(v) for v in stats.values()])
                console.print(table)
            return 0

        if parsed_args.clear_cache:
            deleted = feed.clear_cache()
            console.print(f"[bold green][✓] CVE cache cleared: {deleted} entries deleted.[/bold green]")
            return 0

        console.print(
            f"[bold cyan][⚙] Querying OSV.dev live feed: "
            f"{parsed_args.ecosystem}/{parsed_args.package}@{parsed_args.version_str}[/bold cyan]"
        )

        findings = asyncio.run(
            feed.query_live(
                ecosystem=parsed_args.ecosystem,
                package=parsed_args.package,
                version=parsed_args.version_str,
                source_path="cli-query",
            )
        )

        # Also query NVD if requested
        nvd_results = []
        if parsed_args.nvd_search:
            console.print(f"[bold cyan][⚙] Searching NVD NIST: '{parsed_args.nvd_search}'...[/bold cyan]")
            nvd_results = asyncio.run(feed.search_nvd_keyword(parsed_args.nvd_search, max_results=10))

        if parsed_args.json:
            output = {
                "osv_findings": [f.model_dump() for f in findings],
                "nvd_results": nvd_results,
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            cli = InteractiveCLI(console=console)
            if findings:
                cli._render_findings_table(
                    f"OSV.dev Live CVE: {parsed_args.package}@{parsed_args.version_str}",
                    findings,
                )
            else:
                console.print(
                    f"[bold green][✓] No known vulnerabilities found in OSV.dev for "
                    f"{parsed_args.package}@{parsed_args.version_str} ({parsed_args.ecosystem})[/bold green]"
                )

            if nvd_results:
                table = Table(
                    title=f"NVD NIST Results for '{parsed_args.nvd_search}'",
                    box=box.ROUNDED, expand=True
                )
                table.add_column("CVE ID", style="bold cyan", width=18)
                table.add_column("Published", width=12)
                table.add_column("CVSS v3", width=8)
                table.add_column("Description", style="dim white")
                for cve_item in nvd_results[:10]:
                    cve_id = cve_item.get("id", "N/A")
                    published = cve_item.get("published", "")[:10]
                    metrics = cve_item.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "") if metrics.get("cvssMetricV31") else ""
                    descriptions = cve_item.get("descriptions", [{}])
                    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "N/A")
                    table.add_row(cve_id, published, str(cvss_v31), desc[:100] + "..." if len(desc) > 100 else desc)
                console.print(table)

        return 0

    return 0

def entry_point():
    """Package console script entry point."""
    sys.exit(main())

if __name__ == "__main__":
    sys.exit(main())
