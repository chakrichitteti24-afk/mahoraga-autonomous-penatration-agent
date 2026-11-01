"""
CipherFlux Labs Interactive CLI Terminal Experience.
Provides Metasploit-inspired interactive terminal navigation with number selection,
safe execution, Rich tables, panels, live progress bars, and graceful interrupts.
"""
import sys
import os
import asyncio
import time
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from rich.text import Text

from .theme import get_console
from .banner import print_banner, VERSION
from .diagnostics import SystemDiagnostics

from ..core.orchestrator import orchestrator, ScanProfile
from ..storage.target_store import target_store, TargetItem, TargetType
from ..storage.history_store import history_store
from ..storage.config_store import config_store
from ..reporting.exporter import report_exporter
from backend.core.false_positive_engine import rule_registry
from backend.scanners.cve_engine import KNOWN_CVE_DATABASE, cve_engine
from backend.models.schemas import SecurityFinding, SeverityLevel, VerificationStatus, ScanResponse

class InteractiveCLI:
    def __init__(self, console: Optional[Console] = None):
        self.console = console or get_console()
        self.running = True

    def clear_screen(self):
        """Clean terminal refresh if supported."""
        # Print a neat separator rather than jarring hard-clear on all terminals
        self.console.print("\n" + "─" * 80 + "\n", style="dim")

    def run(self, no_banner: bool = False, plain: bool = False):
        """Start interactive main menu loop."""
        print_banner(self.console, no_banner=no_banner, plain=plain)

        while self.running:
            try:
                self.show_main_menu()
                choice = Prompt.ask(
                    "[bold cyan]cipherflux[/bold cyan] > [bold white]Select Option[/bold white]",
                    default="00",
                ).strip()

                if choice in ("00", "exit", "quit", "q"):
                    self.exit_gracefully()
                    break
                elif choice in ("1", "01"):
                    self.menu_target_management()
                elif choice in ("2", "02"):
                    self.menu_quick_scan()
                elif choice in ("3", "03"):
                    self.menu_full_scan()
                elif choice in ("4", "04"):
                    self.menu_web_scanner()
                elif choice in ("5", "05"):
                    self.menu_api_scanner()
                elif choice in ("6", "06"):
                    self.menu_network_scanner()
                elif choice in ("7", "07"):
                    self.menu_tls_scanner()
                elif choice in ("8", "08"):
                    self.menu_cve_scanner()
                elif choice in ("9", "09"):
                    self.menu_sast_scanner()
                elif choice in ("10"):
                    self.menu_sca_scanner()
                elif choice in ("11"):
                    self.menu_dns_scanner()
                elif choice in ("12"):
                    self.menu_cloud_scanner()
                elif choice in ("13"):
                    self.menu_container_scanner()
                elif choice in ("14"):
                    self.menu_custom_scan()
                elif choice in ("15"):
                    self.menu_vulnerability_results()
                elif choice in ("16"):
                    self.menu_report_generator()
                elif choice in ("17"):
                    self.menu_scan_history()
                elif choice in ("18"):
                    self.menu_rules_database()
                elif choice in ("19"):
                    self.menu_settings()
                elif choice in ("20"):
                    self.menu_diagnostics()
                elif choice in ("21", "?", "help"):
                    self.menu_help()
                else:
                    self.console.print(f"[bold red][!] Invalid choice '{choice}'. Enter 01-21 or 00 to exit.[/bold red]")

            except KeyboardInterrupt:
                self.console.print("\n[bold yellow][!] Keyboard interrupt received.[/bold yellow]")
                if Confirm.ask("[bold yellow]Do you want to exit CipherFlux?[/bold yellow]", default=True):
                    self.exit_gracefully()
                    break
            except Exception as e:
                self.console.print(f"[bold red][ERROR] Unexpected error: {str(e)}[/bold red]")

    def exit_gracefully(self):
        self.console.print("\n[bold cyan]◈ CipherFlux Labs session closed. Stay secure.[/bold cyan]\n")
        self.running = False

    def show_main_menu(self):
        """Display 21 interactive options compliant with specification."""
        table = Table(
            title="◈ CIPHERFLUX LABS — INTERACTIVE FRAMEWORK MENU ◈",
            title_style="bold cyan",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold blue",
            expand=True,
        )
        table.add_column("No.", style="bold cyan", width=6, justify="center")
        table.add_column("Module / Feature", style="bold white", width=36)
        table.add_column("Category & Description", style="dim white")

        options = [
            ("01", "Target Management", "Register, validate targets and configure authorized scopes"),
            ("02", "Quick Vulnerability Scan", "Low-impact availability, headers, TLS, and exposure audit"),
            ("03", "Full Vulnerability Scan", "Centralized multi-vector assessment (Web, Network, Code, Cloud)"),
            ("04", "Web Application Scanner", "Injection canaries, XSS, CORS, cookie flags, and misconfigurations"),
            ("05", "API Security Scanner", "REST, GraphQL introspection, WebSocket CSWSH, and rate limits"),
            ("06", "Network Vulnerability Scanner", "Controlled port discovery and insecure plaintext service checks"),
            ("07", "SSL/TLS Security Scanner", "Protocol handshake, weak ciphers, key size, and certificate audit"),
            ("08", "CVE Vulnerability Scanner", "Verified NVD / OSV / GHSA vulnerability intelligence matching"),
            ("09", "Source Code Security Scanner (SAST)", "Static analysis for hardcoded secrets, injection, and crypto flaws"),
            ("10", "Software Composition Analysis (SCA)", "Manifest analysis (pip, npm, cargo, go, maven) for vulnerable deps"),
            ("11", "DNS & Domain Security Scanner", "SPF (+all), DMARC policy, AXFR zone transfer, and takeover audit"),
            ("12", "Cloud Security Scanner", "Authorized read-only S3, Azure Blob, GCS, IAM, and Security Group audits"),
            ("13", "Container Security Scanner", "Dockerfile AST, Kubernetes RBAC, privileged pods, and IaC audits"),
            ("14", "Custom Scan Configuration", "Configure target, profiles, timeouts, rate limits, and modules"),
            ("15", "Vulnerability Results", "Triage findings by status (Confirmed, Potential, Inconclusive)"),
            ("16", "Security Report Generator", "Synthesize publication-ready PDF, JSON, CSV, and Markdown deliverables"),
            ("17", "Scan History & Comparison", "Inspect historical scans and calculate resolved vs persistent flaws"),
            ("18", "Vulnerability Database & Rules", "Browse, search, and inspect evidence-driven detection rules"),
            ("19", "Settings & Configuration", "Tune timeouts, concurrency, rate limits, and proxy parameters"),
            ("20", "System Diagnostics", "Run 'cipherflux doctor' environmental and engine integrity checks"),
            ("21", "Help & Documentation", "Usage guide, command-line syntax, and security references"),
            ("00", "Exit Framework", "Safely terminate the CipherFlux session"),
        ]

        for num, mod, desc in options:
            if num == "00":
                table.add_row(f"[bold red]{num}[/bold red]", f"[bold red]{mod}[/bold red]", f"[dim red]{desc}[/dim red]")
            else:
                table.add_row(num, mod, desc)

        self.console.print(table)

    # =========================================================================
    # [01] Target Management Submenu
    # =========================================================================
    def menu_target_management(self):
        while True:
            self.console.print("\n[bold cyan]─── TARGET MANAGEMENT SUBMENU ───[/bold cyan]")
            self.console.print("[01] Add Target")
            self.console.print("[02] View Targets")
            self.console.print("[03] Remove Target")
            self.console.print("[04] Validate Target")
            self.console.print("[05] Configure Authorized Scope")
            self.console.print("[06] Import Target List (JSON / CSV)")
            self.console.print("[07] Export Target List (JSON / CSV)")
            self.console.print("[08] View Target Information")
            self.console.print("[00] Back to Main Menu")

            sub_choice = Prompt.ask("[bold cyan]target-mgmt[/bold cyan] > [bold white]Option[/bold white]", default="00").strip()
            if sub_choice in ("0", "00", "back"):
                break
            elif sub_choice in ("1", "01"):
                # Add Target
                name = Prompt.ask("Enter target name / label").strip()
                t_type_str = Prompt.ask("Select Target Type", choices=["URL", "IP", "CIDR", "API", "DOMAIN"], default="URL")
                value = Prompt.ask("Enter target value (e.g. https://target.lab, 192.168.1.10)").strip()
                desc = Prompt.ask("Enter description / asset role", default="").strip()
                tags_str = Prompt.ask("Enter tags (comma separated)", default="web,staging").strip()
                tags = [t.strip() for t in tags_str.split(",") if t.strip()]

                auth = Confirm.ask("Do you have explicit authorized permission to scan this asset?", default=True)
                authorized_by = Prompt.ask("Authorized by (Security Lead / CISO)", default="security_operator").strip() if auth else ""

                t_type = TargetType(t_type_str)
                is_valid, msg, meta = target_store.validate_target(value, t_type)
                if not is_valid:
                    self.console.print(f"[bold red][!] Validation Error: {msg}[/bold red]")
                    if not Confirm.ask("Add target anyway?", default=False):
                        continue

                target = TargetItem(
                    id="",
                    name=name,
                    target_type=t_type,
                    value=value,
                    description=desc,
                    tags=tags,
                    authorized=auth,
                    authorized_by=authorized_by,
                )
                target_store.add_target(target)
                self.console.print(f"[bold green][✓] Target '{target.name}' added successfully with ID: {target.id}[/bold green]")

            elif sub_choice in ("2", "02"):
                # View Targets
                targets = target_store.list_targets()
                if not targets:
                    self.console.print("[bold yellow][!] No targets registered in database.[/bold yellow]")
                else:
                    t_table = Table(title="Authorized Target Inventory", box=box.ROUNDED, expand=True)
                    t_table.add_column("ID", style="bold cyan", width=14)
                    t_table.add_column("Name", style="bold white", width=22)
                    t_table.add_column("Type", width=8)
                    t_table.add_column("Target Value", style="white")
                    t_table.add_column("Authorized", width=12, justify="center")
                    t_table.add_column("Authorized By", style="dim white")
                    for t in targets:
                        auth_txt = "[bold green]YES[/bold green]" if t.authorized else "[bold red]NO[/bold red]"
                        t_table.add_row(t.id, t.name, t.target_type.value, t.value, auth_txt, t.authorized_by or "N/A")
                    self.console.print(t_table)

            elif sub_choice in ("3", "03"):
                # Remove Target
                targets = target_store.list_targets()
                if not targets:
                    self.console.print("[bold yellow][!] No targets to remove.[/bold yellow]")
                    continue
                tid = Prompt.ask("Enter Target ID to remove").strip()
                if target_store.remove_target(tid):
                    self.console.print(f"[bold green][✓] Target '{tid}' removed.[/bold green]")
                else:
                    self.console.print(f"[bold red][!] Target '{tid}' not found.[/bold red]")

            elif sub_choice in ("4", "04"):
                # Validate Target
                val = Prompt.ask("Enter target host, IP, CIDR or URL to validate").strip()
                t_type_str = Prompt.ask("Target type", choices=["URL", "IP", "CIDR", "API", "DOMAIN"], default="URL")
                valid, msg, meta = target_store.validate_target(val, TargetType(t_type_str))
                if valid:
                    self.console.print(f"[bold green][✓] {msg}[/bold green]")
                    for k, v in meta.items():
                        self.console.print(f"    • {k}: {v}")
                else:
                    self.console.print(f"[bold red][✗] {msg}[/bold red]")

            elif sub_choice in ("5", "05"):
                # Scope configuration
                tid = Prompt.ask("Enter Target ID to update authorization scope").strip()
                t = target_store.get_target(tid)
                if not t:
                    self.console.print(f"[bold red][!] Target '{tid}' not found.[/bold red]")
                    continue
                t.authorized = Confirm.ask(f"Authorize scanning for '{t.name}' ({t.value})?", default=t.authorized)
                if t.authorized:
                    t.authorized_by = Prompt.ask("Authorized by (Operator / CISO)", default=t.authorized_by or "security_lead").strip()
                    t.scope_notes = Prompt.ask("Scope boundary notes", default=t.scope_notes or "Authorized for non-destructive audit").strip()
                target_store.save()
                self.console.print(f"[bold green][✓] Target '{t.name}' scope updated.[/bold green]")

            elif sub_choice in ("6", "06"):
                # Import
                fpath = Prompt.ask("Enter path to targets file (.json or .csv)").strip()
                if not os.path.exists(fpath):
                    self.console.print(f"[bold red][!] File not found: {fpath}[/bold red]")
                    continue
                if fpath.endswith(".json"):
                    cnt = target_store.import_json(fpath)
                    self.console.print(f"[bold green][✓] Imported {cnt} targets from JSON.[/bold green]")
                elif fpath.endswith(".csv"):
                    cnt = target_store.import_csv(fpath)
                    self.console.print(f"[bold green][✓] Imported {cnt} targets from CSV.[/bold green]")
                else:
                    self.console.print("[bold red][!] Unsupported format. Please provide .json or .csv.[/bold red]")

            elif sub_choice in ("7", "07"):
                # Export
                fmt = Prompt.ask("Export format", choices=["json", "csv"], default="json")
                out = Prompt.ask("Output file path", default=f"targets_export.{fmt}").strip()
                if fmt == "json":
                    cnt = target_store.export_json(out)
                    self.console.print(f"[bold green][✓] Exported {cnt} targets to {out}[/bold green]")
                else:
                    cnt = target_store.export_csv(out)
                    self.console.print(f"[bold green][✓] Exported {cnt} targets to {out}[/bold green]")

            elif sub_choice in ("8", "08"):
                # View details
                tid = Prompt.ask("Enter Target ID").strip()
                t = target_store.get_target(tid)
                if not t:
                    self.console.print(f"[bold red][!] Target '{tid}' not found.[/bold red]")
                else:
                    panel = Panel(
                        f"[bold cyan]Target ID:[/bold cyan] {t.id}\n"
                        f"[bold cyan]Name:[/bold cyan] {t.name}\n"
                        f"[bold cyan]Type:[/bold cyan] {t.target_type.value}\n"
                        f"[bold cyan]Value:[/bold cyan] {t.value}\n"
                        f"[bold cyan]Authorized:[/bold cyan] {'[green]YES[/green]' if t.authorized else '[red]NO[/red]'}\n"
                        f"[bold cyan]Authorized By:[/bold cyan] {t.authorized_by or 'None'}\n"
                        f"[bold cyan]Authorization Date:[/bold cyan] {t.authorization_date or 'N/A'}\n"
                        f"[bold cyan]Description:[/bold cyan] {t.description or 'N/A'}\n"
                        f"[bold cyan]Tags:[/bold cyan] {', '.join(t.tags) if t.tags else 'None'}\n"
                        f"[bold cyan]Scope Notes:[/bold cyan] {t.scope_notes or 'None'}",
                        title=f"Target Details — {t.name}",
                        box=box.ROUNDED,
                    )
                    self.console.print(panel)

    # =========================================================================
    # Helper: Select or Enter Target
    # =========================================================================
    def _select_or_enter_target(self) -> Optional[str]:
        targets = target_store.list_targets()
        if targets:
            self.console.print("[bold cyan]Registered Targets:[/bold cyan]")
            for idx, t in enumerate(targets, start=1):
                auth_str = "[green]AUTHORIZED[/green]" if t.authorized else "[red]UNAUTHORIZED[/red]"
                self.console.print(f"  [{idx:02d}] {t.name} ({t.value}) — {auth_str}")
            self.console.print("  [00] Enter a custom target URL / Host")

            sel = Prompt.ask("Select target", default="01").strip()
            if sel != "00":
                try:
                    idx = int(sel) - 1
                    if 0 <= idx < len(targets):
                        chosen = targets[idx]
                        if not chosen.authorized:
                            if not Confirm.ask(f"[bold yellow]Warning: '{chosen.name}' is marked unauthorized. Proceed anyway?[/bold yellow]", default=False):
                                return None
                        return chosen.value
                except ValueError:
                    pass

        val = Prompt.ask("Enter Target URL or Host (e.g. https://target.lab, http://127.0.0.1:8000)").strip()
        return val if val else None

    # =========================================================================
    # [02] Quick Vulnerability Scan
    # =========================================================================
    def menu_quick_scan(self):
        self.console.print("\n[bold cyan]◈ QUICK VULNERABILITY SCAN ◈[/bold cyan]")
        self.console.print("[dim]Executes low-impact, passive checks: availability, defensive headers, TLS, and public exposure.[/dim]\n")

        target_url = self._select_or_enter_target()
        if not target_url:
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task = progress.add_task("[bold cyan]Running Quick Scan...", total=100)

            def progress_cb(step_desc: str, pct: int):
                progress.update(task, completed=pct, description=f"[bold cyan]{step_desc}")

            scan_res = asyncio.run(orchestrator.execute_quick_scan(
                target_url=target_url,
                progress_callback=progress_cb,
            ))

        self._render_scan_results_table(scan_res)
        self._offer_report_export(scan_res)

    # =========================================================================
    # [03] Full Vulnerability Scan
    # =========================================================================
    def menu_full_scan(self):
        self.console.print("\n[bold cyan]◈ FULL VULNERABILITY ASSESSMENT ◈[/bold cyan]")
        self.console.print("[dim]Orchestrates Web, API, Network, SSL/TLS, DNS, SAST, SCA, and IaC/Container engines.[/dim]\n")

        target_url = self._select_or_enter_target()
        if not target_url:
            return

        inc_net = Confirm.ask("Include network service port scan?", default=True)
        inc_code = Confirm.ask("Include workspace source code & dependency audit (SAST + SCA)?", default=True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task = progress.add_task("[bold cyan]Executing Full Assessment...", total=100)

            def progress_cb(step_desc: str, pct: int):
                progress.update(task, completed=pct, description=f"[bold cyan]{step_desc}")

            scan_res = asyncio.run(orchestrator.execute_full_scan(
                target_url=target_url,
                include_code_audit=inc_code,
                include_network=inc_net,
                progress_callback=progress_cb,
            ))

        self._render_scan_results_table(scan_res)
        self._offer_report_export(scan_res)

    # =========================================================================
    # [04] Web Application Scanner
    # =========================================================================
    def menu_web_scanner(self):
        self.console.print("\n[bold cyan]◈ WEB APPLICATION SECURITY SCANNER ◈[/bold cyan]")
        target_url = self._select_or_enter_target()
        if not target_url:
            return

        chk_cors = Confirm.ask("Audit CORS configuration & origin reflection?", default=True)
        chk_headers = Confirm.ask("Audit defensive security headers (CSP, HSTS, XFO)?", default=True)
        chk_cookies = Confirm.ask("Audit cookie flags (HttpOnly, Secure, SameSite)?", default=True)
        chk_inj = Confirm.ask("Execute safe non-destructive injection canaries (SSTI, CRLF)?", default=True)

        with Progress(SpinnerColumn(), TextColumn("[bold cyan]Scanning Web Application Posture..."), console=self.console) as progress:
            progress.add_task("scan", total=None)
            findings = asyncio.run(orchestrator.web_engine.scan_endpoint(
                target_url=target_url,
                check_cors=chk_cors,
                check_headers=chk_headers,
                check_ssl=True,
                check_injection=chk_inj,
            ))

        self._render_findings_table(f"Web Security Posture: {target_url}", findings)

    # =========================================================================
    # [05] API Security Scanner
    # =========================================================================
    def menu_api_scanner(self):
        self.console.print("\n[bold cyan]◈ API SECURITY SCANNER ◈[/bold cyan]")
        target_url = self._select_or_enter_target()
        if not target_url:
            return

        api_type = Prompt.ask("Select API Architecture", choices=["rest", "graphql", "websocket"], default="rest")
        chk_intro = True
        chk_rate = True
        if api_type == "graphql":
            chk_intro = Confirm.ask("Audit GraphQL Introspection & suggestions?", default=True)
        elif api_type == "rest":
            chk_rate = Confirm.ask("Audit Rate Limiting headers & controls?", default=True)

        with Progress(SpinnerColumn(), TextColumn(f"[bold cyan]Auditing {api_type.upper()} API Security..."), console=self.console) as progress:
            progress.add_task("scan", total=None)
            findings = asyncio.run(orchestrator.api_engine.scan_api(
                target_url=target_url,
                api_type=api_type,
                check_introspection=chk_intro,
                check_rate_limit=chk_rate,
            ))

        self._render_findings_table(f"API Security Audit: {target_url} ({api_type.upper()})", findings)

    # =========================================================================
    # [06] Network Vulnerability Scanner
    # =========================================================================
    def menu_network_scanner(self):
        self.console.print("\n[bold cyan]◈ NETWORK VULNERABILITY SCANNER ◈[/bold cyan]")
        target_host = Prompt.ask("Enter Target Hostname or IP address", default="127.0.0.1").strip()
        port_choice = Prompt.ask("Ports to audit (comma separated or 'common')", default="common").strip()

        ports = None
        if port_choice.lower() != "common":
            try:
                ports = [int(p.strip()) for p in port_choice.split(",") if p.strip()]
            except ValueError:
                self.console.print("[bold red][!] Invalid ports list. Reverting to default critical ports.[/bold red]")
                ports = None

        with Progress(SpinnerColumn(), TextColumn(f"[bold cyan]Auditing open ports & services on {target_host}..."), console=self.console) as progress:
            progress.add_task("scan", total=None)
            findings = asyncio.run(orchestrator.network_engine.scan_host(
                target_host=target_host,
                ports=ports,
            ))

        self._render_findings_table(f"Network Assessment: {target_host}", findings)

    # =========================================================================
    # [07] SSL/TLS Security Scanner
    # =========================================================================
    def menu_tls_scanner(self):
        self.console.print("\n[bold cyan]◈ SSL/TLS SECURITY SCANNER ◈[/bold cyan]")
        hostname = Prompt.ask("Enter Hostname (e.g. example.com, gateway.lab)", default="127.0.0.1").strip()
        port = IntPrompt.ask("Enter TLS Port", default=443)

        with Progress(SpinnerColumn(), TextColumn(f"[bold cyan]Inspecting SSL/TLS socket on {hostname}:{port}..."), console=self.console) as progress:
            progress.add_task("scan", total=None)
            findings = asyncio.run(orchestrator.tls_engine.scan_tls(hostname, port))

        self._render_findings_table(f"SSL/TLS Security Audit: {hostname}:{port}", findings)

    # =========================================================================
    # [08] CVE Vulnerability Scanner
    # =========================================================================
    def menu_cve_scanner(self):
        self.console.print("\n[bold cyan]◈ CVE VULNERABILITY SCANNER ◈[/bold cyan]")
        self.console.print("[01] Search Known CVE Database")
        self.console.print("[02] Match Specific Dependency (Package & Version)")
        self.console.print("[03] View CVE Intelligence Catalog")
        self.console.print("[00] Back")

        sub = Prompt.ask("Select option", default="01").strip()
        if sub in ("1", "01"):
            q = Prompt.ask("Enter package name or CVE ID to search").strip().lower()
            matches = [c for c in KNOWN_CVE_DATABASE if q in c["package"].lower() or q in c["cve"].lower() or q in c["title"].lower()]
            if not matches:
                self.console.print(f"[bold yellow][!] No matching CVE advisories found for '{q}'.[/bold yellow]")
            else:
                table = Table(title=f"CVE Advisories Matching '{q}'", box=box.ROUNDED, expand=True)
                table.add_column("CVE ID", style="bold cyan", width=16)
                table.add_column("Package", style="bold white", width=14)
                table.add_column("Fixed Version", width=14)
                table.add_column("Severity", width=10)
                table.add_column("Title / Description", style="dim white")
                for m in matches:
                    table.add_row(m["cve"], m["package"], f">= {m['fixed']}", m["severity"].value, m["title"])
                self.console.print(table)

        elif sub in ("2", "02"):
            eco = Prompt.ask("Ecosystem", choices=["npm", "pip", "cargo", "go", "maven", "composer"], default="npm")
            pkg = Prompt.ask("Package Name").strip()
            ver = Prompt.ask("Version String (e.g. 4.17.15)").strip()
            findings = cve_engine.match_dependency(eco, pkg, ver)
            if not findings:
                self.console.print(f"[bold green][✓] No known vulnerabilities matched for {pkg}=={ver} in verified CVE intelligence database.[/bold green]")
            else:
                self._render_findings_table(f"CVE Findings for {pkg}=={ver}", findings)

        elif sub in ("3", "03"):
            table = Table(title="Verified CVE Intelligence Database Catalog", box=box.ROUNDED, expand=True)
            table.add_column("Ecosystem", width=10)
            table.add_column("Package", style="bold white", width=14)
            table.add_column("CVE ID", style="bold cyan", width=16)
            table.add_column("Fixed In", width=12)
            table.add_column("Severity", width=10)
            table.add_column("Advisory Title", style="dim white")
            for c in KNOWN_CVE_DATABASE:
                table.add_row(c["ecosystem"], c["package"], c["cve"], c["fixed"], c["severity"].value, c["title"])
            self.console.print(table)

    # =========================================================================
    # [09] SAST Scanner
    # =========================================================================
    def menu_sast_scanner(self):
        self.console.print("\n[bold cyan]◈ SOURCE CODE SECURITY SCANNER (SAST) ◈[/bold cyan]")
        path = Prompt.ask("Enter directory or file path to scan", default=".").strip()
        if not os.path.exists(path):
            self.console.print(f"[bold red][!] Path does not exist: {path}[/bold red]")
            return

        with Progress(SpinnerColumn(), TextColumn(f"[bold cyan]Auditing source code in {path}..."), console=self.console) as progress:
            progress.add_task("scan", total=None)
            if os.path.isfile(path):
                findings = orchestrator.sast_engine.scan_file(path)
            else:
                findings, count = orchestrator.sast_engine.scan_directory(path)

        self._render_findings_table(f"Static Analysis (SAST): {path}", findings)

    # =========================================================================
    # [10] SCA Scanner
    # =========================================================================
    def menu_sca_scanner(self):
        self.console.print("\n[bold cyan]◈ SOFTWARE COMPOSITION ANALYSIS (SCA) ◈[/bold cyan]")
        self.console.print("[01] Scan Current Workspace Manifests")
        self.console.print("[02] Scan Specific Manifest File")
        sub = Prompt.ask("Option", default="01").strip()

        if sub in ("1", "01"):
            with Progress(SpinnerColumn(), TextColumn("[bold cyan]Auditing project manifests across workspace..."), console=self.console) as progress:
                progress.add_task("scan", total=None)
                findings = orchestrator.sca_engine.audit_workspace_manifests()
            self._render_findings_table("Workspace Dependency SCA", findings)
        else:
            fpath = Prompt.ask("Enter manifest file path (e.g. package.json, requirements.txt)").strip()
            if not os.path.exists(fpath):
                self.console.print(f"[bold red][!] File not found: {fpath}[/bold red]")
                return
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

            self._render_findings_table(f"SCA Findings for {fpath}", findings)

    # =========================================================================
    # [11] DNS & Domain Scanner
    # =========================================================================
    def menu_dns_scanner(self):
        self.console.print("\n[bold cyan]◈ DNS & DOMAIN SECURITY SCANNER ◈[/bold cyan]")
        domain = Prompt.ask("Enter Domain Name (e.g. example.com)").strip()
        if not domain:
            return

        with Progress(SpinnerColumn(), TextColumn(f"[bold cyan]Auditing DNS records, SPF, DMARC, AXFR for {domain}..."), console=self.console) as progress:
            progress.add_task("scan", total=None)
            findings = asyncio.run(orchestrator.dns_engine.scan_domain(
                domain=domain,
                check_zone_transfer=True,
                check_mail_records=True,
                check_takeover=True,
            ))

        self._render_findings_table(f"DNS & Domain Posture: {domain}", findings)

    # =========================================================================
    # [12] Cloud Security Scanner
    # =========================================================================
    def menu_cloud_scanner(self):
        self.console.print("\n[bold cyan]◈ CLOUD SECURITY SCANNER ◈[/bold cyan]")
        self.console.print("[01] Audit AWS S3 Bucket Public Exposure")
        self.console.print("[02] Audit Azure Blob Container Exposure")
        self.console.print("[03] Audit Google Cloud Storage (GCS) Bucket")
        self.console.print("[04] Audit Cloud IAM Policy JSON File")
        self.console.print("[05] Audit Cloud Security Group / Firewall Rules JSON")
        self.console.print("[00] Back")

        sub = Prompt.ask("Select option", default="01").strip()
        if sub in ("1", "01"):
            bname = Prompt.ask("Enter AWS S3 Bucket Name").strip()
            findings = asyncio.run(orchestrator.cloud_engine.audit_s3_bucket(bname))
            self._render_findings_table(f"AWS S3 Audit: {bname}", findings)
        elif sub in ("2", "02"):
            acct = Prompt.ask("Azure Storage Account Name").strip()
            cont = Prompt.ask("Container Name").strip()
            findings = asyncio.run(orchestrator.cloud_engine.audit_azure_blob_container(acct, cont))
            self._render_findings_table(f"Azure Storage Audit: {acct}/{cont}", findings)
        elif sub in ("3", "03"):
            bname = Prompt.ask("Enter Google Cloud Storage Bucket Name").strip()
            findings = asyncio.run(orchestrator.cloud_engine.audit_gcp_bucket(bname))
            self._render_findings_table(f"GCS Storage Audit: {bname}", findings)
        elif sub in ("4", "04"):
            fpath = Prompt.ask("Enter path to IAM Policy JSON file").strip()
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                findings = orchestrator.cloud_engine.audit_iam_policy_document(content, os.path.basename(fpath))
                self._render_findings_table(f"IAM Policy Audit: {fpath}", findings)
            else:
                self.console.print(f"[bold red][!] File not found: {fpath}[/bold red]")
        elif sub in ("5", "05"):
            fpath = Prompt.ask("Enter path to Security Group JSON file").strip()
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                findings = orchestrator.cloud_engine.audit_security_group_rules(content, os.path.basename(fpath))
                self._render_findings_table(f"Security Group Audit: {fpath}", findings)
            else:
                self.console.print(f"[bold red][!] File not found: {fpath}[/bold red]")

    # =========================================================================
    # [13] Container Security Scanner
    # =========================================================================
    def menu_container_scanner(self):
        self.console.print("\n[bold cyan]◈ CONTAINER & KUBERNETES SECURITY SCANNER ◈[/bold cyan]")
        self.console.print("[01] Audit Dockerfile")
        self.console.print("[02] Audit Kubernetes Manifest (YAML)")
        self.console.print("[03] Audit Docker Daemon Configuration (/etc/docker/daemon.json)")
        self.console.print("[00] Back")

        sub = Prompt.ask("Select option", default="01").strip()
        if sub in ("1", "01"):
            fpath = Prompt.ask("Enter Dockerfile path", default="Dockerfile").strip()
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                findings = orchestrator.container_engine.scan_dockerfile_content(content, fpath)
                self._render_findings_table(f"Dockerfile Security Audit: {fpath}", findings)
            else:
                self.console.print(f"[bold red][!] File not found: {fpath}[/bold red]")
        elif sub in ("2", "02"):
            fpath = Prompt.ask("Enter Kubernetes YAML manifest path").strip()
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                findings = orchestrator.container_engine.scan_kubernetes_manifest(content, fpath)
                self._render_findings_table(f"Kubernetes Security Audit: {fpath}", findings)
            else:
                self.console.print(f"[bold red][!] File not found: {fpath}[/bold red]")
        elif sub in ("3", "03"):
            fpath = Prompt.ask("Enter daemon.json path", default="/etc/docker/daemon.json").strip()
            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                findings = orchestrator.container_engine.audit_docker_daemon_config(content)
                self._render_findings_table(f"Docker Daemon Audit: {fpath}", findings)
            else:
                self.console.print(f"[bold red][!] File not found: {fpath}[/bold red]")

    # =========================================================================
    # [14] Custom Scan Configuration
    # =========================================================================
    def menu_custom_scan(self):
        self.console.print("\n[bold cyan]◈ CUSTOM SCAN CONFIGURATION WIZARD ◈[/bold cyan]")
        target_url = self._select_or_enter_target()
        if not target_url:
            return

        profile = Prompt.ask("Scan Profile", choices=["passive", "quick", "standard", "deep"], default="standard")
        timeout = IntPrompt.ask("Request Timeout (seconds)", default=8)
        concurrency = IntPrompt.ask("Max Concurrency", default=10)
        auth_by = Prompt.ask("Authorized Operator", default="security_lead").strip()

        self.console.print("\n[bold cyan]Custom Scan Configuration Preview:[/bold cyan]")
        self.console.print(f"  Target: {target_url}")
        self.console.print(f"  Profile: {profile.upper()}")
        self.console.print(f"  Timeout: {timeout}s")
        self.console.print(f"  Concurrency: {concurrency}")
        self.console.print(f"  Authorized Operator: {auth_by}")

        if Confirm.ask("\nExecute custom scan with these parameters?", default=True):
            if profile in ("passive", "quick"):
                res = asyncio.run(orchestrator.execute_quick_scan(target_url, authorized_by=auth_by))
            else:
                res = asyncio.run(orchestrator.execute_full_scan(target_url, authorized_by=auth_by))
            self._render_scan_results_table(res)
            self._offer_report_export(res)

    # =========================================================================
    # [15] Vulnerability Results Triage
    # =========================================================================
    def menu_vulnerability_results(self):
        self.console.print("\n[bold cyan]◈ VULNERABILITY FINDINGS TRIAGE ◈[/bold cyan]")
        scans = history_store.list_scans()
        if not scans:
            self.console.print("[bold yellow][!] No scan history available. Run a scan first.[/bold yellow]")
            return

        self.console.print(f"Latest scan: {scans[0]['scanId']} ({scans[0]['target']}) — Total Findings: {scans[0]['totalFindings']}")
        scan_id = Prompt.ask("Enter Scan ID to triage", default=scans[0]["scanId"]).strip()
        scan = history_store.get_scan(scan_id)
        if not scan:
            self.console.print(f"[bold red][!] Scan '{scan_id}' not found.[/bold red]")
            return

        self.console.print("\nFilter By Verification Status:")
        self.console.print("[01] Confirmed (Evidence-verified vulnerabilities)")
        self.console.print("[02] Potential (Suspicious indicators requiring review)")
        self.console.print("[03] Inconclusive (Insufficient evidence or probe timeout)")
        self.console.print("[04] Not Vulnerable (Clean checks)")
        self.console.print("[05] Not Tested (Skipped or out-of-scope checks)")
        self.console.print("[06] All Findings")
        self.console.print("[00] Back")

        sub = Prompt.ask("Select status filter", default="06").strip()
        status_map = {
            "01": VerificationStatus.CONFIRMED,
            "02": VerificationStatus.POTENTIAL,
            "03": VerificationStatus.INCONCLUSIVE,
            "04": VerificationStatus.NOT_VULNERABLE,
            "05": VerificationStatus.NOT_TESTED,
        }

        if sub in status_map:
            filtered = [f for f in scan.findings if f.verificationStatus == status_map[sub]]
            title = f"{status_map[sub].value} Findings ({scan.target})"
        elif sub == "06":
            filtered = scan.findings
            title = f"All Findings ({scan.target})"
        else:
            return

        self._render_findings_table(title, filtered)

    # =========================================================================
    # [16] Security Report Generator
    # =========================================================================
    def menu_report_generator(self):
        self.console.print("\n[bold cyan]◈ SECURITY REPORT GENERATOR ◈[/bold cyan]")
        scans = history_store.list_scans()
        if not scans:
            self.console.print("[bold yellow][!] No scan available to export. Run a scan first.[/bold yellow]")
            return

        scan_id = Prompt.ask("Enter Scan ID to export", default=scans[0]["scanId"]).strip()
        scan = history_store.get_scan(scan_id)
        if not scan:
            self.console.print(f"[bold red][!] Scan '{scan_id}' not found.[/bold red]")
            return

        fmt = Prompt.ask("Select Report Format", choices=["pdf", "json", "csv", "md"], default="pdf")
        try:
            dest = report_exporter.export_report(scan, format_type=fmt)
            self.console.print(f"\n[bold green][✓] Security Report Generated Successfully![/bold green]")
            self.console.print(f"    [bold cyan]Format:[/bold cyan] {fmt.upper()}")
            self.console.print(f"    [bold cyan]Destination:[/bold cyan] {dest}\n")
        except Exception as e:
            self.console.print(f"[bold red][!] Failed to generate report: {str(e)}[/bold red]")

    # =========================================================================
    # [17] Scan History
    # =========================================================================
    def menu_scan_history(self):
        self.console.print("\n[bold cyan]◈ SCAN HISTORY & COMPARISON ◈[/bold cyan]")
        scans = history_store.list_scans()
        if not scans:
            self.console.print("[bold yellow][!] No previous scans recorded.[/bold yellow]")
            return

        table = Table(title="Historical Vulnerability Scans", box=box.ROUNDED, expand=True)
        table.add_column("Scan ID", style="bold cyan", width=22)
        table.add_column("Target", style="bold white", width=26)
        table.add_column("Type", width=14)
        table.add_column("Status", width=10)
        table.add_column("Findings", justify="center", width=10)
        table.add_column("Risk", justify="center", width=8)
        table.add_column("Duration", justify="center", width=10)

        for s in scans:
            dur = f"{s.get('durationSeconds', 0):.2f}s"
            table.add_row(
                s["scanId"],
                s["target"],
                s.get("scanType", "N/A"),
                f"[green]{s['status']}[/green]",
                f"[bold red]{s['totalFindings']}[/bold red]",
                f"{s.get('riskScore', 0.0):.1f}",
                dur,
            )
        self.console.print(table)

        if len(scans) >= 2 and Confirm.ask("\nCompare two scans to detect new vs resolved vulnerabilities?", default=False):
            id_a = Prompt.ask("Enter Older Scan ID", default=scans[1]["scanId"]).strip()
            id_b = Prompt.ask("Enter Newer Scan ID", default=scans[0]["scanId"]).strip()
            cmp_res = history_store.compare_scans(id_a, id_b)
            if "error" in cmp_res:
                self.console.print(f"[bold red][!] {cmp_res['error']}[/bold red]")
            else:
                c_panel = Panel(
                    f"[bold green]Resolved Findings:[/bold green] {cmp_res['resolvedFindingsCount']}\n"
                    f"[bold red]New Findings:[/bold red] {cmp_res['newFindingsCount']}\n"
                    f"[bold yellow]Persistent Findings:[/bold yellow] {cmp_res['persistentFindingsCount']}\n"
                    f"[bold cyan]Risk Delta:[/bold cyan] {cmp_res['riskDelta']}",
                    title=f"Scan Comparison: {id_a} vs {id_b}",
                    box=box.ROUNDED,
                )
                self.console.print(c_panel)

    # =========================================================================
    # [18] Rules Database
    # =========================================================================
    def menu_rules_database(self):
        self.console.print("\n[bold cyan]◈ VULNERABILITY RULES DATABASE ◈[/bold cyan]")
        rules = rule_registry.list_all()
        table = Table(title=f"CipherFlux Evidence Detection Rules ({len(rules)} Loaded)", box=box.ROUNDED, expand=True)
        table.add_column("Rule ID", style="bold cyan", width=16)
        table.add_column("Rule Name", style="bold white", width=28)
        table.add_column("CWE", width=10)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6)
        table.add_column("Detection & Evidence Logic", style="dim white")

        for r in rules:
            table.add_row(r.rule_id, r.rule_name, r.cwe_id, r.default_severity.value, r.cvss_base, r.detection_logic)
        self.console.print(table)

    # =========================================================================
    # [19] Settings & Configuration
    # =========================================================================
    def menu_settings(self):
        self.console.print("\n[bold cyan]◈ SETTINGS & CONFIGURATION ◈[/bold cyan]")
        cfg = config_store.all()

        table = Table(title="CipherFlux Active Settings", box=box.ROUNDED, expand=True)
        table.add_column("Configuration Key", style="bold cyan", width=28)
        table.add_column("Current Value", style="bold white")

        for k, v in cfg.items():
            table.add_row(k, str(v))
        self.console.print(table)

        self.console.print("\n[01] Edit Setting Value")
        self.console.print("[02] Reset to Safe Defaults")
        self.console.print("[00] Back")
        sub = Prompt.ask("Option", default="00").strip()

        if sub in ("1", "01"):
            key = Prompt.ask("Enter setting key to modify").strip()
            if key in cfg:
                new_val = Prompt.ask(f"Enter new value for '{key}'").strip()
                # Type cast
                if isinstance(cfg[key], bool):
                    new_val = new_val.lower() in ("true", "1", "yes")
                elif isinstance(cfg[key], int):
                    new_val = int(new_val)
                elif isinstance(cfg[key], float):
                    new_val = float(new_val)
                config_store.set(key, new_val)
                self.console.print(f"[bold green][✓] Updated {key} = {new_val}[/bold green]")
            else:
                self.console.print(f"[bold red][!] Setting '{key}' not found.[/bold red]")
        elif sub in ("2", "02"):
            if Confirm.ask("Reset all configuration to factory safe defaults?", default=False):
                config_store.reset_defaults()
                self.console.print("[bold green][✓] Configuration reset to safe defaults.[/bold green]")

    # =========================================================================
    # [20] System Diagnostics
    # =========================================================================
    def menu_diagnostics(self):
        self.console.print("\n[bold cyan]◈ RUNNING SYSTEM DIAGNOSTICS ('cipherflux doctor') ◈[/bold cyan]\n")
        SystemDiagnostics.render_diagnostics(self.console)

    # =========================================================================
    # [21] Help & Documentation
    # =========================================================================
    def menu_help(self):
        help_text = f"""
[bold cyan]CIPHERFLUX LABS — KALI LINUX VULNERABILITY ASSESSMENT FRAMEWORK[/bold cyan]
Version: {VERSION}

[bold white]Command-Line Usage:[/bold white]
  cipherflux                     Start interactive Metasploit-style CLI
  cipherflux doctor              Run system diagnostics & integrity check
  cipherflux targets             View and manage registered target assets
  cipherflux scan <target>       Run standard security audit against target
  cipherflux scan --profile quick <target>   Run low-impact quick audit
  cipherflux scan --profile deep <target>    Run deep comprehensive assessment
  cipherflux web <url>           Scan web application security posture
  cipherflux api <url>           Scan API (REST, GraphQL, WebSocket)
  cipherflux network <host>      Execute authorized port discovery
  cipherflux ssl <host>          Inspect SSL/TLS handshake & ciphers
  cipherflux cve                 Query CVE intelligence database
  cipherflux sast <path>         Run static code security analysis
  cipherflux sca <manifest>      Audit dependencies for known CVEs
  cipherflux dns <domain>        Audit DNS records, SPF, DMARC, AXFR
  cipherflux cloud <target>      Audit AWS/Azure/GCP storage & IAM
  cipherflux container <file>    Audit Dockerfile & Kubernetes manifests
  cipherflux results             Triage vulnerability findings
  cipherflux history             View scan history & comparison
  cipherflux report              Export PDF/Markdown/CSV audit reports

[bold white]Core Principles:[/bold white]
  • [bold green]Evidence Before Confirmation[/bold green]: Findings are rigorously validated.
  • [bold yellow]No Fabricated Results[/bold yellow]: Every result originates from executed checks.
  • [bold red]Defensive Assessment Only[/bold red]: Zero exploitation or DoS testing.
"""
        self.console.print(Panel(help_text, title="CipherFlux Help & Documentation", box=box.ROUNDED))

    # =========================================================================
    # Helper Renderers
    # =========================================================================
    def _render_scan_results_table(self, scan: ScanResponse):
        self.console.print(f"\n[bold green][✓] Assessment Complete: Scan ID {scan.scanId}[/bold green]")
        self.console.print(f"[bold cyan]Target:[/bold cyan] {scan.target} | [bold cyan]Duration:[/bold cyan] {scan.summary.durationSeconds:.2f}s | [bold cyan]Risk Score:[/bold cyan] {scan.summary.riskScore:.1f}/100")

        sum_panel = Panel(
            f"[bold red]Critical: {scan.summary.criticalCount}[/bold red] | "
            f"[bold orange3]High: {scan.summary.highCount}[/bold orange3] | "
            f"[bold yellow]Medium: {scan.summary.mediumCount}[/bold yellow] | "
            f"[bold blue]Low: {scan.summary.lowCount}[/bold blue] | "
            f"[bold cyan]Info: {scan.summary.infoCount}[/bold cyan] || "
            f"[bold green]Confirmed: {scan.summary.confirmedCount}[/bold green] | "
            f"[bold yellow]Potential: {scan.summary.potentialCount}[/bold yellow] | "
            f"[bold blue]Inconclusive: {scan.summary.inconclusiveCount}[/bold blue]",
            title="Scan Summary",
            box=box.ROUNDED,
        )
        self.console.print(sum_panel)

        self._render_findings_table(f"Findings Dossier ({scan.scanId})", scan.findings)

    def _render_findings_table(self, title: str, findings: List[SecurityFinding]):
        if not findings:
            self.console.print(f"\n[bold green][✓] No security vulnerabilities detected for this check.[/bold green]\n")
            return

        table = Table(title=title, box=box.ROUNDED, expand=True)
        table.add_column("No.", style="bold cyan", width=4, justify="center")
        table.add_column("Severity", width=12, justify="center")
        table.add_column("Vulnerability Title", style="bold white", width=34)
        table.add_column("Category", width=18)
        table.add_column("CWE / CVE", width=14)
        table.add_column("Status", width=14, justify="center")
        table.add_column("Affected Asset / Scope", style="dim white")

        for idx, f in enumerate(findings, start=1):
            # Severity color
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev == "CRITICAL":
                sev_styled = "[bold red]CRITICAL[/bold red]"
            elif sev == "HIGH":
                sev_styled = "[bold red]HIGH[/bold red]"
            elif sev == "MEDIUM":
                sev_styled = "[bold yellow]MEDIUM[/bold yellow]"
            elif sev == "LOW":
                sev_styled = "[bold blue]LOW[/bold blue]"
            else:
                sev_styled = "[bold cyan]INFO[/bold cyan]"

            # Status color
            st = f.verificationStatus.value if hasattr(f.verificationStatus, "value") else str(f.verificationStatus)
            if st == "CONFIRMED":
                st_styled = "[bold green]CONFIRMED[/bold green]"
            elif st == "POTENTIAL":
                st_styled = "[bold yellow]POTENTIAL[/bold yellow]"
            elif st == "INCONCLUSIVE":
                st_styled = "[bold blue]INCONCLUSIVE[/bold blue]"
            elif st == "NOT_VULNERABLE":
                st_styled = "[dim green]NOT_VULN[/dim green]"
            else:
                st_styled = "[dim white]NOT_TESTED[/dim white]"

            ref_id = f.cveId or f.cweId or "N/A"
            table.add_row(str(idx), sev_styled, f.title, f.category, ref_id, st_styled, f.targetScope)

        self.console.print(table)

    def _offer_report_export(self, scan: ScanResponse):
        if Confirm.ask("\nGenerate and export detailed security audit report?", default=True):
            fmt = Prompt.ask("Select format", choices=["pdf", "json", "csv", "md"], default="pdf")
            try:
                dest = report_exporter.export_report(scan, format_type=fmt)
                self.console.print(f"[bold green][✓] Report saved to: {dest}[/bold green]\n")
            except Exception as e:
                self.console.print(f"[bold red][!] Report export error: {str(e)}[/bold red]")
