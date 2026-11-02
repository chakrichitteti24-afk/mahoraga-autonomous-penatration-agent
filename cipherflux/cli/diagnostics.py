"""
CipherFlux Labs System Diagnostics & Integrity Engine ('cipherflux doctor').
Performs real diagnostics on Python runtime, operating system, core dependencies,
scanner engine integrity, rule database, and reporting subsystems.
"""
import sys
import os
import platform
import importlib
from pathlib import Path
from typing import List, Dict, Any, Tuple
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .theme import get_console
from .banner import get_platform_name
from backend.core.false_positive_engine import rule_registry
from backend.scanners.cve_engine import KNOWN_CVE_DATABASE
from ..storage.target_store import target_store
from ..storage.config_store import config_store

class DiagnosticResult:
    def __init__(self, category: str, check_name: str, status: str, details: str):
        self.category = category
        self.check_name = check_name
        self.status = status.upper()  # PASS, FAIL, WARNING, NOT_IMPLEMENTED
        self.details = details

class SystemDiagnostics:
    @staticmethod
    def run_all_checks() -> List[DiagnosticResult]:
        results: List[DiagnosticResult] = []

        # 1. Python Version Check
        py_ver = sys.version_info
        py_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
        if py_ver >= (3, 10):
            results.append(DiagnosticResult("Environment", "Python Runtime", "PASS", f"Python {py_str} (>= 3.10 requirement satisfied)"))
        elif py_ver >= (3, 8):
            results.append(DiagnosticResult("Environment", "Python Runtime", "WARNING", f"Python {py_str} (Python 3.10+ recommended)"))
        else:
            results.append(DiagnosticResult("Environment", "Python Runtime", "FAIL", f"Python {py_str} is unsupported (< 3.8)"))

        # 2. Operating System
        plat_name = get_platform_name()
        if "KALI" in plat_name:
            results.append(DiagnosticResult("Environment", "Operating System", "PASS", f"{plat_name} (Primary Supported Platform)"))
        elif "DEBIAN" in plat_name or "LINUX" in plat_name:
            results.append(DiagnosticResult("Environment", "Operating System", "PASS", f"{plat_name} (Compatible Debian-based distribution)"))
        else:
            results.append(DiagnosticResult("Environment", "Operating System", "PASS", f"{plat_name} (Cross-platform Development Environment)"))

        # 3. Critical Dependencies
        core_deps = [
            ("rich", "Rich Terminal Rendering"),
            ("cryptography", "X.509 Certificate & TLS Inspection"),
            ("httpx", "Asynchronous HTTP/2 Probing Client"),
            ("dns", "DNS Resolver & AXFR Query Engine"),
            ("reportlab", "PDF Security Audit Exporter"),
            ("pydantic", "Schema Validation & Data Integrity"),
            ("yaml", "IaC & Kubernetes Manifest Parser"),
            ("PIL", "CipherFlux Icon & Graphic Generation"),
        ]
        for mod, desc in core_deps:
            try:
                importlib.import_module(mod)
                results.append(DiagnosticResult("Dependencies", f"Package: {mod}", "PASS", f"{desc} loaded successfully"))
            except ImportError as e:
                results.append(DiagnosticResult("Dependencies", f"Package: {mod}", "FAIL", f"Missing dependency: {str(e)}"))

        # 4. Scanner Engine Status
        engines = [
            ("SAST Engine", "backend.scanners.sast_scanner", "SASTScanner"),
            ("Web DAST Engine", "backend.scanners.web_scanner", "WebPostureScanner"),
            ("API Security Engine", "backend.scanners.api_scanner", "APISecurityScanner"),
            ("Network Engine", "backend.scanners.network_scanner", "NetworkScanner"),
            ("SSL/TLS Engine", "backend.scanners.tls_scanner", "TLSScanner"),
            ("DNS Security Engine", "backend.scanners.dns_scanner", "DNSDomainScanner"),
            ("SCA Dependency Engine", "backend.scanners.sca_scanner", "SCAScanner"),
            ("Container & IaC Engine", "cipherflux.scanners.container_scanner", "ContainerSecurityScanner"),
            ("Cloud Security Engine", "cipherflux.scanners.cloud_scanner", "CloudSecurityScanner"),
            ("Live CVE Feed (OSV/NVD)", "backend.scanners.osv_feed", "LiveCVEFeedEngine"),
        ]
        for name, mod_path, cls_name in engines:
            try:
                mod = importlib.import_module(mod_path)
                cls_obj = getattr(mod, cls_name)
                # Instantiate to verify
                _ = cls_obj()
                results.append(DiagnosticResult("Scanner Engines", name, "PASS", "Initialized and operational"))
            except Exception as e:
                results.append(DiagnosticResult("Scanner Engines", name, "FAIL", f"Initialization error: {str(e)}"))

        # 4b. Playwright Browser Security Engine
        try:
            from backend.scanners.browser_engine import browser_engine
            avail, reason = browser_engine.is_available()
            if avail:
                results.append(DiagnosticResult("Browser Engine", "Playwright Chromium", "PASS", "Headless browser operational for DOM/CSP analysis"))
            else:
                results.append(DiagnosticResult("Browser Engine", "Playwright Chromium", "WARNING", "Optional: pip install playwright && playwright install chromium"))
        except Exception as e:
            results.append(DiagnosticResult("Browser Engine", "Playwright Chromium", "WARNING", f"Browser engine unavailable: {e}"))

        # 5. Core Verification & False-Positive Registry
        try:
            from backend.core.verification_engine import VerificationEngine
            _ = VerificationEngine()
            results.append(DiagnosticResult("Verification", "Verification Engine", "PASS", "Independent non-destructive probe engine ready"))
        except Exception as e:
            results.append(DiagnosticResult("Verification", "Verification Engine", "FAIL", f"Error: {str(e)}"))

        # 6. Rules Database
        rule_count = len(rule_registry.list_all())
        if rule_count > 0:
            results.append(DiagnosticResult("Database", "Detection Rules", "PASS", f"{rule_count} authoritative evidence-based rules loaded"))
        else:
            results.append(DiagnosticResult("Database", "Detection Rules", "WARNING", "No detection rules found in registry"))

        # 7. CVE Intelligence Database
        cve_count = len(KNOWN_CVE_DATABASE)
        if cve_count > 0:
            results.append(DiagnosticResult("Database", "CVE Intelligence", "PASS", f"{cve_count} verified CVE advisories active"))
        else:
            results.append(DiagnosticResult("Database", "CVE Intelligence", "WARNING", "CVE intelligence catalog is empty"))

        # 8. Storage & Targets Registry
        try:
            t_count = len(target_store.list_targets())
            results.append(DiagnosticResult("Storage", "Target Registry", "PASS", f"Target database active ({t_count} targets registered)"))
        except Exception as e:
            results.append(DiagnosticResult("Storage", "Target Registry", "FAIL", f"Storage error: {str(e)}"))

        # 9. Configuration File Access
        try:
            cfg = config_store.all()
            results.append(DiagnosticResult("Storage", "Configuration Store", "PASS", f"Config loaded ({len(cfg)} parameters)"))
        except Exception as e:
            results.append(DiagnosticResult("Storage", "Configuration Store", "FAIL", f"Config error: {str(e)}"))

        # 10. Assets & Application Icons
        icon_path = Path("assets/icons/icon-256.png")
        svg_path = Path("assets/cipherflux-logo.svg")
        if icon_path.exists() and svg_path.exists():
            results.append(DiagnosticResult("Assets", "Application Icons & SVG", "PASS", "Icon variants and master SVG verified"))
        else:
            results.append(DiagnosticResult("Assets", "Application Icons & SVG", "WARNING", "Icon assets partially missing"))

        # 11. Unimplemented / Intentionally Out-of-Scope modules
        results.append(DiagnosticResult("Safety Policy", "Active Exploitation Engine", "NOT_IMPLEMENTED", "Intentionally omitted: CipherFlux strictly enforces non-destructive vulnerability assessment"))
        results.append(DiagnosticResult("Safety Policy", "Denial of Service (DoS) Testing", "NOT_IMPLEMENTED", "Intentionally omitted: Prohibited by safe assessment policy"))

        return results

    @classmethod
    def render_diagnostics(cls, console=None) -> bool:
        """Render diagnostic results to Rich terminal and return True if all critical tests pass."""
        if console is None:
            console = get_console()

        results = cls.run_all_checks()

        table = Table(
            title="◈ CIPHERFLUX LABS — SYSTEM DIAGNOSTICS & ENGINE INTEGRITY ◈",
            title_style="bold cyan",
            box=box.ROUNDED,
            expand=True,
        )
        table.add_column("Category", style="bold cyan", width=18)
        table.add_column("Diagnostic Check", style="bold white", width=26)
        table.add_column("Status", justify="center", width=18)
        table.add_column("Details", style="dim white")

        pass_count = 0
        fail_count = 0
        warn_count = 0
        not_impl_count = 0

        for r in results:
            if r.status == "PASS":
                pass_count += 1
                status_txt = Text("[ PASS ]", style="bold green")
            elif r.status == "FAIL":
                fail_count += 1
                status_txt = Text("[ FAIL ]", style="bold red")
            elif r.status == "WARNING":
                warn_count += 1
                status_txt = Text("[ WARNING ]", style="bold yellow")
            else:
                not_impl_count += 1
                status_txt = Text("[ NOT_IMPLEMENTED ]", style="bold blue")

            table.add_row(r.category, r.check_name, status_txt, r.details)

        console.print(table)

        summary_text = (
            f"Diagnostics Complete: [bold green]{pass_count} Passed[/bold green] | "
            f"[bold red]{fail_count} Failed[/bold red] | "
            f"[bold yellow]{warn_count} Warnings[/bold yellow] | "
            f"[bold blue]{not_impl_count} Not Implemented[/bold blue]"
        )
        panel = Panel(summary_text, border_style="cyan" if fail_count == 0 else "red")
        console.print(panel)

        return fail_count == 0
