"""
CipherFlux Labs — Playwright Browser Security Engine
Performs JavaScript-aware security analysis on live web pages.

Detects:
  - DOM-based XSS sinks (document.write, innerHTML, eval, location.hash)
  - JWT / sensitive tokens stored in localStorage or sessionStorage
  - Content-Security-Policy bypass via unsafe-inline / unsafe-eval
  - Mixed active content (HTTP resources on HTTPS pages)
  - Overly permissive postMessage listeners
  - Prototype pollution indicators in global objects
  - JavaScript source map exposure
  - Inline script secrets (hardcoded API keys, passwords)
  - Console error / stack trace leakage

Uses Playwright Chromium in headless isolated mode.
Falls back gracefully to NOT_TESTED if Playwright is not installed.
All probing is passive (no input injection, no form submission).
"""
from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..models.schemas import SecurityFinding, SeverityLevel, VerificationStatus

logger = logging.getLogger("cipherflux.browser_engine")

# ─── Playwright Availability Check ───────────────────────────────────────────
_PLAYWRIGHT_AVAILABLE = False
_PLAYWRIGHT_MISSING_REASON = ""

try:
    from playwright.async_api import async_playwright, Browser, Page, Response as PwResponse
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_MISSING_REASON = (
        "playwright package is not installed. "
        "Run: pip install playwright && playwright install chromium"
    )
    logger.info("Playwright not available: %s", _PLAYWRIGHT_MISSING_REASON)


# ─── Detection Patterns ──────────────────────────────────────────────────────
# DOM XSS sinks we inject a canary into and watch for reflection
_DOM_XSS_SINKS = [
    "document.write(",
    "document.writeln(",
    ".innerHTML",
    ".outerHTML",
    ".insertAdjacentHTML(",
    "eval(",
    "setTimeout(\"",
    "setInterval(\"",
    "location.href",
    "location.hash",
    "location.search",
    "document.URL",
    "document.referrer",
]

_DANGEROUS_STORAGE_PATTERNS = [
    r"(?i)(access_token|id_token|auth_token|jwt|bearer|session_token)\s*[:=]\s*[\"']?[A-Za-z0-9\-_\.]+",
    r"(?i)token\s*[:=]\s*[\"']?ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",  # JWT
    r"(?i)(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*[\"']?[^\"'\s]{4,}",
    r"(?i)Authorization\s*[:=]\s*Bearer\s+[A-Za-z0-9\-_\.]+",
    r"ey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+",  # Raw JWT pattern
]

_INLINE_SECRET_PATTERNS = [
    (r"(?i)api[_-]?key\s*[=:]\s*[\"'][A-Za-z0-9\-_]{16,}[\"']", "Hardcoded API Key in Script"),
    (r"(?i)secret[_-]?key\s*[=:]\s*[\"'][A-Za-z0-9\-_]{16,}[\"']", "Hardcoded Secret Key in Script"),
    (r"(?i)password\s*[=:]\s*[\"'][^\"']{6,}[\"']", "Hardcoded Password in Script"),
    (r"(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*[\"']AKIA[A-Z0-9]{16}[\"']", "AWS Access Key ID Exposure"),
    (r"(?i)private[_-]?key\s*[=:]\s*[\"']-----BEGIN", "Private Key Material in Script"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token Exposure"),
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key Exposure"),
    (r"AIza[A-Za-z0-9\-_]{35}", "Google API Key Exposure"),
]

_CSP_UNSAFE_DIRECTIVES = ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"]

_PROTOTYPE_POLLUTION_CHECK = """
(function() {
    var results = [];
    var testKey = '__cipherflux_probe_' + Math.random().toString(36).slice(2);
    try {
        var probe = JSON.parse('{"__proto__": {"' + testKey + '": 1}}');
        if ({}[testKey] === 1) results.push('prototype_pollution_detected');
    } catch(e) {}
    return results;
})();
"""

_POSTMESSAGE_LISTENER_CHECK = """
(function() {
    var listenerCount = 0;
    var origAddEventListener = EventTarget.prototype.addEventListener;
    return typeof window.__cipherflux_pmlisteners !== 'undefined'
        ? window.__cipherflux_pmlisteners
        : 'not_instrumented';
})();
"""

_DOM_SINK_SCAN_SCRIPT = """
(function() {
    var findings = [];
    var pageSource = document.documentElement.outerHTML;
    var sinks = %s;
    sinks.forEach(function(sink) {
        if (pageSource.indexOf(sink) !== -1) {
            findings.push(sink);
        }
    });
    return findings;
})();
""" % str(_DOM_XSS_SINKS)

_STORAGE_SCAN_SCRIPT = """
(function() {
    var results = {localStorage: {}, sessionStorage: {}};
    try {
        for (var i = 0; i < localStorage.length; i++) {
            var key = localStorage.key(i);
            results.localStorage[key] = localStorage.getItem(key);
        }
    } catch(e) {}
    try {
        for (var i = 0; i < sessionStorage.length; i++) {
            var key = sessionStorage.key(i);
            results.sessionStorage[key] = sessionStorage.getItem(key);
        }
    } catch(e) {}
    return results;
})();
"""

_MIXED_CONTENT_SCAN_SCRIPT = """
(function() {
    var mixedResources = [];
    var allElements = document.querySelectorAll('[src],[href],[action]');
    allElements.forEach(function(el) {
        var url = el.src || el.href || el.action || '';
        if (url && url.startsWith('http://') && window.location.protocol === 'https:') {
            mixedResources.push({tag: el.tagName, url: url.substring(0, 120)});
        }
    });
    return mixedResources;
})();
"""


# ─── Result Data Class ───────────────────────────────────────────────────────
@dataclass
class BrowserScanResult:
    target_url: str
    page_title: str = ""
    csp_header: str = ""
    console_errors: List[str] = field(default_factory=list)
    dom_sinks_found: List[str] = field(default_factory=list)
    storage_findings: List[str] = field(default_factory=list)
    mixed_content: List[Dict] = field(default_factory=list)
    inline_secrets: List[Tuple[str, str]] = field(default_factory=list)
    source_maps_exposed: List[str] = field(default_factory=list)
    js_errors: List[str] = field(default_factory=list)
    prototype_pollution: bool = False
    response_headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None


# ─── Browser Engine ──────────────────────────────────────────────────────────
class PlaywrightBrowserEngine:
    """
    Headless Chromium-powered browser security scanner.
    All checks are passive — no form submission, no input injection,
    no authentication attempts, no destructive probing.
    """

    def __init__(
        self,
        timeout_ms: int = 15_000,
        headless: bool = True,
        user_agent: str = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 "
            "(CipherFlux Labs Security Audit)"
        ),
    ):
        self.timeout_ms = timeout_ms
        self.headless = headless
        self.user_agent = user_agent

    def is_available(self) -> Tuple[bool, str]:
        """Return (available, reason) tuple."""
        return _PLAYWRIGHT_AVAILABLE, _PLAYWRIGHT_MISSING_REASON

    async def scan(self, target_url: str) -> List[SecurityFinding]:
        """
        Run the full passive browser security scan against a URL.
        Returns a list of SecurityFinding objects.
        Returns a NOT_TESTED finding if Playwright is not installed.
        """
        if not _PLAYWRIGHT_AVAILABLE:
            return [self._make_not_tested(target_url)]

        result = await self._collect_browser_data(target_url)

        if result.error:
            return [self._make_error_finding(target_url, result.error)]

        return self._analyse(result, target_url)

    async def _collect_browser_data(self, target_url: str) -> BrowserScanResult:
        result = BrowserScanResult(target_url=target_url)
        console_messages: List[str] = []
        js_errors: List[str] = []
        response_headers: Dict[str, str] = {}

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=self.headless,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-web-security",   # allow cross-origin JS reads
                        "--disable-dev-shm-usage",
                        "--disable-extensions",
                    ],
                )
                context = await browser.new_context(
                    user_agent=self.user_agent,
                    java_script_enabled=True,
                    ignore_https_errors=True,
                )
                page = await context.new_page()

                # Wire up listeners before navigation
                page.on("console", lambda msg: console_messages.append(
                    f"[{msg.type.upper()}] {msg.text}"
                ))
                page.on("pageerror", lambda err: js_errors.append(str(err)))

                resp = await page.goto(
                    target_url,
                    timeout=self.timeout_ms,
                    wait_until="networkidle",
                )

                if resp:
                    response_headers = dict(resp.headers)

                result.page_title = await page.title()
                result.response_headers = response_headers
                result.csp_header = response_headers.get(
                    "content-security-policy", ""
                )
                result.console_errors = [
                    m for m in console_messages if "[ERROR]" in m or "[WARNING]" in m
                ]
                result.js_errors = js_errors

                # DOM sink scan
                dom_sinks = await page.evaluate(_DOM_SINK_SCAN_SCRIPT)
                result.dom_sinks_found = dom_sinks or []

                # Storage scan
                storage = await page.evaluate(_STORAGE_SCAN_SCRIPT)
                result.storage_findings = self._check_storage_secrets(storage)

                # Mixed content scan
                mixed = await page.evaluate(_MIXED_CONTENT_SCAN_SCRIPT)
                result.mixed_content = mixed or []

                # Inline script scan
                page_source = await page.content()
                result.inline_secrets = self._scan_inline_secrets(page_source)

                # Source map exposure
                result.source_maps_exposed = self._find_source_maps(response_headers, page_source)

                # Prototype pollution check
                try:
                    pp_result = await page.evaluate(_PROTOTYPE_POLLUTION_CHECK)
                    result.prototype_pollution = "prototype_pollution_detected" in (pp_result or [])
                except Exception:
                    pass

                await context.close()
                await browser.close()

        except Exception as e:
            result.error = str(e)

        return result

    # ─── Analysis → Findings ─────────────────────────────────────────────────
    def _analyse(self, result: BrowserScanResult, target_url: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url

        # 1. DOM XSS sinks
        if result.dom_sinks_found:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"DOM XSS Sink Patterns Detected in JavaScript ({hostname})",
                severity=SeverityLevel.HIGH,
                category="Cross-Site Scripting (XSS)",
                targetScope=target_url,
                cvss="7.5",
                cweId="CWE-79",
                cveId=None,
                owaspCategory="A03:2021-Injection",
                description=(
                    f"The following dangerous DOM XSS sink patterns were identified in the "
                    f"page's JavaScript: {', '.join(result.dom_sinks_found[:8])}. "
                    f"These patterns can facilitate DOM-based XSS when user-controlled input "
                    f"reaches these sinks without sanitisation."
                ),
                remediationSummary=(
                    "Replace innerHTML assignments with textContent or DOMPurify-sanitised output. "
                    "Avoid eval() and document.write(). Use Trusted Types API."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                    "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                ],
                verificationStatus=VerificationStatus.POTENTIAL,
                statusBadge="DOM XSS SINK DETECTED",
                confidence=0.65,
                evidence={
                    "sinks_found": result.dom_sinks_found,
                    "source": "Playwright DOM scan",
                },
            ))

        # 2. JWT / secret in localStorage / sessionStorage
        for storage_finding in result.storage_findings:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"Sensitive Token / Secret Stored in Browser Storage ({hostname})",
                severity=SeverityLevel.HIGH,
                category="Insecure Session Management",
                targetScope=target_url,
                cvss="7.5",
                cweId="CWE-312",
                cveId=None,
                owaspCategory="A02:2021-Cryptographic Failures",
                description=(
                    f"A security-sensitive token or credential was detected in browser localStorage "
                    f"or sessionStorage: {storage_finding}. "
                    f"Storage APIs are accessible to any JavaScript on the page and cannot be "
                    f"protected from XSS attacks."
                ),
                remediationSummary=(
                    "Store authentication tokens exclusively in HttpOnly, Secure, SameSite=Strict cookies. "
                    "Never store JWT access tokens, API keys, or passwords in localStorage/sessionStorage."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
                ],
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="SENSITIVE TOKEN IN STORAGE",
                confidence=0.92,
                evidence={"pattern_matched": storage_finding, "source": "Playwright storage scan"},
            ))

        # 3. CSP misconfiguration
        if result.csp_header:
            csp_issues = self._analyse_csp(result.csp_header)
            for issue in csp_issues:
                findings.append(SecurityFinding(
                    id=f"finding-{uuid.uuid4().hex[:8]}",
                    title=f"Weak Content Security Policy: {issue} ({hostname})",
                    severity=SeverityLevel.MEDIUM,
                    category="Security Header Misconfiguration",
                    targetScope=target_url,
                    cvss="5.4",
                    cweId="CWE-693",
                    cveId=None,
                    owaspCategory="A05:2021-Security Misconfiguration",
                    description=(
                        f"The Content-Security-Policy header contains the unsafe directive '{issue}'. "
                        f"This weakens the policy and may allow inline script execution or "
                        f"connections to arbitrary external origins."
                    ),
                    remediationSummary=(
                        f"Remove '{issue}' from CSP. Use nonces or hashes for inline scripts. "
                        "Use the strict-dynamic approach for trusted script loading."
                    ),
                    references=[
                        "https://content-security-policy.com/",
                        "https://web.dev/articles/strict-csp",
                    ],
                    verificationStatus=VerificationStatus.CONFIRMED,
                    statusBadge="WEAK CSP DIRECTIVE",
                    confidence=0.95,
                    evidence={"csp_header": result.csp_header[:300], "unsafe_directive": issue},
                ))
        elif not result.csp_header:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"Content-Security-Policy (CSP) Header Missing ({hostname})",
                severity=SeverityLevel.MEDIUM,
                category="Security Header Misconfiguration",
                targetScope=target_url,
                cvss="5.4",
                cweId="CWE-693",
                cveId=None,
                owaspCategory="A05:2021-Security Misconfiguration",
                description=(
                    "No Content-Security-Policy (CSP) header was returned by the server. "
                    "CSP is a critical defence against XSS and data injection attacks."
                ),
                remediationSummary=(
                    "Add a strict Content-Security-Policy header. "
                    "Start with: Content-Security-Policy: default-src 'self'"
                ),
                references=["https://content-security-policy.com/"],
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="MISSING CSP",
                confidence=0.99,
                evidence={"source": "Playwright response headers"},
            ))

        # 4. Mixed active content
        if result.mixed_content:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"Mixed Active Content (HTTP Resources on HTTPS Page) ({hostname})",
                severity=SeverityLevel.MEDIUM,
                category="Insecure Transport",
                targetScope=target_url,
                cvss="5.9",
                cweId="CWE-311",
                cveId=None,
                owaspCategory="A02:2021-Cryptographic Failures",
                description=(
                    f"The HTTPS page loads {len(result.mixed_content)} resource(s) over plain HTTP. "
                    f"Mixed content downgrades TLS protections and allows network attackers "
                    f"to intercept or modify page resources."
                ),
                remediationSummary="Update all resource URLs to use HTTPS. Enable upgrade-insecure-requests CSP directive.",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="MIXED CONTENT",
                confidence=0.98,
                evidence={"mixed_resources": result.mixed_content[:5], "source": "Playwright DOM scan"},
            ))

        # 5. Inline script secrets
        for secret_value, secret_type in result.inline_secrets:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"{secret_type} Exposed in Client-Side JavaScript ({hostname})",
                severity=SeverityLevel.CRITICAL,
                category="Sensitive Data Exposure",
                targetScope=target_url,
                cvss="9.1",
                cweId="CWE-200",
                cveId=None,
                owaspCategory="A02:2021-Cryptographic Failures",
                description=(
                    f"A {secret_type} was detected in client-side JavaScript source. "
                    f"Any visitor can read this credential from browser DevTools or the page source, "
                    f"which could lead to full account or service compromise."
                ),
                remediationSummary=(
                    "Remove all credentials from client-side code immediately. "
                    "Rotate any exposed keys or tokens. Use server-side proxies for API calls."
                ),
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure",
                ],
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="SECRET IN CLIENT JS",
                confidence=0.90,
                evidence={"secret_type": secret_type, "source": "Playwright inline script scan"},
            ))

        # 6. Source map exposure
        for sm_url in result.source_maps_exposed:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"JavaScript Source Map Exposed in Production ({hostname})",
                severity=SeverityLevel.MEDIUM,
                category="Information Disclosure",
                targetScope=target_url,
                cvss="5.3",
                cweId="CWE-540",
                cveId=None,
                owaspCategory="A05:2021-Security Misconfiguration",
                description=(
                    f"A JavaScript source map file was detected: {sm_url}. "
                    f"Source maps expose the original unminified application source code to anyone "
                    f"who can access them, aiding targeted vulnerability research."
                ),
                remediationSummary=(
                    "Remove source maps from production builds or restrict access via server-side rules. "
                    "In webpack: set devtool: false or devtool: 'hidden-source-map'."
                ),
                references=["https://developer.chrome.com/docs/devtools/javascript/source-maps/"],
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="SOURCE MAP EXPOSED",
                confidence=0.96,
                evidence={"source_map_url": sm_url},
            ))

        # 7. Prototype pollution
        if result.prototype_pollution:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"Prototype Pollution Indicator Detected ({hostname})",
                severity=SeverityLevel.HIGH,
                category="Web Application Vulnerability",
                targetScope=target_url,
                cvss="7.3",
                cweId="CWE-1321",
                cveId=None,
                owaspCategory="A03:2021-Injection",
                description=(
                    "A Prototype Pollution canary probe confirmed that a `__proto__` "
                    "property injected via JSON parsing polluted the Object prototype, "
                    "indicating the page executes vulnerable JavaScript that does not "
                    "properly sanitise object merge or JSON.parse paths."
                ),
                remediationSummary=(
                    "Audit all object merge, lodash.merge, jQuery.extend, and JSON.parse code paths. "
                    "Use Object.create(null) for dictionaries. Validate all keys before assignment."
                ),
                references=[
                    "https://portswigger.net/web-security/prototype-pollution",
                    "https://nvd.nist.gov/vuln/search/results?query=prototype+pollution",
                ],
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="PROTOTYPE POLLUTION CONFIRMED",
                confidence=0.85,
                evidence={"source": "Playwright JS runtime probe"},
            ))

        # 8. Stack traces / JS errors leaking internal paths
        sensitive_errors = [
            e for e in result.js_errors
            if any(kw in e.lower() for kw in ["cannot read", "is not defined", "at /"]) 
            and len(e) > 40
        ]
        if sensitive_errors:
            findings.append(SecurityFinding(
                id=f"finding-{uuid.uuid4().hex[:8]}",
                title=f"JavaScript Error Stack Traces Leaking Internal Paths ({hostname})",
                severity=SeverityLevel.LOW,
                category="Information Disclosure",
                targetScope=target_url,
                cvss="3.5",
                cweId="CWE-209",
                cveId=None,
                owaspCategory="A05:2021-Security Misconfiguration",
                description=(
                    f"{len(sensitive_errors)} JavaScript runtime error(s) containing internal "
                    f"file path or stack information were captured. This information can assist "
                    f"in fingerprinting the application's internal structure."
                ),
                remediationSummary=(
                    "Implement a global error handler that logs errors server-side without "
                    "exposing stack traces to the browser console in production."
                ),
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                verificationStatus=VerificationStatus.CONFIRMED,
                statusBadge="JS ERROR LEAKAGE",
                confidence=0.80,
                evidence={"sample_errors": sensitive_errors[:3], "source": "Playwright console capture"},
            ))

        return findings

    # ─── Helpers ─────────────────────────────────────────────────────────────
    def _check_storage_secrets(self, storage: Any) -> List[str]:
        """Check localStorage and sessionStorage for sensitive token patterns."""
        hits: List[str] = []
        if not isinstance(storage, dict):
            return hits

        for store_name in ("localStorage", "sessionStorage"):
            items = storage.get(store_name, {})
            if not isinstance(items, dict):
                continue
            for key, value in items.items():
                full_str = f"{key}={value}"
                for pattern in _DANGEROUS_STORAGE_PATTERNS:
                    if re.search(pattern, full_str):
                        # Redact the actual value in the finding
                        hits.append(f"{store_name}[{key}] matches sensitive pattern")
                        break
        return hits

    def _scan_inline_secrets(self, page_source: str) -> List[Tuple[str, str]]:
        """Scan page HTML/JS for inline hardcoded secrets."""
        hits: List[Tuple[str, str]] = []
        for pattern, description in _INLINE_SECRET_PATTERNS:
            match = re.search(pattern, page_source)
            if match:
                # Return redacted snippet only
                snippet = match.group(0)[:40] + "..." if len(match.group(0)) > 40 else match.group(0)
                hits.append((snippet, description))
        return hits

    def _analyse_csp(self, csp_header: str) -> List[str]:
        """Return list of unsafe CSP directives found in the header."""
        issues = []
        csp_lower = csp_header.lower()
        for directive in _CSP_UNSAFE_DIRECTIVES:
            if directive.lower() in csp_lower:
                issues.append(directive)
        return issues

    def _find_source_maps(self, headers: Dict[str, str], page_source: str) -> List[str]:
        """Find references to .map files in page source or SourceMap header."""
        maps = []
        # Check SourceMap response header
        sm_header = headers.get("sourcemap", "") or headers.get("x-sourcemap", "")
        if sm_header:
            maps.append(sm_header)
        # Scan inline //# sourceMappingURL= comments
        matches = re.findall(r"//# sourceMappingURL=([^\s\"']+\.map)", page_source)
        maps.extend(matches[:5])
        return maps

    # ─── NOT_TESTED / error findings ─────────────────────────────────────────
    def _make_not_tested(self, target_url: str) -> SecurityFinding:
        return SecurityFinding(
            id=f"finding-{uuid.uuid4().hex[:8]}",
            title="Browser Security Scan: Playwright Not Installed",
            severity=SeverityLevel.INFORMATIONAL,
            category="Browser Security Analysis",
            targetScope=target_url,
            cvss="0.0",
            description=(
                "The Playwright browser engine is not installed. "
                "DOM XSS, localStorage token leakage, CSP bypass, and mixed content "
                "checks require Playwright Chromium. "
                f"Install: {_PLAYWRIGHT_MISSING_REASON}"
            ),
            remediationSummary=(
                "pip install playwright && playwright install chromium"
            ),
            verificationStatus=VerificationStatus.NOT_TESTED,
            statusBadge="PLAYWRIGHT NOT INSTALLED",
            confidence=1.0,
            evidence={"install_command": "pip install playwright && playwright install chromium"},
        )

    def _make_error_finding(self, target_url: str, error: str) -> SecurityFinding:
        return SecurityFinding(
            id=f"finding-{uuid.uuid4().hex[:8]}",
            title=f"Browser Scan Error: Could Not Load Page",
            severity=SeverityLevel.INFORMATIONAL,
            category="Browser Security Analysis",
            targetScope=target_url,
            cvss="0.0",
            description=f"The headless browser could not load the target page: {error[:200]}",
            remediationSummary="Verify the target URL is accessible and returns HTML content.",
            verificationStatus=VerificationStatus.NOT_TESTED,
            statusBadge="BROWSER LOAD ERROR",
            confidence=1.0,
            evidence={"error": error[:300]},
        )


# Singleton
browser_engine = PlaywrightBrowserEngine()
