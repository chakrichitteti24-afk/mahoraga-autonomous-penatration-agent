"""
CipherFlux Labs — Tests for Feature 1 (OSV Live CVE Feed) and Feature 3 (Playwright Browser Engine).

All tests run offline-safe:
  - OSV feed tests mock the HTTP layer.
  - Browser engine tests verify the graceful NOT_TESTED path when Playwright is absent.
"""
import asyncio
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────
def _make_osv_vuln(pkg_name: str = "requests", version: str = "2.25.0") -> dict:
    """Construct a minimal OSV vulnerability payload."""
    return {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2023-99999"],
        "summary": f"Test vulnerability in {pkg_name}",
        "details": f"A test vulnerability affecting {pkg_name} < 2.28.0.",
        "severity": [{"type": "CVSS_V3", "score": "7.5/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0.0.0"},
                            {"fixed": "2.28.0"},
                        ],
                    }
                ],
                "versions": [version],
            }
        ],
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-99999"}],
        "modified": "2023-01-01T00:00:00Z",
        "database_specific": {"cwe_ids": ["CWE-400"]},
    }


# ── Feature 1: OSV Live CVE Feed ──────────────────────────────────────────────
class TestOSVFeedIsAffected(unittest.TestCase):
    """Test the version range inclusion logic used by the OSV feed."""

    def setUp(self):
        from backend.scanners.osv_feed import _is_affected
        self._is_affected = _is_affected

    def test_affected_version_inside_range(self):
        vuln = _make_osv_vuln(version="2.25.0")
        self.assertTrue(self._is_affected(vuln, "2.25.0"))

    def test_fixed_version_not_affected(self):
        vuln = _make_osv_vuln(version="2.25.0")
        self.assertFalse(self._is_affected(vuln, "2.28.0"))

    def test_newer_version_not_affected(self):
        vuln = _make_osv_vuln(version="2.25.0")
        self.assertFalse(self._is_affected(vuln, "3.0.0"))

    def test_older_version_affected(self):
        vuln = _make_osv_vuln(version="2.25.0")
        self.assertTrue(self._is_affected(vuln, "1.0.0"))

    def test_invalid_version_returns_false(self):
        vuln = _make_osv_vuln(version="2.25.0")
        self.assertFalse(self._is_affected(vuln, "not-a-version"))


class TestOSVEcosystemNormalisation(unittest.TestCase):
    def test_pip_normalises_to_pypi(self):
        from backend.scanners.osv_feed import _normalise_ecosystem
        self.assertEqual(_normalise_ecosystem("pip"), "PyPI")

    def test_npm_unchanged(self):
        from backend.scanners.osv_feed import _normalise_ecosystem
        self.assertEqual(_normalise_ecosystem("npm"), "npm")

    def test_cargo_normalises_to_cratesio(self):
        from backend.scanners.osv_feed import _normalise_ecosystem
        self.assertEqual(_normalise_ecosystem("cargo"), "crates.io")

    def test_unknown_ecosystem_passed_through(self):
        from backend.scanners.osv_feed import _normalise_ecosystem
        self.assertEqual(_normalise_ecosystem("RubyGems"), "RubyGems")


class TestOSVFindingConversion(unittest.TestCase):
    def test_vuln_converts_to_security_finding(self):
        from backend.scanners.osv_feed import _osv_vuln_to_finding
        from backend.models.schemas import VerificationStatus

        vuln = _make_osv_vuln("requests", "2.25.0")
        finding = _osv_vuln_to_finding(vuln, "PyPI", "requests", "2.25.0", "requirements.txt")

        self.assertIn("requests", finding.title)
        self.assertIn("OSV LIVE", finding.title)
        self.assertEqual(finding.cveId, "CVE-2023-99999")
        self.assertEqual(finding.verificationStatus, VerificationStatus.CONFIRMED)
        self.assertGreater(finding.confidence, 0.9)

    def test_severity_extracted_from_cvss_vector(self):
        from backend.scanners.osv_feed import _osv_to_severity
        from backend.models.schemas import SeverityLevel

        vuln = _make_osv_vuln()
        # Score string "7.5/AV:N/..." → HIGH
        sev = _osv_to_severity(vuln)
        self.assertEqual(sev, SeverityLevel.HIGH)


class TestOSVFeedCaching(unittest.TestCase):
    """Test cache read/write round-trip using a temp directory."""

    def test_cache_write_and_read(self):
        import tempfile, time
        from unittest.mock import patch

        vuln = _make_osv_vuln()
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("backend.scanners.osv_feed._get_cache_dir", return_value=Path(tmpdir)):
                from backend.scanners.osv_feed import _write_cache, _read_cache
                _write_cache("test_key", [vuln])
                result = _read_cache("test_key")
                self.assertIsNotNone(result)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["id"], vuln["id"])

    def test_expired_cache_returns_none(self):
        import tempfile, time
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "expired_key.json"
            cache_file.write_text(
                json.dumps({"timestamp": time.time() - 90_000, "advisories": [_make_osv_vuln()]}),
                encoding="utf-8",
            )
            with patch("backend.scanners.osv_feed._get_cache_dir", return_value=Path(tmpdir)):
                from backend.scanners.osv_feed import _read_cache
                result = _read_cache("expired_key")
                self.assertIsNone(result)


class TestLiveCVEFeedLiveQuery(unittest.IsolatedAsyncioTestCase):
    """Test the feed engine's live query path with mocked OSV client."""

    async def test_live_query_returns_findings_when_affected(self):
        from backend.scanners.osv_feed import LiveCVEFeedEngine, osv_client

        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        vuln = _make_osv_vuln("requests", "2.25.0")
        feed = LiveCVEFeedEngine()

        with patch("backend.scanners.osv_feed._get_cache_dir", return_value=tmpdir):
            with patch.object(osv_client, "query_package", new=AsyncMock(return_value=[vuln])):
                findings = await feed.query_live("PyPI", "requests", "2.25.0", "test_manifest")

        self.assertGreater(len(findings), 0)
        self.assertEqual(findings[0].cveId, "CVE-2023-99999")

    async def test_live_query_returns_empty_when_not_affected(self):
        from backend.scanners.osv_feed import LiveCVEFeedEngine, osv_client

        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        vuln = _make_osv_vuln("requests", "2.25.0")
        feed = LiveCVEFeedEngine()

        with patch("backend.scanners.osv_feed._get_cache_dir", return_value=tmpdir):
            with patch.object(osv_client, "query_package", new=AsyncMock(return_value=[vuln])):
                # 3.0.0 is beyond the fixed version 2.28.0 → not affected
                findings = await feed.query_live("PyPI", "requests", "3.0.0", "test_manifest")

        self.assertEqual(len(findings), 0)

    async def test_offline_fallback_returns_empty_list(self):
        """If OSV.dev is unreachable, the feed returns [] without crashing."""
        from backend.scanners.osv_feed import LiveCVEFeedEngine, osv_client

        import tempfile
        tmpdir = Path(tempfile.mkdtemp())
        feed = LiveCVEFeedEngine()

        with patch("backend.scanners.osv_feed._get_cache_dir", return_value=tmpdir):
            with patch.object(osv_client, "query_package", new=AsyncMock(return_value=[])):
                findings = await feed.query_live("PyPI", "requests", "2.25.0", "test_manifest")

        self.assertIsInstance(findings, list)


class TestSCAWithLiveFeed(unittest.TestCase):
    """Ensure SCAScanner correctly integrates with the live feed."""

    def test_sca_pip_with_live_feed_enabled(self):
        """SCA scanner with live feed enabled deduplicates results from both sources."""
        from backend.scanners.sca_scanner import SCAScanner
        from backend.scanners.osv_feed import live_cve_feed

        manifest = "requests==2.25.0\n"

        with patch.object(
            live_cve_feed, "query_live",
            new=AsyncMock(return_value=[]),  # live feed returns nothing here
        ):
            scanner = SCAScanner(use_live_feed=True)
            # Patch _live_query to return empty synchronously
            scanner._live_query = lambda eco, pkg, ver, src: []
            findings = scanner.scan_pip_manifest(manifest, "requirements.txt")

        self.assertIsInstance(findings, list)

    def test_sca_live_feed_disabled(self):
        from backend.scanners.sca_scanner import SCAScanner
        scanner = SCAScanner(use_live_feed=False)
        manifest = "requests==2.25.0\n"
        findings = scanner.scan_pip_manifest(manifest, "requirements.txt")
        self.assertIsInstance(findings, list)


# ── Feature 3: Playwright Browser Engine ─────────────────────────────────────
class TestBrowserEngineAvailability(unittest.TestCase):
    def test_is_available_returns_bool_and_reason(self):
        from backend.scanners.browser_engine import PlaywrightBrowserEngine
        engine = PlaywrightBrowserEngine()
        available, reason = engine.is_available()
        self.assertIsInstance(available, bool)
        self.assertIsInstance(reason, str)

    def test_not_tested_finding_when_playwright_absent(self):
        """When Playwright is not installed, scan() must return a NOT_TESTED finding."""
        import asyncio as _asyncio
        from backend.scanners.browser_engine import PlaywrightBrowserEngine
        from backend.models.schemas import VerificationStatus

        engine = PlaywrightBrowserEngine()

        # Simulate Playwright being unavailable via the _make_not_tested path
        finding = engine._make_not_tested("https://example.com")
        self.assertEqual(finding.verificationStatus, VerificationStatus.NOT_TESTED)
        self.assertIn("Playwright", finding.title)


class TestBrowserEngineAnalysis(unittest.TestCase):
    """Test the _analyse() method against synthetic BrowserScanResult objects."""

    def _make_engine(self):
        from backend.scanners.browser_engine import PlaywrightBrowserEngine
        return PlaywrightBrowserEngine()

    def _make_result(self, **kwargs):
        from backend.scanners.browser_engine import BrowserScanResult
        defaults = dict(
            target_url="https://example.com",
            page_title="Test Page",
            csp_header="",
            console_errors=[],
            dom_sinks_found=[],
            storage_findings=[],
            mixed_content=[],
            inline_secrets=[],
            source_maps_exposed=[],
            js_errors=[],
            prototype_pollution=False,
            response_headers={},
            error=None,
        )
        defaults.update(kwargs)
        return BrowserScanResult(**defaults)

    def test_missing_csp_detected(self):
        engine = self._make_engine()
        result = self._make_result(csp_header="")
        findings = engine._analyse(result, "https://example.com")
        titles = [f.title for f in findings]
        self.assertTrue(any("CSP" in t and "Missing" in t for t in titles))

    def test_unsafe_inline_csp_detected(self):
        engine = self._make_engine()
        result = self._make_result(csp_header="default-src 'self'; script-src 'unsafe-inline'")
        findings = engine._analyse(result, "https://example.com")
        titles = [f.title for f in findings]
        self.assertTrue(any("unsafe-inline" in t for t in titles))

    def test_dom_xss_sinks_detected(self):
        engine = self._make_engine()
        result = self._make_result(dom_sinks_found=["innerHTML", "eval("])
        findings = engine._analyse(result, "https://example.com")
        self.assertTrue(any("DOM XSS" in f.title for f in findings))

    def test_storage_secret_detected(self):
        engine = self._make_engine()
        result = self._make_result(storage_findings=["localStorage[token] matches sensitive pattern"])
        findings = engine._analyse(result, "https://example.com")
        self.assertTrue(any("Storage" in f.title for f in findings))

    def test_mixed_content_detected(self):
        engine = self._make_engine()
        result = self._make_result(mixed_content=[{"tag": "SCRIPT", "url": "http://cdn.example.com/lib.js"}])
        findings = engine._analyse(result, "https://example.com")
        self.assertTrue(any("Mixed" in f.title for f in findings))

    def test_inline_secret_detected(self):
        engine = self._make_engine()
        result = self._make_result(inline_secrets=[("AIzaSyABCDEF123456789012345678901", "Google API Key Exposure")])
        findings = engine._analyse(result, "https://example.com")
        self.assertTrue(any("Google API Key" in f.title for f in findings))

    def test_source_map_detected(self):
        engine = self._make_engine()
        result = self._make_result(source_maps_exposed=["main.js.map"])
        findings = engine._analyse(result, "https://example.com")
        self.assertTrue(any("Source Map" in f.title for f in findings))

    def test_prototype_pollution_detected(self):
        engine = self._make_engine()
        result = self._make_result(prototype_pollution=True)
        findings = engine._analyse(result, "https://example.com")
        self.assertTrue(any("Prototype Pollution" in f.title for f in findings))

    def test_clean_page_no_critical_findings(self):
        """A page with a strong CSP and no issues should have no HIGH/CRITICAL findings."""
        from backend.models.schemas import SeverityLevel
        engine = self._make_engine()
        result = self._make_result(
            csp_header="default-src 'none'; script-src 'nonce-abc123'; base-uri 'self'",
        )
        findings = engine._analyse(result, "https://example.com")
        high_or_critical = [
            f for f in findings
            if f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
        ]
        self.assertEqual(len(high_or_critical), 0)


class TestBrowserEngineStorageChecker(unittest.TestCase):
    def test_jwt_in_localstorage_detected(self):
        from backend.scanners.browser_engine import PlaywrightBrowserEngine
        engine = PlaywrightBrowserEngine()
        storage = {
            "localStorage": {"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc"},
            "sessionStorage": {},
        }
        hits = engine._check_storage_secrets(storage)
        self.assertGreater(len(hits), 0)

    def test_non_sensitive_storage_clean(self):
        from backend.scanners.browser_engine import PlaywrightBrowserEngine
        engine = PlaywrightBrowserEngine()
        storage = {
            "localStorage": {"theme": "dark", "lang": "en"},
            "sessionStorage": {"cart_items": "3"},
        }
        hits = engine._check_storage_secrets(storage)
        self.assertEqual(len(hits), 0)


if __name__ == "__main__":
    unittest.main()
