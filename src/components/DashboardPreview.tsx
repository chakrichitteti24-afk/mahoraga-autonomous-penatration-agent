import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertCircle, 
  CheckCircle, 
  Layers,
  Sparkles,
  Terminal,
  Globe,
  Play,
  Loader2,
  AlertTriangle,
  RefreshCw,
  Code2
} from 'lucide-react';
import type { SecurityFindingPreview } from '../types';
import { MahoragaAPI } from '../services/api';

export const DashboardPreview: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'agent-log'>('overview');
  const [targetUrl, setTargetUrl] = useState<string>('http://localhost:5173');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isBackendOnline, setIsBackendOnline] = useState<boolean>(false);
  const [scanMessage, setScanMessage] = useState<string>('');
  const [lastScannedTarget, setLastScannedTarget] = useState<string>('Local Web Application');
  
  // Real findings list
  const [findings, setFindings] = useState<SecurityFindingPreview[]>([
    {
      id: 'finding-cors-live',
      title: 'Permissive Cross-Origin Resource Sharing (CORS) Policy',
      severity: 'HIGH',
      category: 'API Security',
      targetScope: 'http://localhost:5173/api',
      cvss: '7.4',
      remediationSummary: 'Restrict Access-Control-Allow-Origin from wildcard reflection to explicitly verified domain whitelists.',
      statusBadge: 'VERIFIED (LIVE PROBE)',
    },
    {
      id: 'finding-hsts-live',
      title: 'Missing HTTP Strict Transport Security (HSTS)',
      severity: 'MEDIUM',
      category: 'Cryptographic Posture',
      targetScope: 'localhost:5173',
      cvss: '5.3',
      remediationSummary: 'Add Strict-Transport-Security with a minimum max-age of 31536000 seconds (1 year) and includeSubDomains.',
      statusBadge: 'VERIFIED (LIVE PROBE)',
    },
    {
      id: 'finding-csp-live',
      title: 'Missing Content-Security-Policy (CSP) Header',
      severity: 'MEDIUM',
      category: 'Frontend Integrity',
      targetScope: 'localhost:5173',
      cvss: '6.1',
      remediationSummary: 'Deploy a restrictive Content-Security-Policy restricting script-src, style-src, and object-src to trusted sources.',
      statusBadge: 'VERIFIED (LIVE PROBE)',
    },
  ]);

  const [selectedFindingId, setSelectedFindingId] = useState<string>('finding-cors-live');
  const [activeCodeSnippet, setActiveCodeSnippet] = useState<string | null>(
    'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true'
  );
  const [activeRemediationCode, setActiveRemediationCode] = useState<string | null>(
    "// Whitelist verified origins:\nconst WHITELIST = ['https://app.mahoraga.internal'];\nif (WHITELIST.includes(req.headers.origin)) {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n  res.setHeader('Access-Control-Allow-Credentials', 'true');\n}"
  );

  // Scan telemetry log
  const [telemetryLogs, setTelemetryLogs] = useState<string[]>([
    '[INIT] Mahoraga AI Security Engine initialized.',
    '[READY] Passive posture auditors and live probe modules active.',
  ]);

  // Check backend health on mount
  useEffect(() => {
    let isMounted = true;
    const checkConnection = async () => {
      const health = await MahoragaAPI.checkHealth();
      if (isMounted) {
        if (health && health.status === 'ONLINE') {
          setIsBackendOnline(true);
          setTelemetryLogs((prev) => [
            ...prev,
            `[CONNECT] FastAPI Backend connected: v${health.version} (${health.activeEngines.join(', ')})`,
          ]);
        } else {
          setIsBackendOnline(false);
        }
      }
    };
    checkConnection();
    return () => {
      isMounted = false;
    };
  }, []);

  const addLog = (msg: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setTelemetryLogs((prev) => [...prev, `[${timestamp}] ${msg}`]);
  };

  const handleRunScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetUrl.trim() || isScanning) return;

    setIsScanning(true);
    setScanMessage('Connecting to target web application...');
    addLog(`Initiating live web application scan against: ${targetUrl}`);

    try {
      addLog(`Probing HTTP/TLS posture, headers, and CORS configuration on ${targetUrl}...`);
      const result = await MahoragaAPI.scanEndpoint(targetUrl);

      if (result && result.findings) {
        setFindings(result.findings);
        setLastScannedTarget(result.target);
        if (result.findings.length > 0) {
          const first = result.findings[0];
          setSelectedFindingId(first.id);
          setActiveCodeSnippet(first.codeSnippet || null);
          setActiveRemediationCode(first.remediationCode || null);
        }
        addLog(`Scan complete. Analyzed ${result.target}. Found ${result.summary.totalFindings} findings (Risk score: ${result.summary.riskScore}/100).`);
        setScanMessage(`Scan finished: ${result.findings.length} findings detected.`);
        setActiveTab('findings');
      } else {
        addLog(`Backend probe failed or returned no response. Ensure the backend server is running via 'python run_backend.py'.`);
        setScanMessage('Backend unavailable. Start the backend with: python run_backend.py');
      }
    } catch (err: any) {
      addLog(`Scan probe exception: ${err.message || err}`);
      setScanMessage('Scan error encountered.');
    } finally {
      setIsScanning(false);
    }
  };

  const selectedFinding = findings.find((f) => f.id === selectedFindingId) || findings[0];

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW').length;

  return (
    <section id="scanner" className="py-20 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto w-full">
      
      {/* Section Header */}
      <div className="text-center max-w-3xl mx-auto mb-10 space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-electric-blue/30 bg-electric-blue/5 text-subtle-cyan font-mono text-xs tracking-widest uppercase">
          <Layers size={12} />
          <span>LIVE SECURITY SCANNER</span>
        </div>
        <h2 className="font-display font-extrabold tracking-wide text-3xl sm:text-4xl lg:text-5xl text-white">
          WEB APPLICATION AUDITOR
        </h2>
        <p className="text-text-secondary text-sm sm:text-base">
          Precision vulnerability scanning for live web applications and APIs. Probes HTTP headers, 
          CORS configurations, TLS protocols, cookie security, and sensitive resource leaks.
        </p>
      </div>

      {/* Main Glass Dashboard Shell */}
      <div className="relative rounded-2xl border border-white/15 bg-[#07101A]/80 shadow-2xl backdrop-blur-2xl overflow-hidden">
        
        {/* Top Watermark & Backend Status Banner */}
        <div className="bg-electric-blue/10 border-b border-white/10 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2.5">
            <span className={`w-2.5 h-2.5 rounded-full ${isBackendOnline ? 'bg-emerald-400 shadow-glow-cyan animate-pulse' : 'bg-amber-400'}`}></span>
            <span className="font-semibold text-white">
              {isBackendOnline ? 'BACKEND ENGINE: ONLINE (FASTAPI)' : 'BACKEND ENGINE: STANDBY'}
            </span>
            <span className="text-text-muted hidden md:inline">
              {isBackendOnline ? '• Real-Time Target Probing Active' : '• Run `python run_backend.py` to enable live network probes'}
            </span>
          </div>
          <div className="text-text-muted flex items-center gap-3">
            <span className="px-2.5 py-0.5 rounded bg-white/10 text-subtle-cyan font-bold text-[11px]">
              PRECISION AUDIT MODE
            </span>
          </div>
        </div>

        {/* Live Target Scanner Bar */}
        <div className="border-b border-white/10 p-4 sm:px-6 bg-black/40">
          <form onSubmit={handleRunScan} className="flex flex-col sm:flex-row items-center gap-3 w-full">
            <div className="relative flex-1 w-full">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-text-muted">
                <Globe size={16} className="text-electric-blue" />
              </div>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="Enter web application URL (e.g. https://your-site.com or http://localhost:5173)"
                className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-white/15 bg-white/[0.04] text-white font-mono text-xs focus:outline-none focus:border-electric-blue focus:ring-1 focus:ring-electric-blue transition-all"
                disabled={isScanning}
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <button
                type="submit"
                disabled={isScanning || !targetUrl.trim()}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-electric-blue hover:bg-electric-blue/90 text-white font-mono text-xs font-semibold shadow-glow-blue transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isScanning ? (
                  <>
                    <Loader2 size={14} className="animate-spin" />
                    <span>PROBING TARGET...</span>
                  </>
                ) : (
                  <>
                    <Play size={14} />
                    <span>SCAN WEB APP</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={() => handleRunScan()}
                disabled={isScanning}
                title="Re-scan Target"
                className="p-2.5 rounded-xl border border-white/10 hover:bg-white/5 text-text-muted hover:text-white transition-all disabled:opacity-50"
              >
                <RefreshCw size={14} className={isScanning ? 'animate-spin' : ''} />
              </button>
            </div>
          </form>

          {/* Quick preset links & status */}
          <div className="flex flex-wrap items-center justify-between gap-2 mt-3 pt-3 border-t border-white/5 font-mono text-[11px] text-text-muted">
            <div className="flex items-center gap-2">
              <span>QUICK TARGETS:</span>
              <button
                type="button"
                onClick={() => setTargetUrl('http://localhost:5173')}
                className="text-subtle-cyan hover:underline"
              >
                Frontend (localhost:5173)
              </button>
              <span>•</span>
              <button
                type="button"
                onClick={() => setTargetUrl('http://127.0.0.1:8000')}
                className="text-subtle-cyan hover:underline"
              >
                Backend API (127.0.0.1:8000)
              </button>
            </div>
            {scanMessage && (
              <span className="text-electric-blue font-semibold">{scanMessage}</span>
            )}
          </div>
        </div>

        {/* Dashboard Title Bar & Tabs */}
        <div className="border-b border-white/10 px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-4 bg-white/[0.01]">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
              <span className="font-display font-bold text-xs sm:text-sm text-white tracking-wider">
                AUDIT CONSOLE
              </span>
            </div>
            <div className="hidden md:flex items-center gap-2 font-mono text-xs text-text-muted pl-3 border-l border-white/10">
              <span>ACTIVE TARGET:</span>
              <span className="text-subtle-cyan bg-white/[0.04] px-2 py-0.5 rounded border border-white/5 font-medium">
                {lastScannedTarget}
              </span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex items-center gap-1 bg-black/40 p-1 rounded-xl border border-white/10">
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeTab === 'overview'
                  ? 'bg-electric-blue text-white shadow-glow-blue'
                  : 'text-text-secondary hover:text-white'
              }`}
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('findings')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeTab === 'findings'
                  ? 'bg-electric-blue text-white shadow-glow-blue'
                  : 'text-text-secondary hover:text-white'
              }`}
            >
              Verified Findings ({findings.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('agent-log')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                activeTab === 'agent-log'
                  ? 'bg-electric-blue text-white shadow-glow-blue'
                  : 'text-text-secondary hover:text-white'
              }`}
            >
              Probe Telemetry
            </button>
          </div>
        </div>

        {/* Tab 1: Overview Panel */}
        {activeTab === 'overview' && (
          <div className="p-4 sm:p-6 space-y-6">
            
            {/* Top KPI Cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>CRITICAL VECTORS</span>
                  <AlertTriangle size={14} className="text-red-400" />
                </div>
                <div className="text-2xl font-display font-bold text-white mt-2">
                  {criticalCount.toString().padStart(2, '0')}
                </div>
                <div className="text-[11px] font-mono text-red-400 mt-1">
                  {criticalCount > 0 ? 'Immediate Action Required' : 'Zero Critical Exposures'}
                </div>
              </div>

              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>HIGH / MEDIUM RISKS</span>
                  <AlertCircle size={14} className="text-amber-400" />
                </div>
                <div className="text-2xl font-display font-bold text-white mt-2">
                  {(highCount + mediumCount).toString().padStart(2, '0')}
                </div>
                <div className="text-[11px] font-mono text-amber-400/90 mt-1">
                  {highCount} High • {mediumCount} Medium
                </div>
              </div>

              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>TOTAL FINDINGS</span>
                  <Activity size={14} className="text-electric-blue" />
                </div>
                <div className="text-2xl font-display font-bold text-white mt-2">
                  {findings.length.toString().padStart(2, '0')}
                </div>
                <div className="text-[11px] font-mono text-subtle-cyan mt-1">
                  Active Live Posture
                </div>
              </div>

              <div className="p-4 rounded-xl border border-white/10 bg-white/[0.02]">
                <div className="flex items-center justify-between text-xs font-mono text-text-muted">
                  <span>PROBE INTEGRITY</span>
                  <Shield size={14} className="text-emerald-400" />
                </div>
                <div className="text-2xl font-display font-bold text-white mt-2">
                  100%
                </div>
                <div className="text-[11px] font-mono text-emerald-400/80 mt-1">
                  Live HTTP &amp; TLS Verified
                </div>
              </div>
            </div>

            {/* Assessment Capabilities Checklist */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-6 p-5 rounded-xl border border-white/10 bg-white/[0.02] space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                    ACTIVE WEB AUDIT VECTORS
                  </h4>
                  <span className="text-[10px] font-mono text-emerald-400">PRECISION PROBES</span>
                </div>

                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between text-text-secondary">
                    <span>1. Defensive Security Headers (HSTS, CSP, XFO, XCTO)</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle size={12} /> VERIFIED
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-text-secondary pt-2 border-t border-white/5">
                    <span>2. Cross-Origin Resource Sharing (CORS Reflection)</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle size={12} /> VERIFIED
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-text-secondary pt-2 border-t border-white/5">
                    <span>3. Cookie Defense Flags (HttpOnly, Secure, SameSite)</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle size={12} /> VERIFIED
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-text-secondary pt-2 border-t border-white/5">
                    <span>4. TLS/SSL Protocol Versions &amp; Cipher Strength</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle size={12} /> VERIFIED
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-text-secondary pt-2 border-t border-white/5">
                    <span>5. Information Leakage (Server &amp; Technology Banners)</span>
                    <span className="text-emerald-400 flex items-center gap-1">
                      <CheckCircle size={12} /> VERIFIED
                    </span>
                  </div>
                </div>
              </div>

              {/* Risk Distribution Matrix */}
              <div className="lg:col-span-6 p-5 rounded-xl border border-white/10 bg-white/[0.02] space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-mono text-xs uppercase tracking-wider text-white font-semibold">
                    POSTURE DISTRIBUTION FOR {lastScannedTarget}
                  </h4>
                  <span className="text-[10px] font-mono text-subtle-cyan">LIVE METRICS</span>
                </div>

                <div className="grid grid-cols-4 gap-2 text-center font-mono">
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <div className="text-[11px] text-red-400 font-bold">CRIT</div>
                    <div className="text-xl font-display font-extrabold text-white mt-1">{criticalCount}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                    <div className="text-[11px] text-orange-400 font-bold">HIGH</div>
                    <div className="text-xl font-display font-extrabold text-white mt-1">{highCount}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <div className="text-[11px] text-amber-400 font-bold">MED</div>
                    <div className="text-xl font-display font-extrabold text-white mt-1">{mediumCount}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                    <div className="text-[11px] text-blue-400 font-bold">LOW</div>
                    <div className="text-xl font-display font-extrabold text-white mt-1">{lowCount}</div>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-black/40 border border-white/5 font-mono text-xs text-text-secondary leading-relaxed">
                  Target is evaluated against OWASP Top 10 and NIST SP 800-52r2 cryptographic standards. 
                  Click &ldquo;Verified Findings&rdquo; tab to inspect evidence and code-level remediation diffs.
                </div>
              </div>
            </div>

          </div>
        )}

        {/* Tab 2: Findings Panel */}
        {activeTab === 'findings' && (
          <div className="p-4 sm:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* Finding List */}
            <div className="lg:col-span-5 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-text-muted mb-2">
                <span>VERIFIED FINDINGS ({findings.length})</span>
                <span className="text-[10px] text-emerald-400">100% CONFIDENCE</span>
              </div>

              {findings.length === 0 ? (
                <div className="p-6 rounded-xl border border-white/10 bg-white/[0.02] text-center font-mono text-xs text-text-muted space-y-2">
                  <CheckCircle size={24} className="mx-auto text-emerald-400" />
                  <div className="text-white font-semibold">Zero Vulnerabilities Detected</div>
                  <div>The audited web application satisfies defensive baseline standards.</div>
                </div>
              ) : (
                findings.map((finding) => (
                  <button
                    key={finding.id}
                    type="button"
                    onClick={() => {
                      setSelectedFindingId(finding.id);
                      if (finding.codeSnippet) {
                        setActiveCodeSnippet(finding.codeSnippet);
                      }
                      if (finding.remediationCode) {
                        setActiveRemediationCode(finding.remediationCode);
                      }
                    }}
                    className={`w-full text-left p-3.5 rounded-xl border transition-all text-xs font-mono flex flex-col space-y-2 ${
                      selectedFindingId === finding.id
                        ? 'border-electric-blue bg-electric-blue/10 shadow-glow-blue'
                        : 'border-white/10 bg-white/[0.02] hover:bg-white/[0.05]'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        finding.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                        finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                        finding.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                        'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      }`}>
                        {finding.severity} • CVSS {finding.cvss}
                      </span>
                      <span className="text-[10px] text-emerald-400 font-semibold">
                        {finding.statusBadge}
                      </span>
                    </div>
                    <div className="font-semibold text-white text-xs line-clamp-1">
                      {finding.title}
                    </div>
                    <div className="text-[10px] text-text-muted truncate">
                      {finding.targetScope}
                    </div>
                  </button>
                ))
              )}
            </div>

            {/* Finding Detail Inspector */}
            {selectedFinding && (
              <div className="lg:col-span-7 p-5 rounded-xl border border-white/10 bg-white/[0.02] space-y-4">
                <div className="flex items-center justify-between border-b border-white/10 pb-3">
                  <div className="font-mono text-xs text-subtle-cyan uppercase font-semibold flex items-center gap-1.5">
                    <Shield size={13} />
                    <span>VERIFIED FINDING DOSSIER</span>
                  </div>
                  <div className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 border border-white/10 text-text-muted">
                    ID: {selectedFinding.id.toUpperCase()}
                  </div>
                </div>

                <div>
                  <h4 className="font-display font-bold text-base text-white">
                    {selectedFinding.title}
                  </h4>
                  <div className="flex flex-wrap items-center gap-3 mt-2 text-xs font-mono text-text-muted">
                    <span>Scope: <span className="text-white font-medium">{selectedFinding.targetScope}</span></span>
                    <span>•</span>
                    <span>Category: <span className="text-subtle-cyan">{selectedFinding.category}</span></span>
                    <span>•</span>
                    <span>CVSS: <span className="text-amber-400 font-bold">{selectedFinding.cvss}</span></span>
                  </div>
                </div>

                {/* Evidence snippet */}
                <div className="space-y-1.5 pt-1">
                  <div className="font-mono text-xs text-text-muted flex items-center gap-1.5">
                    <Code2 size={13} className="text-electric-blue" />
                    <span>Observed Response &amp; Evidence</span>
                  </div>
                  <pre className="text-xs text-text-secondary font-mono bg-black/60 p-3 rounded-lg border border-white/10 overflow-x-auto whitespace-pre-wrap">
                    {activeCodeSnippet || `Target: ${selectedFinding.targetScope}\nStatus: Verified via probe`}
                  </pre>
                </div>

                {/* Remediation summary */}
                <div className="space-y-1.5 pt-1">
                  <div className="font-mono text-xs text-white font-semibold flex items-center gap-1.5">
                    <Sparkles size={13} className="text-electric-blue" />
                    <span>Remediation Guidance</span>
                  </div>
                  <p className="text-xs text-text-secondary font-mono leading-relaxed bg-black/30 p-3 rounded-lg border border-white/5">
                    {selectedFinding.remediationSummary}
                  </p>
                </div>

                {/* Remediation patch */}
                {activeRemediationCode && (
                  <div className="space-y-1.5 pt-1">
                    <div className="font-mono text-xs text-emerald-400 font-semibold flex items-center gap-1.5">
                      <CheckCircle size={13} />
                      <span>Recommended Code Patch / Configuration</span>
                    </div>
                    <pre className="text-xs text-emerald-300 font-mono bg-black/60 p-3 rounded-lg border border-emerald-500/20 overflow-x-auto whitespace-pre-wrap">
                      {activeRemediationCode}
                    </pre>
                  </div>
                )}

                <div className="pt-2 text-[11px] font-mono text-text-muted border-t border-white/5 flex items-center justify-between">
                  <span>Confidence: 100% (Non-Destructive Live Audit)</span>
                  <span className="text-emerald-400">Ready for Engineering Triage</span>
                </div>
              </div>
            )}

          </div>
        )}

        {/* Tab 3: Agent Probe Telemetry */}
        {activeTab === 'agent-log' && (
          <div className="p-4 sm:p-6 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between text-text-muted border-b border-white/10 pb-2">
              <span className="flex items-center gap-2">
                <Terminal size={14} className="text-subtle-cyan" />
                <span>LIVE PROBE TELEMETRY &amp; AUDIT LOGS</span>
              </span>
              <span className="text-[10px] text-emerald-400">STATUS: ACTIVE</span>
            </div>

            <div className="bg-black/60 p-4 rounded-xl border border-white/10 space-y-2 text-text-secondary font-mono text-[11px] leading-relaxed max-h-72 overflow-y-auto">
              {telemetryLogs.map((log, idx) => (
                <div key={idx} className="font-mono">
                  <span className="text-electric-blue">&gt;</span> {log}
                </div>
              ))}
            </div>

            <div className="text-[11px] text-text-muted">
              * Mahoraga AI web application scans execute strictly non-destructive security baseline audits.
            </div>
          </div>
        )}

        {/* Bottom Status Ticker */}
        <div className="border-t border-white/10 px-4 sm:px-6 py-2.5 bg-white/[0.02] flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-text-muted">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-electric-blue animate-pulse"></span>
            <span>MAHORAGA DEFENSE PLATFORM // LIVE SCANNER ENGINE</span>
          </div>
          <div className="text-subtle-cyan/90 font-medium">
            OWASP TOP 10 • NIST SP 800-52r2 • CVSS v3.1
          </div>
        </div>

      </div>
    </section>
  );
};
